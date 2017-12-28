#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <sys/timerfd.h>
#include <assert.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdarg.h>
#include "json-c/json.h"
#include "miio_json.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include "rbtree.h"
#include "config.h"
#include "miio_agent.h"

FILE *log_file;
log_level_t g_loglevel = LOG_DEBUG;

int miot_fd, agent_listenfd, timer_fd;
struct agent_info agent;

struct rb_root key_tree = RB_ROOT;
struct rb_root id_tree = RB_ROOT;

static struct option options[] = {
	{"help",	no_argument,		NULL, 'h'},
	{"version",	no_argument,		NULL, 'v'},
	{"loglevel",    required_argument,      NULL, 'l'},
	{"logfile",	required_argument,      NULL, 'L'},
	{"daemonize",	no_argument,		NULL, 'D'},
	{NULL,		0,			0,	0}
};

static void sighandler(int sig)
{
	free_key_tree();
	free_id_tree();

	if (miot_fd >0) {
		close(miot_fd);
	}
	if(agent_listenfd > 0)
		close(agent_listenfd);

	log_printf(LOG_ERROR, "miio_agent will be exit\n");
	exit(-1);
}

int main(int argc, char *argv[])
{
	int n = 0;
	int daemonize = 0;

	log_file = stdout;

	while (n >= 0) {
		n = getopt_long(argc, argv, "hDvl:L:", options, NULL);
		if (n < 0)
			continue;
		switch (n) {
			case 'D':
				daemonize = 1;
				break;
			case 'l':
				g_loglevel = atoi(optarg);
				if (g_loglevel > LOG_LEVEL_MAX)
					g_loglevel = LOG_LEVEL_MAX;
				log_printf(LOG_INFO, "Set log level to: %d\n", g_loglevel);
				break;
			case 'L':
				logfile_init(optarg);
				break;
			case 'v':
				fprintf(stdout, "%s\n", PACKAGE_STRING);
				exit(1);
			case 'h':
			default:
				fprintf(stderr, "miio agent - MIIO OT messages agent protocol implementation\n"
				"Copyright (C) Xiaomi\n"
				"Author: Fu Sichang <fusichang@xiaomi.com>\n"
				"Version: %s\n"
				"Build time: %s %s\n", PACKAGE_STRING, __TIME__, __DATE__);
				fprintf(stderr, "\n");
				fprintf(stderr, "Usage: %s\n"
				"\t[-D --daemonize]\n"
				"\t[-l --loglevel=<level>] set loglevel (0-4), bigger = more verbose\n"
				"\t[-L --logfile=file] output log into file instead of stdout\n"
				"\t[-h --help]\n"
				, argv[0]);
				exit(1);
		}
	}

	signal(SIGINT, sighandler);
	signal(SIGPIPE, SIG_IGN);

	miot_fd = miot_connect_init();
	agent_listenfd = agent_server_init();

	if (miot_fd <= 0 || agent_listenfd <=0) {
		log_printf(LOG_ERROR, "create socket error\n");
		return -1;
	}

	memset(&agent, 0, sizeof(agent));

	agent.pollfds[agent.count_pollfds].fd = miot_fd;
	agent.pollfds[agent.count_pollfds].events = POLLIN;
	log_printf(LOG_INFO, "miot client fd: %d\n", agent.pollfds[agent.count_pollfds].fd);
	agent.count_pollfds++;

	agent.pollfds[agent.count_pollfds].fd = agent_listenfd;
	agent.pollfds[agent.count_pollfds].events = POLLIN;
	log_printf(LOG_INFO, "agent listen fd: %d\n", agent.pollfds[agent.count_pollfds].fd);
	agent.count_pollfds++;

	/* timer */
	timer_fd = timer_setup();
	assert(timer_fd > 0);
	timer_start(timer_fd, TIMER_INTERVAL, TIMER_INTERVAL);
	agent.pollfds[agent.count_pollfds].fd = timer_fd;
	agent.pollfds[agent.count_pollfds].events = POLLIN;
	log_printf(LOG_INFO, "timer fd: %d\n", agent.pollfds[agent.count_pollfds].fd);
	agent.count_pollfds++;

	if (daemonize)
		if (daemon(0, 1) < 0)
			log_printf(LOG_WARNING, "daemonize fail: %m\n");
	n = 0;

	while (n >= 0) {
		int i;
		n = poll(agent.pollfds, agent.count_pollfds, POLL_TIMEOUT);
		if (n <= 0) {
			continue;
		}

		for (i = 0; i < agent.count_pollfds && n > 0; i++) {
			if (agent.pollfds[i].revents & (POLLNVAL | POLLHUP | POLLERR)) {
				int j = i;
				log_printf(LOG_WARNING, "agent.pollfds[i].revents: %08x, %d\n",agent.pollfds[i].revents, agent.pollfds[i].fd);
				if (agent.pollfds[i].fd == miot_fd) {
					close(miot_fd);
					agent.pollfds[i].fd = -1;
					miot_fd = -1;
					continue;
				}
				if (agent.pollfds[i].fd == agent_listenfd) {
					continue;
				}
				delete_fd_from_agent(agent.pollfds[i].fd);
				n--;
			} else if (agent.pollfds[i].revents & POLLIN) {
				if (agent.pollfds[i].fd == timer_fd)
					timer_handler(timer_fd);
				else if (agent.pollfds[i].fd == miot_fd)
					agent_recv_handler(miot_fd, 0);
				else if (agent.pollfds[i].fd == agent_listenfd)
					agent_listen_handler(agent_listenfd);
				else
					agent_recv_handler(agent.pollfds[i].fd, 1);
				n--;
			}
		}
	}
	free_key_tree();
	free_id_tree();
	return 0;
}

int  miot_connect_init(void)
{
	int miot_fd;
	struct sockaddr_in servaddr;

	miot_fd = socket(AF_INET, SOCK_STREAM, 0);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(SERVER_IP);
	servaddr.sin_port = htons(MIOT_SERVER_PORT);

	if (connect(miot_fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
		log_printf(LOG_ERROR, "Connect to server error: %s:%d\n", SERVER_IP, MIOT_SERVER_PORT);
		return -1;
	}
	return miot_fd;
}

int  agent_server_init(void)
{
	struct sockaddr_in serveraddr;
	int agent_listenfd;
	int ret = -1, on = 1;

	agent_listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (agent_listenfd < 0) {
		log_printf(LOG_ERROR, "Create ot server socket error: %s\n",
			   strerror(errno));
		return -1;
	}

	if ((ret = setsockopt(agent_listenfd, SOL_SOCKET, SO_REUSEADDR,
				  (char *) &on, sizeof(on))) < 0) {
		log_printf(LOG_ERROR, "OT server setsockopt(SO_REUSEADDR): %m");
		close(agent_listenfd);
		return ret;
	}

	if (ioctl(agent_listenfd, FIONBIO, (char *)&on) < 0) {
		log_printf(LOG_ERROR, "ioctl FIONBIO failed: %m");
		close(agent_listenfd);
		return -1;
	}

	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(DISPATCHER_SERVER_PORT);
	serveraddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(agent_listenfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
		log_printf(LOG_ERROR, "Socket bind port (%d) error: %s\n",
			   DISPATCHER_SERVER_PORT, strerror(errno));
		close(agent_listenfd);
		return -1;
	}

	if (listen(agent_listenfd, 32) == -1) {
		perror("listen");
		return -1;
	}
	return agent_listenfd;
}

void timer_handler(int fd)
{
	uint64_t exp = 0;
	static uint32_t i = 0;
	/* just read out the "events" in fd, otherwise poll will keep
	 * reporting POLLIN */
	read(fd, &exp, sizeof(uint64_t));

	if (miot_fd <= 0) {
		miot_fd = miot_connect_init();
		agent.pollfds[0].fd = miot_fd;
	}

	i++;
	if (i % 100 == 0) {
		update_id_tree();
		i = 0;
	}
}

/*
*listen connect from client
*/
int agent_listen_handler(int listenfd)
{
	int newfd;
	struct sockaddr_storage other_addr;
	socklen_t sin_size = sizeof(struct sockaddr_storage);

	while (1) {
		newfd = accept(listenfd, (struct sockaddr *)&other_addr, &sin_size);
		if (newfd <= 0) {
			break;
		}
		 //add into poll
		if (agent.count_pollfds >= MAX_POLL_FDS) {
			log_printf(LOG_ERROR, "too many sockets to track\n");
			return -1;
		}

		agent.pollfds[agent.count_pollfds].fd = newfd;
		agent.pollfds[agent.count_pollfds].events = POLLIN;
		log_printf(LOG_INFO, "OT agent listen accept sockfd: %d\n",
			   agent.pollfds[agent.count_pollfds].fd);
		agent.count_pollfds++;
	}
	return 0;
}

/**
*handler messages from miot
**/
int miot_msg_handler(char *msg, int msg_len)
{
	int ret = -1;

	if (json_verify_method(msg, "method") == 0) {
		/* It's a command msg */
		//log_printf(LOG_DEBUG, "cloud/mobile cmd: %s,len: %d\n", msg, msg_len);
		ret = send_to_register_client(msg, msg_len);
	} else {
		/* It's a report ACK msg */
		//log_printf(LOG_DEBUG, "cloud ack: %s, len: %d\n", msg, msg_len);
		ret = send_ack_to_client(msg);
	}
	return ret;
}

int get_newid(void)
{
	static int id=1;

	if (id >= MAX_ID_NUM)
		id = 1;
	return id++;
}

/*
*upload info or ack
*parse msg, if id exist, means this msg need ack, should linked to list.
*so repleace old id with new id,record the corresponding relationship
	new_id:		old_id, fd
*if id is not exist,means ack no need, just send to miot
*/
int client_msg_handler(char *msg, int len, int sockfd)
{
	int ret, old_id;
	int fd = miot_fd;

	//log_printf(LOG_DEBUG,"msg is %s, len is %d\n", msg, len);
	if (json_verify_method(msg, "method") == 0 ) {
		struct json_object *save_obj, *new_obj, *tmp_obj;
		const char *str,*key;

		save_obj = json_tokener_parse(msg);
		json_object_object_get_ex(save_obj, "method", &new_obj);
		if (!json_object_is_type(new_obj, json_type_string)) {
			json_object_put(save_obj);
			return -1;
		}
		str = json_object_get_string(new_obj);
		if (memcmp(str, "register", strlen("register")) == 0) {
			json_object_object_get_ex(save_obj, "key", &tmp_obj);
			if (json_object_is_type(tmp_obj, json_type_string)) {
				key = json_object_get_string(tmp_obj);
				log_printf(LOG_INFO, "register key: %s, fd: %d\n", key, sockfd);
				key_insert(&key_tree, key, sockfd);
				ret = 0;
			}
		} else if (memcmp(str, "unregister", strlen("unregister")) == 0) {
			json_object_object_get_ex(save_obj, "key", &tmp_obj);
			if (json_object_is_type(tmp_obj, json_type_string)) {
				int key_len;
				key = json_object_get_string(tmp_obj);
				key_len = strlen(key);
				if (key_len == 0) {
					log_printf(LOG_INFO, "unregister all,fd: %d\n", sockfd);
					remove_fd_from_keytree(sockfd);
				} else {
					log_printf(LOG_INFO, "unregister key: %s, fd: %d\n", key, sockfd);
					remove_key_within_fd(sockfd,  key);
				}
				ret = 0;
			}
		} else if (json_verify_get_int(msg, "id", &old_id) == 0 ) {
			int msg_len;
			char *newmsg;
			struct id_node *p;
			int new_id = get_newid();
			/* replace with new id */
			json_object_object_del(save_obj, "id");
			json_object_object_add(save_obj, "id", json_object_new_int(new_id));
			newmsg = (char *)json_object_to_json_string_ext(save_obj, JSON_C_TO_STRING_PLAIN);
			msg_len = strlen(newmsg);
			log_printf(LOG_INFO, "U:new id:%d, old_id:%d, fd:%d: len: %d\n", new_id, old_id, sockfd, msg_len);
			log_printf(LOG_DEBUG, "newmsg  is %s\n", newmsg);
			ret = send(fd, newmsg, msg_len, 0);

			p = (struct id_node *)malloc(sizeof(struct id_node));
			p->new_id = new_id;
			p->old_id = old_id;
			p->fd = sockfd;
			p->ts= time(NULL);
			id_insert(&id_tree, p);
		} else {
			ret = send(fd, msg, len, 0);
		}
		json_object_put(save_obj);
	} else {
		//ack, just send to miot
		log_printf(LOG_INFO, "U:ACK,fd:%d, len:%d\n", sockfd, len);
		ret = send(fd, msg, len, 0);
	}
	return ret;
}
/* In some cases, we might receive several accumulated json RPC, we need to split these json.
 * E.g.:
 *   {"count":1,"stack":"sometext"}{"count":2,"stack":"sometext"}{"count":3,"stack":"sometext"}
 *
 * return the length we've consumed, -1 on error
 */
int agent_recv_handler_one(int sockfd, char *msg, int msg_len, int flag)
{
	struct json_tokener *tok;
	struct json_object *json;
	int ret = 0;

	//log_printf(LOG_INFO, "%s: sockfd: %d, length: %d bytes\n", (flag == 0 ? "miot" : "client"), sockfd, msg_len);
	log_printf(LOG_DEBUG, "%s():%s\n",__func__, msg);
	if (json_verify(msg) < 0)
		return -1;

	/* split json if multiple */
	tok = json_tokener_new();
	while (msg_len > 0) {
		char *tmpstr;
		int tmplen;

		json = json_tokener_parse_ex(tok, msg, msg_len);
		if (json == NULL) {
			log_printf(LOG_ERROR, "token parse error msg: %.*s, length: %d bytes\n",
				    msg_len, msg, msg_len);
			json_tokener_free(tok);
			return ret;
		}

		tmplen = tok->char_offset;
		tmpstr = malloc(tmplen + 10);
		if (tmpstr == NULL) {
			log_printf(LOG_ERROR, "%s():malloc error\n", __func__);
			json_tokener_free(tok);
			json_object_put(json);
			return -1;
		}
		memcpy(tmpstr, msg, tmplen);
		tmpstr[tmplen] = '\0';

		if (flag == 1)
			client_msg_handler((char *)tmpstr, tmplen, sockfd);
		else
			miot_msg_handler((char *)tmpstr, tmplen);

		free(tmpstr);
		json_object_put(json);
		ret += tok->char_offset;
		msg += tok->char_offset;
		msg_len -= tok->char_offset;
	}
	json_tokener_free(tok);
	return ret;
}

/*
*receive msgs from miot or clientfd, and split to one msg
*flag = 0 means from miot
*flag = 1 means from clientfd
*/
int agent_recv_handler(int sockfd, int flag)
{
	char buf[MAX_BUF];
	ssize_t count;
	int left_len = 0;
	int ret = 0;
	bool first_read = true;

	memset(buf, 0, MAX_BUF);
	while (1) {
		count = recv(sockfd, buf + left_len, sizeof(buf) - left_len, MSG_DONTWAIT);
		if (count < 0) {
			return -1;
		}

		if (count == 0) {
			if (first_read && flag == 0) {
				log_printf(LOG_ERROR, "miot_fd :%d is closed, will be reconnect\n", sockfd);
				close(sockfd);
				agent.pollfds[0].fd = -1;
				miot_fd = -1;
			} else if (first_read && flag == 1) {
				log_printf(LOG_ERROR, "sockfd :%d occurs error, delete from agent\n", sockfd);
				delete_fd_from_agent(sockfd);
			}
			if (left_len) {
				buf[left_len] = '\0';
				log_printf(LOG_WARNING, "remain str: %s\n",buf);
			}
			return 0;
		}
		first_read = false;
		ret = agent_recv_handler_one(sockfd, buf, count + left_len, flag);
		if (ret < 0) {
			log_printf(LOG_ERROR, "agent_recv_handler_one errors:%d\n", ret);
			return -1;
		}

		left_len = count + left_len - ret;
		memmove(buf, buf + ret, left_len);
	}
	return 0;
}

int timer_setup(void)
{
	int fd;

	fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (fd < 0) {
		perror("timerfd_create");
		return fd;
	}

	return fd;
}

int timer_start(int fd, int first_expire, int interval)
{
	struct itimerspec new_value;

	new_value.it_value.tv_sec = first_expire / 1000;
	new_value.it_value.tv_nsec = first_expire % 1000 * 1000000;

	new_value.it_interval.tv_sec = interval / 1000;
	new_value.it_interval.tv_nsec = interval % 1000 * 1000000;

	if (timerfd_settime(fd, 0, &new_value, NULL) == -1) {
		perror("timerfd_settime");
		return -1;
	}

	return 0;
}

int insert_fd_within_key(struct key_node *pNode, int fd)
{
	int i = 0;
	while(i < MAX_CLIENT_NUM - 1 && pNode->fd[i]) {
		if (fd == pNode->fd[i])
			return 0;
		i++;
	}
	pNode->fd[i] = fd;
	return 1;
}

/**
 * register the interesting key with fd
 */
int key_insert(struct rb_root *root, const char *key, int fd)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct key_node *this = container_of(*new, struct key_node, node);
		int result = strcmp(key, this->key);

		parent = *new;
		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else {
			return insert_fd_within_key(this, fd);
		}
	}
	struct key_node *p;
	p = (struct key_node *)malloc(sizeof(struct key_node));
	memset(p, 0, sizeof(struct key_node));
	strcpy(p->key, key);
	p->fd[0] = fd;
	/* Add new node and rebalance tree. */
	rb_link_node(&p->node, parent, new);
	rb_insert_color(&p->node, root);

	return 1;
}

int key_search(struct rb_root *root, const char *key, struct key_node **pNode)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct key_node *this = container_of(node, struct key_node, node);
		int result = strcmp(key, this->key);

		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else {
			*pNode = this;
			return 1;
		}
	}
	return 0;
}

int delete_fd_from_agent(int sockfd)
{
	int i;

	remove_fd_from_keytree(sockfd);
	remove_fd_from_idtree(sockfd);

	for (i = 0; i < agent.count_pollfds; i++) {
		if (agent.pollfds[i].fd == sockfd)
			break;
	}

	if (i == agent.count_pollfds) return -1;

	close(agent.pollfds[i].fd);
	while (i < agent.count_pollfds - 1 && agent.pollfds[i].fd) {
		agent.pollfds[i] = agent.pollfds[i + 1];
		i++;
	}
	agent.pollfds[i].fd = -1;
	agent.count_pollfds--;
	return 0;
}

/**
 * unregister fd from specific key_node
 */
int remove_fd_from_keynode(struct key_node *pNode, int fd)
{
	int i, fd_found = 0, ret = -1;
	struct key_node *q = pNode;

	for (i = 0; i < MAX_CLIENT_NUM && q->fd[i]; i++) {
		if (fd == q->fd[i]) {
			fd_found = 1;
			break;
		}
	}

	if (fd_found == 1) {
		ret = 0;
		while(i < MAX_CLIENT_NUM - 1 && q->fd[i]) {
			q->fd[i] = q->fd[i + 1];
			i++;
		}
		q->fd[i] = 0;
		/*the key just has one fd, free it*/
		if (q->fd[0] == 0) {
			//printf("key is %s, fd is %d\n", q->key, fd);
			rb_erase(&q->node, &key_tree);
			free(q);
			ret = 1;
		}
	}
	return ret;
}

/**
 * unregister the interesting key with fd
 */
int remove_key_within_fd(int fd,  const char *key)
{
	struct key_node *p;
	int key_found;
	int ret = -1;
	key_found = key_search(&key_tree, key, &p);
	if (key_found == 0) {
		log_printf(LOG_WARNING, "Key not found: %s\n", key);
		return ret;
	}
	ret = remove_fd_from_keynode(p, fd);
	if (ret < 0) {
		log_printf(LOG_WARNING, "fd %d not found with the key %s\n", fd, key);
	}
	return ret;
}
/**
 * unregister all interesting key with fd
 */
void remove_fd_from_keytree(int fd)
{
	struct rb_node *node;
	struct key_node *p;
	int ret;

	node = rb_first(&key_tree);
	while (node) {
		p = rb_entry(node, struct key_node, node);
		ret = remove_fd_from_keynode(p, fd);
		if (ret == 1) {
			node = rb_first(&key_tree);
			continue;
		}
		node = rb_next(node);
	}
}

void print_registered_key(void)
{
	struct rb_node *node;
	struct key_node *p;
	int i = 0;

	log_printf(LOG_DEBUG, "===search all key_tree nodes start===\n");
	for (node = rb_first(&key_tree); node; node = rb_next(node)) {
		p = rb_entry(node, struct key_node, node);
		log_printf(LOG_DEBUG,"key = %s\n", p->key);
		for (i = 0; i < MAX_CLIENT_NUM && p->fd[i]; i++) {
			log_printf(LOG_DEBUG, "%d, \n", p->fd[i]);
		}
	}
	log_printf(LOG_DEBUG,"============end===========\n");
}

int send_to_register_client(char *msg, int msg_len)
{
	int ret =-1, key_found = 0;
	char *key;
	Node *p;
	struct json_object *parse, *tmp_obj;

	parse = json_tokener_parse(msg);

	json_object_object_get_ex(parse, "method", &tmp_obj);
	if (!json_object_is_type(tmp_obj, json_type_string)) {
		log_printf(LOG_ERROR, "method not string\n");
		json_object_put(parse);
		return ret;
	} else {
		key = (char *)json_object_get_string(tmp_obj);
	}

	key_found = key_search(&key_tree,  key, &p);
	if (key_found == 1) {
		int i = 0;
		while (i < MAX_CLIENT_NUM && p->fd[i]) {
			ret = send(p->fd[i], msg, msg_len, 0);
			log_printf(LOG_INFO,"S:cmd,fd:%d, len:%d\n",  p->fd[i], ret);
			i++;
		}
	} else {
		log_printf(LOG_WARNING,"no sockfd is registered, msg is %s\n",  msg);
	}
	json_object_put(parse);
	return ret;
}
/*
*record the id map
*/
int id_insert(struct rb_root *root, struct id_node *pNode)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	if (!pNode) {
		return -1;
	}
	/* Figure out where to put new node */
	while (*new) {
		struct id_node *this = container_of(*new, struct id_node, node);
		int result = pNode->new_id - this->new_id;

		parent = *new;
		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else {
			free(pNode);
			return 0;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&pNode->node, parent, new);
	rb_insert_color(&pNode->node, root);
	return 1;
}

int id_search(struct rb_root *root, int new_id, struct id_node **pNode)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct id_node *this = container_of(node, struct id_node, node);
		int result = new_id - this->new_id;

		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else {
			*pNode = this;
			return 1;
		}
	}
	return 0;
}

void remove_fd_from_idtree(int fd)
{
	struct rb_node *node;
	struct id_node *p;

	node = rb_first(&id_tree);
	while (node) {
		p = rb_entry(node, struct id_node, node);
		if (p->fd == fd) {
			rb_erase(&p->node, &id_tree);
			free(p);
			node = rb_first(&id_tree);
			continue;
		}
		node = rb_next(node);
	}
}

/*
*remove invaild id
*/
void update_id_tree(void)
{
	struct rb_node *node;
	struct id_node *p;
	unsigned int now = time(NULL);

	node = rb_first(&id_tree);
	while (node) {
		p = rb_entry(node, struct id_node, node);
		if (now > p->ts + MAX_VALID_TIME) {
			rb_erase(&p->node, &id_tree);
			free(p);
			node = rb_first(&id_tree);
			continue;
		}
		node = rb_next(node);
	}
}

void remove_id_node(struct id_node *p)
{
	rb_erase(&p->node, &id_tree);
	free(p);
}

int send_ack_to_client(char *msg)
{
	ID_Node *p;
	int id, found = 0;
	int ret = -1;

	if (json_verify_get_int(msg, "id", &id) != 0) {
		return -1;
	}

	found = id_search(&id_tree, id, &p);
	if (found == 1) {
		int old_id, fd, msg_len;
		char *newmsg;
		struct json_object *parse;

		//get old id and fd
		old_id = p->old_id;
		fd = p->fd;
		remove_id_node(p);

		parse = json_tokener_parse(msg);
		/* replace with new id */
		json_object_object_del(parse, "id");
		json_object_object_add(parse, "id", json_object_new_int(old_id));
		newmsg = (char *)json_object_to_json_string_ext(parse, JSON_C_TO_STRING_PLAIN);
		msg_len = strlen(newmsg);

		ret = send(fd, newmsg, msg_len, 0);
		log_printf(LOG_INFO, "S:ACK, new_id:%d, old_id:%d, fd:%d,length: %d\n", id, old_id, fd, msg_len);
		json_object_put(parse);
	} else {
		log_printf(LOG_WARNING, "id %d not found\n",  id);
	}
	return ret;
}

void print_id_tree(void)
{
	struct rb_node *node;
	struct id_node *p;
	log_printf(LOG_DEBUG, "===search all id_tree nodes start===\n");
	for (node = rb_first(&id_tree); node; node = rb_next(node)) {
		p = rb_entry(node, struct id_node, node);
		log_printf(LOG_DEBUG, "fd is %d\t, old_id is %d\t, new_id is %d\n", p->fd, p->old_id, p->new_id);
	}
	log_printf(LOG_DEBUG, "===========end==========\n");
}

void free_key_tree(void)
{
	struct rb_node *node;
	struct key_node *p;

	node = rb_first(&key_tree);
	while (node) {
		p = rb_entry(node, struct key_node, node);
		rb_erase(&p->node, &key_tree);
		free(p);
		node = rb_first(&key_tree);
	}
}

void free_id_tree(void)
{
	struct rb_node *node;
	struct id_node *p;

	node = rb_first(&id_tree);
	while (node) {
		p = rb_entry(node, struct id_node, node);
		rb_erase(&p->node, &id_tree);
		free(p);
		node = rb_first(&id_tree);
	}
}

void logfile_init(char *filename)
{
	FILE *fp;

	fp = fopen(filename, "a");
	if (fp == NULL) {
		log_printf(LOG_ERROR, "can't open %s: %m\n", filename);
		return;
	}

	log_file = fp;
}

void log_printf(log_level_t level, const char *fmt, ...)
{
	char buf[80];
	time_t now;
	va_list ap;
	struct tm *p;
	char *slevel;

	if (stdout == NULL)
		return;

	if (level <= g_loglevel) {
		switch (level) {
		case LOG_ERROR   : slevel = "[ERROR]"; break;
		case LOG_WARNING : slevel = "[WARNING]"; break;
		case LOG_INFO    : slevel = "[INFO]"; break;
		case LOG_DEBUG   : slevel = "[DEBUG]"; break;
		case LOG_VERBOSE : slevel = "[VERBOSE]"; break;
		default          : slevel = "[UNKNOWN]"; break;
		}

		now = time(NULL);
		p = localtime(&now);
		strftime(buf, 80, "[%Y%m%d %H:%M:%S]", p);

		va_start(ap, fmt);
		fprintf(log_file, "%s %s ", buf, slevel);
		vfprintf(log_file, fmt, ap);
		va_end(ap);
		fflush(log_file);
	}
}