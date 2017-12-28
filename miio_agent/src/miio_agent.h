#ifndef __MIIO_H
#define __MIIO_H

#include "rbtree.h"

#define SERVER_IP	"127.0.0.1"
#define MIOT_SERVER_PORT	54322
#define DISPATCHER_SERVER_PORT	54320

#define POLL_TIMEOUT			100	/* 100ms */
#define MAX_CLIENT_NUM		20
#define MAX_POLL_FDS			(MAX_CLIENT_NUM + 3)
#define MAX_BUF			4096
#define TIMER_INTERVAL		3000	/* 3s */

#define MAX_KEY_NUM		100
#define MAX_KEY_LEN			32
#define KEY_NUM_INDEX		0
#define MAX_VALID_TIME		180
#define MAX_ID_NUM			2147483647

struct agent_info
{
	struct pollfd pollfds[MAX_POLL_FDS];
	int count_pollfds;
};

typedef struct key_node {
	struct rb_node node;
	char key[MAX_KEY_LEN];
	int fd[MAX_CLIENT_NUM];
}Node;

typedef struct id_node
{
	struct rb_node node;
	int new_id;
	int old_id;
	int fd;
	unsigned int ts;
}ID_Node;

typedef enum
{
	LOG_ERROR = 0,
	LOG_WARNING,
	LOG_INFO,
	LOG_DEBUG,
	LOG_VERBOSE,
	LOG_LEVEL_MAX = LOG_VERBOSE
} log_level_t;

int  miot_connect_init(void);
int  agent_server_init(void);

int agent_listen_handler(int listenfd);
int agent_recv_handler(int sockfd, int flag);
int agent_recv_handler_one(int sockfd, char *msg, int msg_len, int flag);

int miot_msg_handler(char *msg, int msg_len);
int client_msg_handler(char *msg, int len, int sockfd);

int timer_setup(void);
void timer_handler(int fd);
int timer_start(int fd, int first_expire, int interval);

int key_search(struct rb_root *root, const char *key, struct key_node **pNode);
int key_insert(struct rb_root *root, const char *key, int fd);
int remove_fd_from_keynode(struct key_node *pNode, int fd);
void remove_fd_from_keytree(int fd);
int remove_key_within_fd(int fd,  const char *key);
void print_registered_key(void);
void free_key_tree(void);

int id_insert(struct rb_root *root, struct id_node *pNode);
int id_search(struct rb_root *root, int new_id, struct id_node **pNode);
void remove_id_node(struct id_node *p);
void remove_fd_from_idtree(int fd);
void print_id_tree(void);
void free_id_tree(void);
void update_id_tree(void);

int delete_fd_from_agent(int sockfd);

int send_to_register_client(char *msg, int msg_len);
int send_ack_to_client(char *msg);

void logfile_init(char *filename);
void log_printf(log_level_t level, const char *fmt, ...);

void print_id_list(void);
#endif
