/*
 * Simple tcp client, send data and quit
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DATA_MAX	1024
#define SERVER_IP	"127.0.0.1"
#define SERVER_PORT	54320

/*
"{"method":"register","key":"%s"}"
"{"method":"unregister","key":"%s"}"
"{"method":"unregister","key":"%s"}"  //if key is null, unregister all*/

char *reg_template1 = "{\"method\":\"register\",\"key\":\"set_light\"}";
char *reg_template2 = "{\"method\":\"register\",\"key\":\"set_watermark\"}";
char *unreg_template1 = "{\"method\":\"unregister\",\"key\":\"keya\"}";
char *unreg_template2 = "{\"method\":\"unregister\",\"key\":\"keyc\"}";
char *unreg_template3 = "{\"method\":\"unregister\",\"key\":\"\"}";

int main(int argc, char**argv)
{
	int sockfd, n;
	struct sockaddr_in servaddr;
	char buf[DATA_MAX];

	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(SERVER_IP);
	servaddr.sin_port = htons(SERVER_PORT);

	if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
		printf("Connect to server error: %s:%d\n", SERVER_IP, SERVER_PORT);
		return -1;
	}

	n = send(sockfd, reg_template1, strlen(reg_template1), 0);
	printf("reg key:%s send ret : %d\n", reg_template1, n);

	n = send(sockfd, reg_template2, strlen(reg_template2), 0);
	printf("reg key:%s send ret : %d\n", reg_template2, n);

	while (1) {
		n = recv(sockfd, buf, sizeof(buf), 0);
		printf("client1 recv msg is %s\n", buf);
	}

	return 0;
}