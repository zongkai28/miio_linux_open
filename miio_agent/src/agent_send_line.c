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

int main(int argc, char**argv)
{
	int sockfd, n;
	struct sockaddr_in servaddr;

	if (argc != 2) {
		printf("Usage: %s msg\n", argv[0]);
		exit(-1);
	}

	if (strlen(argv[1]) >= DATA_MAX) {
		printf("msg too long, max %d\n", DATA_MAX);
		exit(-1);
	}

	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(SERVER_IP);
	servaddr.sin_port = htons(SERVER_PORT);

	if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
		printf("Connect to server error: %s:%d\n", SERVER_IP, SERVER_PORT);
		return -1;
	}

	n = send(sockfd, argv[1], strlen(argv[1]), 0);

	return 0;
}
