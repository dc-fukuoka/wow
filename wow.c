#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ctype.h>

#define SIZE    128
#define MAC_LEN 17 /* aa:bb:cc:dd:ee:ff */

char ip_str[16];
unsigned char mac[6]; /* 6 bytes */
unsigned char magic_packet[102]; /* first 6 bytes:FF, and MACx16, 6*17 = 102 */
int port;

#define myassert(expr, fmt, ...) \
	do {								\
		if (!(expr)) {						\
			fprintf(stderr, "%s:%d in %s(): %s: "fmt, __FILE__, __LINE__, __func__, strerror(errno), ## __VA_ARGS__); \
			exit(EXIT_FAILURE);				\
		}							\
	} while(0)

int check_mac(const char *_mac)
{
	char *mac_dup = strdup(_mac);
	/* check the length */
	if (strlen(mac_dup) != MAC_LEN)
		goto err;

	/* check if '-' or ':' exists and its count is 5 */
	char *p;
	int cnt = 0;
	for (p=mac_dup+2; *p; p+=3) {
		switch(*p) {
		case '-':
		case ':':
			cnt++;
			break;
		default:
			goto err;
		}
	}
	if (cnt != 5) goto err;


	char *mac_str[6];
	for (p=mac_dup; *p; p++) {
		switch(*p) {
		case '-':
		case ':':
			*p = '\0';
		default:
			break;
		}
	}
	int i = 0;
	for (p=mac_dup; *p; p+=3) {
		mac_str[i] = p;
		i++;
	}

	for (i=0; i<6; i++)
		sscanf(mac_str[i], "%x", &mac[i]);
#ifdef _DEBUG
	printf("debug: mac:\n");
	for (i=0; i<6; i++)
		printf("%02x ", mac[i]);
	printf("\n");
#endif

	free(mac_dup);
	return 0;
err:
	fprintf(stderr, "MAC address is invalid.\n");
	if (mac_dup) free(mac_dup);
	exit(EXIT_FAILURE);
}

int set_magic_packet(void)
{
	int i, j;
	
	for (i=0; i<6; i++)
		magic_packet[i] = (unsigned char)(-1);
	for (i=6; i<102; i++) {
		magic_packet[i] = mac[i%6];
	}
	return 0;
}


int resolv_name(const char *node, char *ip_str)
{
	
	struct in_addr addr;
	struct addrinfo hints, *res = NULL;
	int err;

	err = getaddrinfo(node, NULL, NULL, &res);
	myassert(err == 0, "getaddrinfo(), %s\n", gai_strerror(err));

	addr.s_addr = ((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;
	myassert(inet_ntop(AF_INET, &addr, ip_str, 16), "inet_ntop()\n");
	freeaddrinfo(res);
	printf("%s -> %s\n", node, ip_str);
	return 0;
}

int send_magic_packet(void)
{
	int sockfd;
	struct sockaddr_in server_addr;
	in_addr_t ip = inet_addr(ip_str);
	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	myassert(sockfd >= 0, "socket()\n");

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family      = AF_INET;
	server_addr.sin_addr.s_addr = ip;
	server_addr.sin_port        = htons(port);
			
	myassert(connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) >= 0, "connect()\n");

	printf("connected\n");

	myassert(send(sockfd, magic_packet, sizeof(magic_packet), MSG_DONTWAIT) >= 0, "send()\n");
	printf("sent magic packet...\n");
	myassert(close(sockfd) >= 0, "close()\n");
	return 0;
}

int main(int argc, char **argv)
{
	if (!argv[1] || !argv[2] || !argv[3]) {
		fprintf(stderr, "usage: %s <FQDN> <MAC address> <port no>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	
	char *node = argv[1];
	char *_mac = argv[2];
	port = atoi(argv[3]);

	resolv_name(node, ip_str);
	check_mac(_mac);
	set_magic_packet();

#ifdef _DEBUG
	printf("debug: %s: %s\n", node, ip_str);
	int i;
	printf("debug: packet:\n");
	for (i=0; i<102; i++)
		printf("%02x ", magic_packet[i]);
	printf("\n");
#endif

	send_magic_packet();
	
	return 0;
}
