#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

#define MAC_LEN 17 /* aa:bb:cc:dd:ee:ff */

struct magic_packet_info {
	char ip_str[15]; /* aaa.bbb.ccc.ddd */
	unsigned char mac[6]; /* 6 bytes */
	unsigned char magic_packet[102]; /* first 6 bytes:FF, and MACx16, 6*17 = 102 */
	uint16_t port;
};

#define myassert(expr, fmt, ...) \
        do {                                                            \
                if (!(expr)) {                                          \
                        fprintf(stderr, "%s:%d in %s(): %s: "fmt, __FILE__, __LINE__, __func__, strerror(errno), ## __VA_ARGS__); \
                        exit(EXIT_FAILURE);                             \
                }                                                       \
        } while(0)

int check_mac(const char *mac, struct magic_packet_info *minfo)
{
        char *mac_dup = strdup(mac);
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
                sscanf(mac_str[i], "%hhx", &minfo->mac[i]);
#ifdef _DEBUG
        printf("debug: mac:\n");
        for (i=0; i<6; i++)
                printf("%02x ", minfo->mac[i]);
        printf("\n");
#endif

        free(mac_dup);
        return 0;
err:
        fprintf(stderr, "MAC address is invalid.\n");
        if (mac_dup) free(mac_dup);
        exit(EXIT_FAILURE);
}

int set_magic_packet(struct magic_packet_info *minfo)
{
        int i;

        for (i=0; i<6; i++)
                minfo->magic_packet[i] = (unsigned char)(-1);
        for (i=6; i<102; i++)
                minfo->magic_packet[i] = minfo->mac[i%6];
        return 0;
}

int resolv_name(const char *node, struct magic_packet_info *minfo)
{

        struct in_addr addr;
        struct addrinfo hints, *res = NULL;
        int err;

        err = getaddrinfo(node, NULL, NULL, &res);
        myassert(err == 0, "getaddrinfo(), %s\n", gai_strerror(err));

        addr.s_addr = ((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;

        memset(minfo->ip_str, '\0', sizeof(minfo->ip_str));
        myassert(inet_ntop(AF_INET, &addr, minfo->ip_str, 16) != 0, "inet_ntop()\n");
        freeaddrinfo(res);
        printf("%s -> %s\n", node, minfo->ip_str);
        return 0;
}

int send_magic_packet(struct magic_packet_info *minfo)
{
        int sockfd;
        struct in_addr ip;
        struct sockaddr_in client_addr, server_addr;
        int optval = 1;

        myassert(inet_aton(minfo->ip_str, &ip) != 0, "inet_aton()\n");

        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        myassert(sockfd >= 0, "socket()\n");
        printf("using UDP protocol...\n");

//      myassert(setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) >= 0, "setsockopt()\n");

        memset(&client_addr, 0, sizeof(client_addr));
        client_addr.sin_family      = AF_INET;
        client_addr.sin_addr.s_addr = INADDR_ANY;
        client_addr.sin_port        = 0;

        myassert(bind(sockfd, (struct sockaddr*)&client_addr, sizeof(client_addr)) >= 0, "bind()\n");

        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family      = AF_INET;
        server_addr.sin_addr.s_addr = ip.s_addr;
        server_addr.sin_port        = htons(minfo->port);

#ifdef _DEBUG
        printf("debug: port: %u <-> %d\n", server_addr.sin_port, minfo->port);
        printf("debug: %s <-> %u\n", minfo->ip_str, ip.s_addr);
#endif

        myassert(sendto(sockfd, minfo->magic_packet, sizeof(minfo->magic_packet), 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) == sizeof(minfo->magic_packet), "sendto()\n");
        printf("sent magic packet...\n");
        myassert(close(sockfd) >= 0, "close()\n");
        return 0;
}

int main(int argc, char **argv)
{
        if (argc != 4) {
                fprintf(stderr, "usage: %s <FQDN> <MAC address> <UDP port no>\n", argv[0]);
                exit(EXIT_FAILURE);
        }

	struct magic_packet_info minfo;

        char *node = argv[1];
        char *mac = argv[2];
        minfo.port = (uint16_t)atoi(argv[3]);

        resolv_name(node, &minfo);
        check_mac(mac, &minfo);
        set_magic_packet(&minfo);

#ifdef _DEBUG
        printf("debug: %s: %s\n", node, minfo.ip_str);
        int i;
        printf("debug: packet:\n");
        for (i=0; i<102; i++)
                printf("%02x", minfo.magic_packet[i]);
        printf("\n");
#endif

        send_magic_packet(&minfo);

        return 0;
}
