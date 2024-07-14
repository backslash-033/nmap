#include "ft_nmap.h"

typedef struct ip_addr_s {
    char    printable[INET_ADDRSTRLEN];
    int     network;
}           ip_addr_t;

int convert_ip(char *ip, ip_addr_t *ip_addr) {
	struct sockaddr_in sockaddr;
	int ret;

    // Get the source address into int format
    ret = inet_pton(AF_INET, ip, &(sockaddr.sin_addr));
    if (ret == 0) {
        fprintf(stderr, "%s is not a valid source IP address\n", ip);
        return -1;
    } else if (ret == -1) {
        perror("Error turning source IP to network format");
        return -1;
    }
	strlcpy(ip_addr->printable, ip, strlen(ip));
	ip_addr->printable[INET_ADDRSTRLEN] = 0;
	ip_addr->network = sockaddr.sin_addr.s_addr;
	return 0;
}