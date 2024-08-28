#include "ft_nmap.h"

static int convert_ip(char *ip, ip_addr_t *ip_addr) {
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
	memset(ip_addr->printable, 0, INET_ADDRSTRLEN);
	ft_strlcpy(ip_addr->printable, ip, strlen(ip) + 1);
	ip_addr->network = sockaddr.sin_addr.s_addr;
	return 0;
}

ip_addr_t **parse_ips(char **ips) {
	int ret = 0;
	char *ip = *ips;
	int len_list = 0;
	ip_addr_t **formatted_ips;

	while (*(ips + len_list))
		len_list++;
	formatted_ips = malloc((len_list + 1) * sizeof(ip_addr_t *));
	if (!formatted_ips) {
		perror("malloc");
		return NULL;
	}
	formatted_ips[len_list] = NULL;
	len_list = 0;
	while (ip) {
		puts("Loop");
		formatted_ips[len_list] = malloc(sizeof(ip_addr_t));
		if (!formatted_ips[len_list]) {
			perror("malloc");
			free_darray((void **)formatted_ips);
			return NULL;
		}
		ret = convert_ip(ip, formatted_ips[len_list]);
		if (ret == -1) {
			free_darray((void **)formatted_ips);
			return NULL;
		}
		len_list++;
		ip  = *(++ips);
	}
	return formatted_ips;
}