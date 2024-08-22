#include "ft_nmap.h"

// TODO delete me, for debug
void print_ip(uint32_t ip_addr) {
	char ip_str[INET_ADDRSTRLEN];  // Buffer to hold the IPv4 address string

	// Convert the IP address from network byte order to string format
	if (inet_ntop(AF_INET, &ip_addr, ip_str, INET_ADDRSTRLEN) == NULL) {
		perror("inet_ntop");
		return;
	}

	// Print the IP address in string format
	printf("IP Address: %s\n", ip_str);
}

// TODO delete me, for debug
void print_my_ip() {
    struct ifaddrs *ifaddr, *ifa;
    char ip[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            void *addr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            inet_ntop(AF_INET, addr, ip, NI_MAXHOST);
            printf("Interface: %s\tAddress: %s\n", ifa->ifa_name, ip);
        }
    }

    freeifaddrs(ifaddr);
}

// FIXME doesn't work for eth0
void *routine(void * arg) {
	tdata_in in = *(tdata_in *)arg;
	int	*port_list = NULL;
	t_uint16_vector port_vector = {
		.list = NULL,
		.len = in.hnp.ports_len,
	};
	ip_addr_t	**ptr;
	ip_addr_t	to_scan;
	ip_addr_t	src_ip;

	ptr = calloc(2, sizeof(ip_addr_t *));
	if (ptr == NULL)
		return NULL;
	ptr[0] = &to_scan;

	to_scan.network = ((struct sockaddr_in *)in.hnp.host.info.ai_addr)->sin_addr.s_addr;
	inet_ntop(AF_INET, &(to_scan.network), to_scan.printable, INET_ADDRSTRLEN);

	port_list = calloc(in.hnp.ports_len, sizeof(int));
	if (port_list == NULL) {
		return NULL;
	}

	port_vector.list = in.hnp.ports;

	print_my_ip();
	printf("Source ");
	print_ip(in.opts->source);
	src_ip.network = in.opts->source;
	inet_ntop(AF_INET, &(src_ip.network), src_ip.printable, INET_ADDRSTRLEN);

	scanner(ptr, port_vector, src_ip, in.port, in.scans, in.opts->data, strlen(in.opts->data), in.opts);

	free(port_list);
	free(ptr);


	return NULL;
}