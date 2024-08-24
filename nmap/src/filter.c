#include "ft_nmap.h"

void addrinfo_to_ipv4_string(const struct addrinfo *addr, char *buffer, size_t buffer_size) {
	// Ensure the address is IPv4
	if (addr->ai_family == AF_INET) {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)addr->ai_addr;

		// Convert the integer IP address to a string
		if (inet_ntop(AF_INET, &ipv4->sin_addr, buffer, buffer_size) == NULL) {
			perror("inet_ntop");
			// Handle error (for example, set buffer to an empty string)
			buffer[0] = '\0';
		}
	} else {
		fprintf(stderr, "Not an IPv4 address.\n");
		buffer[0] = '\0';  // Empty the buffer if not IPv4
	}
}

char *create_filter(int scan, host_data dest_ip) {
	char buffer[INET_ADDRSTRLEN];
	struct sockaddr_in *ip_struct = (struct sockaddr_in *)dest_ip.info.ai_addr;

	if (inet_ntop(AF_INET, &ip_struct->sin_addr, buffer, sizeof(buffer)) == NULL) {
		perror("imet_ntop");
		return NULL;
	}

	if (scan == UDP_SCAN) {
		return ft_strjoin("(udp or icmp) and src host ", buffer);
	} else {
		return ft_strjoin("(tcp or icmp) and src host ", buffer);
	}
}
