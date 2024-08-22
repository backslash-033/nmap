#include "ft_nmap.h"

int    scanner(ip_addr_t **ip_list,
				t_uint16_vector port_vector,
				ip_addr_t src_ip, int src_port,
				int scan, char *data, int data_len,
				const options *opts) {
	/*
	Core function of the Nmap scanner. Calls the necessary functions to perform
	the different scans proposed by the utilitary. The parameters MUST be
	already parsed, or set to default values (see args)

	Args:
		ip_addr_t **ip_list: the list of IPs to be scanned
			The array of ip_addr_t * MUST be NULL-terminated.
		int *port_list: the list of ports to be scanned.
		int len_port_list: the length of the list of ports to be scanned.
		ip_addr_t src_ip: the IP address to emit the packets from.
		int src_port: the port to emit the packets from.
		int scan: the scan to be performed on the hosts and ports.
		char *data: the data to transmit when sending a packet
			Doesn't need to be \0 terminated.
		int data_len: the length (in bytes) of the passed data

	Returns:
		Nothing    
	*/
	int ret;
	ip_addr_t *dest_ip = *ip_list;
	int dest_port;
	int (*scanner_func)(ip_addr_t, ip_addr_t, int, int, int, char *, int, const options *) = NULL;


	printf("SRC IP Address: %s\n", src_ip.printable);
    printf("DEST IP Address: %s\n", (*ip_list)->printable);

	if (scan != -1)
		scanner_func = tcp_scan;
	else
		scanner_func = udp_scan;

	while (dest_ip) {
		for (size_t j = 0; j < port_vector.len; j++) {
			dest_port = port_vector.list[j];
			ret = scanner_func(src_ip, *dest_ip, src_port, dest_port, scan, data, data_len, opts);
			if (ret != 0)
				return ret;
		}
		dest_ip = *(++ip_list);
	}
	return 0;
}

void sigint_handler() {
    exit(1);
}

// int main() {
//     signal(SIGINT, sigint_handler);
// 	char data[] = "HELLO\0";
// 	size_t len_ports = 2;
// 	int *ports = malloc(sizeof(int) * len_ports);
// 	ports[0] = 80;
// 	ports[1] = 443;
// 	char **raw_ips_to_scan = ft_split("127.0.0.1\n", '\n');
// 	char **raw_source_ips = ft_split("127.0.0.1\n", '\n');
// 	ip_addr_t **ips_to_scan = parse_ips(raw_ips_to_scan);
// 	ip_addr_t **source_ips = parse_ips(raw_source_ips);
// 	ip_addr_t **copy_ips;
// 	ip_addr_t *addr;
// 	int scan = SYN_SCAN;

// // 	if (!ips_to_scan || !source_ips) {
// // 		fprintf(stderr, "Error parsing IPs\n");
// // 		return 1;
// // 	}
// // 	copy_ips = ips_to_scan;
// // 	addr = *ips_to_scan;
// // 	while (addr) {
// // 		printf("Printable is: %s\nInt is: %d\n", (*ips_to_scan)->printable, (*ips_to_scan)->network);
// // 		addr = *(++ips_to_scan);
// // 	}
// // 	ips_to_scan = copy_ips;

// 	scanner(ips_to_scan, ports, len_ports, **source_ips, 12345, scan, data, strlen(data));
// 	printf("End of scan\n");
// 	// free_formatted_ips(ips_to_scan);
// 	// free_formatted_ips(source_ips);
// 	free_darray((void **)ips_to_scan);
// 	free_darray((void **)source_ips);
// 	free(ports);
// 	free_darray((void **)raw_ips_to_scan);
// 	free_darray((void **)raw_source_ips);
// }
