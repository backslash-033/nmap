#include "ft_nmap.h"

void    scanner(ip_addr_t **ip_list,
				int *port_list, int len_port_list,
                ip_addr_t src_ip, int src_port,
                int scan, char *data, int data_len) {
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
	int (*scanner_func)(ip_addr_t, ip_addr_t, int, int, int, char *, int) = NULL;

	if (scan != -1)
		scanner_func = tcp_scan;
	else
		scanner_func = udp_scan;

	while (dest_ip) {
		for (int j = 0; j < len_port_list; j++) {
			dest_port = port_list[j];
			ret = scanner_func(src_ip, *dest_ip, src_port, dest_port, scan, data, data_len);
			printf("IP: %s\nPort: %d\nRet: %d\n", dest_ip->printable, dest_port, ret);
		}
		dest_ip = *(++ip_list);
	}
}

void sigint_handler() {
    exit(1);
}

int main() {
    signal(SIGINT, sigint_handler);
	char data[] = "HELLO\0";
	int *port = malloc(sizeof(int) * 1);
	port[0] = 80;
	ip_addr_t **ips_to_scan = parse_ips(ft_split("127.0.0.1\n", '\n'));
	ip_addr_t **source_ips = parse_ips(ft_split("127.0.0.1\n", '\n'));
	ip_addr_t **copy_ips;
	ip_addr_t *addr;
	int scan = SYN_SCAN;

	if (!ips_to_scan || !source_ips) {
		fprintf(stderr, "Error parsing IPs\n");
		return 1;
	}
	copy_ips = ips_to_scan;
	addr = *ips_to_scan;
	while (addr) {
		printf("Printable is: %s\nInt is: %d\n", (*ips_to_scan)->printable, (*ips_to_scan)->network);
		addr = *(++ips_to_scan);
	}
	ips_to_scan = copy_ips;

	scanner(ips_to_scan, port, 1, **source_ips, 12345, scan, data, strlen(data));
}
