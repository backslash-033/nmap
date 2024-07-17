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
    (void)ip_list;
    (void)port_list;
	(void)len_port_list;
	(void)src_ip;
	(void)src_port;
    (void)scan;
	(void)data;
	(void)data_len;
    

	ip_addr_t *dest_ip = *ip_list;
	int dest_port;
	int (*scanner_func)(ip_addr_t, ip_addr_t, int, int, char *, int) = NULL;

	switch (scan) {
		case SYN_SCAN:
			scanner_func = syn_scan;
			break;
		case NULL_SCAN:
			scanner_func = null_scan;
			break;
		case ACK_SCAN:
			scanner_func = ack_scan;
			break;
		case FIN_SCAN:
			scanner_func = fin_scan;
			break;
		case XMAS_SCAN:
			scanner_func = xmas_scan;
			break;
		case UDP_SCAN:
			scanner_func = udp_scan;
			break;
		default:
			fprintf(stderr, "Please choose valid scan option.\n");
			return ;
	}

	while (dest_ip) {
		for (int j = 0; j < len_port_list; j++) {
			dest_port = port_list[j];
			ret = scanner_func(src_ip, *dest_ip, src_port, dest_port, data, data_len);
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
    char data[] = "GET / HTTP/1.1";
	int *port = malloc(sizeof(int) * 1);
	port[0] = 80;
	ip_addr_t **ips_to_scan = parse_ips(ft_split("127.0.0.1\n127.0.0.2\n", '\n'));

	if (!ips_to_scan) {
		fprintf(stderr, "Error parsing IPs\n");
		return 1;
	}
	ip_addr_t **copy_ips = ips_to_scan;
	ip_addr_t *addr = *ips_to_scan;
	while (addr) {
		printf("Printable is: %s\nInt is: %d\n", (*ips_to_scan)->printable, (*ips_to_scan)->network);
		addr = *(++ips_to_scan);
	}

	ips_to_scan = copy_ips;
	ip_addr_t src_ip;
	memset(&src_ip, 0, sizeof(src_ip));
	strncpy(src_ip.printable, IP_ADDRESS, INET_ADDRSTRLEN);
	src_ip.network = INADDR_LOOPBACK;

	scanner(ips_to_scan, port, 1, src_ip, 12345, SYN_SCAN, data, sizeof(data));
}
