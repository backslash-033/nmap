#include "ft_nmap.h"

int    scanner(ip_addr_t **ip_list,
				t_uint16_vector port_vector,
				ip_addr_t src_ip, int src_port,
				int scan, char *data, size_t data_len,
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
		size_t data_len: the length (in bytes) of the passed data

	Returns:
		Nothing    
	*/
	int ret;
	ip_addr_t *dest_ip = *ip_list;
	int dest_port;
	int (*scanner_func)(ip_addr_t, ip_addr_t, int, int, int, char *, size_t, const options *) = NULL;

	if (scan == -1 || scan == 255)
		scanner_func = udp_scan;
	else
		scanner_func = tcp_scan;

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
