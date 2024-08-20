#include "ft_nmap.h"

void *routine(void * arg) {
	tdata_in in = *(tdata_in *)arg;

	printf("My port: %d\n", in.port);
	printf("My scan: %d\n", in.scans);

	for (int i = 0; in.hnp[i].ports; i++) {
		int	*port_list = NULL;
		host_and_ports	current = in.hnp[i];
		t_uint16_vector port_vector = {
			.list = NULL,
			.len = current.ports_len,
		};

		ip_addr_t	**ptr = calloc(2, sizeof(ip_addr_t *));
		ip_addr_t	to_scan;

		ptr[0] = &to_scan;

		to_scan.network = ((struct sockaddr_in *)current.host.info.ai_addr)->sin_addr.s_addr;
		inet_ntop(AF_INET, &(to_scan.network), to_scan.printable, INET_ADDRSTRLEN);

		printf(".network: %d\n", to_scan.network);
		printf(".printable: %s\n", to_scan.printable);

		port_list = calloc(current.ports_len, sizeof(int));
		if (port_list == NULL) {
			return NULL;
		}

		port_vector.list = current.ports;

		ip_addr_t	src_ip;

		// TODO: Make it dynamic ?
		src_ip.network = 16777343;
		inet_ntop(AF_INET, &(src_ip.network), src_ip.printable, INET_ADDRSTRLEN);

		scanner(ptr, port_vector, src_ip, in.port, in.scans, "salut", 5);

		free(port_list);
		free(ptr);
	}


	return NULL;
}