#include "ft_nmap.h"

static void	sdisplay_port_range(uint16_t *array, uint32_t size, str s, uint32_t *a);

void *routine(void * arg) {
	tdata_in in = *(tdata_in *)arg;
	str s;
	uint32_t a = 0;

	// TODO: Get rid of or change the behavior
	in.output->data = calloc(1000, 1);

	s = in.output->data;

	printf("My port: %d\n", in.port);
	printf("My scan: %d\n", in.scans);

	for (int i = 0; in.hnp[i].ports; i++) {
		int	*port_list = NULL;
		host_and_ports	current = in.hnp[i];
		t_uint16_vector port_vector = {
			.list = NULL,
			.len = current.ports_len,
		};
		a += sprintf((s + a), "Host: %s\n", current.host.basename);
		a += sprintf((s + a), "Range: ");
		sdisplay_port_range(current.ports, current.ports_len, s, &a);
		a += sprintf((s + a), "\n\n");


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

static void	sdisplay_port_range(uint16_t *array, uint32_t size, str s, uint32_t *a) {
	bool	in_range = false;

	if (size == 1) {
		*a += sprintf((s + *a), "%hu\n", array[0]);
	}
	else {
		for (uint32_t i = 0; i != (size - 1); i++) {
			if (!in_range)
				*a += sprintf((s + *a), "%hu", array[i]);
			if (array[i] + 1 == array[i + 1] && !in_range) {
				in_range = true;
				*a += sprintf((s + *a), "-");
			}
			if (array[i] + 1 != array[i + 1] && in_range) {
				in_range = false;
				*a += sprintf((s + *a), "%hu,", array[i]);
			}
		}
		*a += sprintf((s + *a), "%hu", array[size - 1]);
	}

}