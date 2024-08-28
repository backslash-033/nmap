#include "ft_nmap.h"

extern int	thread_errno;

void *routine(void * arg) {
	const tdata_in in = *(tdata_in *)arg;
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
	src_ip.network = in.opts->source;
	inet_ntop(AF_INET, &(src_ip.network), src_ip.printable, INET_ADDRSTRLEN);

	if (scanner(ptr, port_vector, src_ip, in.port, in.scans, in.opts->data, strlen(in.opts->data), in.opts) != 0)
		thread_errno = ECANCELED;

	free(port_list);
	free(ptr);

	return NULL;
}