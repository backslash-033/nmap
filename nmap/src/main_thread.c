#include "ft_nmap.h"

int	main_thread(const t_uint16_vector ports, t_scan *scan) {
	int ret;

	// TODO Make me dynamic
	char dev[] = "eth0";


	scan->results = create_port_state_vector(ports.list, ports.len);
	if (!scan->results) {
		return -1;
	}
	
    ret = listener(dev, *scan);
	if (ret != 0) {
		// TODO free scan in calling function OR here if simpler
		return -1;
	}

	return 0;
}