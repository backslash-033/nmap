#include "ft_nmap.h"

int	main_thread(const uint16_t *ports, const uint32_t size, t_scan *scan) {
	int ret;

	// TODO Make me dynamic
	char dev[] = "eth0";


	scan->results = create_port_state_vector(ports, (size_t)size);
	if (!scan->results) {
		return -1;
	}
	
    ret = listener(dev, *scan);
	if (ret != 0) {
		// TODO free scan in calling function
		return -1;
	}

	return 0;
}