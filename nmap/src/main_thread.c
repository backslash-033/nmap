#include "ft_nmap.h"

void	main_thread(const uint16_t *ports, const uint32_t size) {
	t_port_state_vector states;
    int scan;

    scan = SYN_SCAN;
	char dev[] = "eth0";

    states.ports = calloc(size, sizeof(t_port_state));

	for (int i = 0; i < (int)size; i++) {
		states.ports[i].port = ports[i];
		states.ports[i].state = NOTHING;
	}
    states.len = size;

    listener(dev, scan, states);

	free(states.ports);
}