#include "ft_nmap.h"

t_port_state_vector	*main_thread(const uint16_t *ports, const uint32_t size, enum e_scans scan) {
	t_port_state_vector *states;

	// TODO Make me dynamic
	char dev[] = "eth0";


	// TODO use create_port_state_vector
	states = calloc(1, sizeof(t_port_state_vector));
	if (!states)
		return NULL;
    states->ports = calloc(size, sizeof(t_port_state));
	if (!states->ports) {
		free(states);
		return NULL;
	}

	for (int i = 0; i < (int)size; i++) {
		states->ports[i].port = ports[i];
		states->ports[i].state = NOTHING;
	}
    states->len = size;

    listener(dev, scan, states);
	// TODO remove the above except return line
	t_scan *scans = calloc(1, sizeof(t_scan));
	scans->results = states;
	scans->type = scan;
	print_results(scans, 1);


	return states;
}