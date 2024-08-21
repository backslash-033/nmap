#include "ft_nmap.h"

t_scan	main_thread(const uint16_t *ports, const uint32_t size, enum e_scans scan) {
	t_port_state_vector *states;
	t_scan result;

	// TODO Make me dynamic
	char dev[] = "wlp0s20f3";

	// TODO use create_port_state_vector
	states = calloc(1, sizeof(t_port_state_vector));
	if (!states)
		return result;
    states->ports = calloc(size, sizeof(t_port_state));
	if (!states->ports) {
		free(states);
		return result;
	}

	for (int i = 0; i < (int)size; i++) {
		states->ports[i].port = ports[i];
		states->ports[i].state = NOTHING;
	}
    states->len = size;

    listener(dev, scan, states);

	result.results = states;
	result.type = scan;

	return result;
}