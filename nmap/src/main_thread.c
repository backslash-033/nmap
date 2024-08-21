#include "ft_nmap.h"

t_scan	main_thread(const uint16_t *ports, const uint32_t size, enum e_scans scan, const bool if_lo) {
	t_port_state_vector *states;
	t_scan result;

	// TODO Make me dynamic

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

    listener(scan, states, if_lo);

	result.results = states;
	result.type = scan;

	return result;
}