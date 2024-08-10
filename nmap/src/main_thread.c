#include "ft_nmap.h"

void	main_thread() {
	t_port_state_vector states;
    int scan;

    scan = SYN_SCAN;
	char dev[] = "wlp0s20f3";

    states.ports = malloc(6 * sizeof(int));
    states.ports[0].port = 80;
    states.ports[1].port = 4350;
    states.ports[2].port = 4435;
    states.ports[3].port = 1252;
    states.ports[4].port = 65535;
    states.ports[5].port = 443;

    states.ports[0].state = NOTHING;
    states.ports[1].state = NOTHING;
    states.ports[2].state = NOTHING;
    states.ports[3].state = NOTHING;
    states.ports[4].state = NOTHING;
    states.ports[5].state = NOTHING;

    states.len = 6;
    (void)scan;
    (void)states;
    listener(dev, scan, states);
}