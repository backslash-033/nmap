#include "ft_nmap.h"

// TODO function char_to_flags, give the uchar from the tcpheader_t and
// returns a struct tcp_flags_s with the different flags as booleans,
// set the correct ones to true -> actually, could even do hex to flags

void free_formatted_ips(ip_addr_t **formatted_ips) {
	ip_addr_t **base = formatted_ips;

	while (formatted_ips) {
		free(*formatted_ips);
		*formatted_ips = NULL;
		formatted_ips++;
	}
	formatted_ips = base;
	free(formatted_ips);
	formatted_ips = NULL;
}

void free_linked_list(t_list **list) {
    t_list *current;
    t_list *next_node;

    if (list == NULL || *list == NULL) {
        return;
    }
    current = *list;
    while (current != NULL) {
        next_node = current->next;
        free(current->content);
        free(current);
        current = next_node;
    }
    *list = NULL;
}

uint32_t random_uint32(uint32_t min, uint32_t max) {
	if (min > max)
		return 0;

	const uint32_t diff = max - min;
	
	srand(time(NULL));
	return (rand() % diff) + min;
}

uint16_t random_uint16(uint16_t min, uint16_t max) {
	if (min > max)
		return 0;

	const uint16_t diff = max - min;
	
	srand(time(NULL));
	return (rand() % diff) + min;
}

t_port_state_vector *create_port_state_vector(int *ports, size_t len) {
	t_port_state_vector *vector;
	size_t				i;

	vector = malloc(sizeof(t_port_state_vector));
	if (!vector)
		return NULL;
	
	vector->ports = malloc(len * sizeof(t_port_state));
	if (!vector->ports) {
		free(vector);
		return NULL;
	}
	
	for (i = 0; i < len; i++) {
		vector->ports[i].port = ports[i];
		vector->ports[i].state = NOTHING;
	}
	vector->len = len;
	return vector;
}