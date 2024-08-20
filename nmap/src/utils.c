#include "ft_nmap.h"

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

void free_port_state_vector(t_port_state_vector **vector) {
	free((*vector)->ports);
	free(*vector);
	vector = NULL;
}