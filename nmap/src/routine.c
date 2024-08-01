#include "ft_nmap.h"

static void	sdisplay_port_range(uint16_t *array, uint32_t size, str s, uint32_t *a);

void *routine(void * arg) {
	tdata_in in = *(tdata_in *)arg;
	str s;
	uint32_t a = 0;

	in.output->data = calloc(1000, 1);

	s = in.output->data;

	printf("My port: %d\n", in.port);
	printf("My scan: %d\n", in.scans);

	for (int i = 0; in.hnp[i].ports; i++) {
		a += sprintf((s + a), "Host: %s\n", in.hnp[i].host.basename);
		a += sprintf((s + a), "Range: ");
		sdisplay_port_range(in.hnp[i].ports, in.hnp[i].ports_len, s, &a);
		a += sprintf((s + a), "\n\n");
	}

	return NULL;
}

static void	sdisplay_port_range(uint16_t *array, uint32_t size, str s, uint32_t *a) {
	bool	in_range = false;

	if (size == 1) {
		*a += sprintf((s + *a), "%hu\n", array[0]);
	}
	else {
		for (uint32_t i = 0; i != (size - 1); i++) {
			if (!in_range)
				*a += sprintf((s + *a), "%hu", array[i]);
			if (array[i] + 1 == array[i + 1] && !in_range) {
				in_range = true;
				*a += sprintf((s + *a), "-");
			}
			if (array[i] + 1 != array[i + 1] && in_range) {
				in_range = false;
				*a += sprintf((s + *a), "%hu,", array[i]);
			}
		}
		*a += sprintf((s + *a), "%hu", array[size - 1]);
	}

}