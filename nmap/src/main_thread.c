#include "ft_nmap.h"

void *main_thread(void *arg) {
	int *ret = calloc(1, sizeof(int));
	
	if (!ret) {
		return NULL;
	}

	t_listener_in *data = (t_listener_in *)arg;
	// TODO Make me dynamic
	char dev[] = "lo";
	
    *ret = listener(data);
	if (*ret != 0) {
		// TODO free scan in calling function OR here if simpler
	}
	return ret;

}