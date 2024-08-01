#include "ft_nmap.h"

void	*routine(void *thread_arg) {
	tdata_in	data = *((tdata_in *)thread_arg);

	printf("Thread id: %d\n", data.id);
	puts("Exiting thread");

	return NULL;
}