#include "ft_nmap.h"

void *main_thread(void *arg) {
	listener((t_listener_in *)arg);
	return NULL;
}