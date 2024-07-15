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