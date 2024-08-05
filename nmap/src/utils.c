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