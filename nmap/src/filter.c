#include "ft_nmap.h"

char *create_filter(int scan, t_port_state_vector dest_ports) {
    /*
        Note: the spaces in the strings are intentional, DO NOT REMOVE THEM
    */
    char *filter;
    char *scan_name;
    char buff[12]; // for "port 65535 " + null terminator
    size_t len_filter = strlen("or icmp");


    if (scan == UDP_SCAN) {
        scan_name = strdup("udp src ");
        len_filter += strlen("udp src ") * dest_ports.len;
    }
    else {
        scan_name = strdup("tcp src ");
        len_filter += strlen("tcp src ") * dest_ports.len;
    }
    if (!scan_name) {
        perror("malloc");
        return NULL;
    }
    len_filter += strlen("or ") * (dest_ports.len - 1); // no "or " after final port, if icmp, extra "or " is already counted
    
    t_list *port_list = NULL;
    for (size_t i = 0; i < dest_ports.len; i++) {
        len_filter += snprintf(buff, sizeof(buff), "port %d ", dest_ports.ports[i].port);
        t_list *next_node = ft_lstnew(strdup(buff));
        if (!next_node) {
            free(scan_name);
            free_linked_list(&port_list);
            return NULL;
        }
        ft_lstadd_back(&port_list, next_node);
    }
    filter = malloc(len_filter + 1);
    if (!filter) {
        free(scan_name);
        free_linked_list(&port_list);
        return NULL;
    }
    filter[0] = 0;

    t_list *current = port_list;
    while (current) {
        strcat(filter, scan_name);
        strcat(filter, (char *)current->content);
        current = current->next;
        if (current)
            strcat(filter, "or ");
    }
    strcat(filter, "or icmp");
    free(scan_name);
    free_linked_list(&port_list);
    return filter;
}