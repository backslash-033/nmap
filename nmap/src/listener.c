#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include "ft_nmap.h"

static pcap_t *g_handle = NULL;

static void handle_alarm(int sig) {
    (void) sig;
    if (g_handle)
        pcap_breakloop(g_handle);
}

// TODO change scan and states to a t_scan
int listener(char *interface, int scan, t_port_state_vector states) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *device;
    pcap_t *handle;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    const uint32_t timeout = 1;
    (void) states;

    char *filter;
    struct bpf_program  compiled_filter;

    // Find all devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }
 
    // Use the first device
    device = alldevs;
    for (; device != NULL; device = device->next) {
        if (!strcmp(device->name, interface))
            break;
    }

    if (device == NULL) {
        fprintf(stderr, "No devices found.\n");
        return 1;
    }

    // Get network number and mask
    if (pcap_lookupnet(device->name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device->name, errbuf);
        net = 0;
        mask = 0;
    }
 
    // Open the device for packet capture
    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device->name, errbuf);
        pcap_freealldevs(alldevs);
        return 2;
    }

    g_handle = handle;

    filter = create_filter(scan, states);
    if (!filter) {
        perror("malloc");
        return 1;
    }
    printf("%s\n", filter);

    // Compile and set the filter
    if (pcap_compile(handle, &compiled_filter, filter, 0, net) == -1) {
        pcap_freealldevs(alldevs);
        pcap_close(handle);
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        free(filter);
        return 2;
    }
    if (pcap_setfilter(handle, &compiled_filter) == -1) {
        pcap_freealldevs(alldevs);
        pcap_close(handle);
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
        free(filter);
		return 2;
    }
    free(filter);

    signal(SIGALRM, handle_alarm);
    alarm(timeout);

    // Start capturing packets
    // TODO states.len might be ambitious, back to -1 if necessary
    pcap_loop(handle, states.len, packet_handler, (u_char *)&states);
    pcap_freealldevs(alldevs);
    pcap_close(handle);
    return 0;
}


// int main(int ac, char **av) {
//     t_port_state_vector states;

//     int scan;

//     if (ac != 3) {
//         fprintf(stderr, "Usage: %s <interface> <protocol name>\n", av[0]);
//         return 1;
//     }
//     if (!strcmp("tcp", av[2])) {
//         scan = SYN_SCAN;
//     } else if (!strcmp("udp", av[2])) {
//         scan = UDP_SCAN;
//     } else {
//         fprintf(stderr, "Please enter a valid scan name: tcp, udp\n");
//         return 1;
//     }

//     states.ports = malloc(6 * sizeof(int));
//     states.ports[0].port = 80;
//     states.ports[1].port = 4350;
//     states.ports[2].port = 4435;
//     states.ports[3].port = 1252;
//     states.ports[4].port = 65535;
//     states.ports[5].port = 443;

//     states.ports[0].state = NOTHING;
//     states.ports[1].state = NOTHING;
//     states.ports[2].state = NOTHING;
//     states.ports[3].state = NOTHING;
//     states.ports[4].state = NOTHING;
//     states.ports[5].state = NOTHING;

//     states.len = 6;
//     (void)scan;
//     (void)states;
//     listener(av[1], scan, states);
//     return 0;
// }
