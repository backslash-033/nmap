#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include "ft_nmap.h"
 
// struct pcap_if {
// 	struct pcap_if *next;
// 	char *name;		// name to hand to "pcap_open_live()"
// 	char *description;	// textual description of interface, or NULL 
// 	struct pcap_addr *addresses;
// 	bpf_u_int32 flags;	// PCAP_IF_ interface flags 
// };

/*
Explanations:
- if the scan is TCP based, listen on TCP and ICMP with the list of src and dest ports
	Example: listening for TCP packets: 
		- source port 33
		- destination ports 1055 and 9535
	"tcp port 33 or port 1055 or port 9535"
- if the scan is UDP based, isten on UDP and ICMP with the list of src and dest ports
	ICMP don't use ports like UDP or TCP do. ICMP messages are identified with their type and code
	When an ICMP unreachable is sent, it contains the IP header along with the 8 first bytes of
	the UDP (if the triggering request was UDP), effecitvely giving out the original src and dest ports
	Example: listening for UDP packets:
		- source port 33
		- destination ports 1055 and 9535
	"udp port 33 or port 1055 or port 9535 or icmp"
*/

// TODO ICMP header
// TODO ICMP handler

void udp_packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)user;
    (void)header;
    printf("Entering UDP Packet handler\n");
    ipheader_t *iph = (ipheader_t *)(packet + 14); // Skip Ethernet header
    if (iph->protocol == IPPROTO_UDP) {
        udpheader_t *udph = (udpheader_t *)(packet + 14 + iph->ihl * 4); // Skip IP header
 
        // Copy packed members to aligned local variables
        struct in_addr src_ip, dest_ip;
        memcpy(&src_ip, &iph->src_ip, sizeof(src_ip));
        memcpy(&dest_ip, &iph->dest_ip, sizeof(dest_ip));
 
        printf("Captured UDP packet from %s:%d to %s:%d\n",
               inet_ntoa(src_ip), ntohs(udph->src_port),
               inet_ntoa(dest_ip), ntohs(udph->dest_port));
    }
}

void    set_port_state(uint8_t port_state, uint16_t port, t_port_state_vector *states) {
    for (size_t i = 0; i < states->len; i++) {
        if (states->ports[i].port == port) {
            states->ports[i].port = port_state;
            break;
        }
    }
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)user;
    (void)header;
    ipheader_t *iph = (ipheader_t *)(packet + 14); // Skip Ethernet header
    void *proto_packet = (void *)iph + iph->ihl * 4; // Skip IP heade
    t_port_state_vector *states = (t_port_state_vector *)user;
    int src_port = 0;
    udpheader_t *udph;
    tcpheader_t *tcph;
    icmpheader_t *icmph;

    if (iph->protocol == IPPROTO_TCP) {
        tcph = (tcpheader_t *)proto_packet;

        src_port = ntohs(tcph->src_port);
        if (tcph->flags & RST) {
            set_port_state(NEGATIVE, src_port, states);
        } else if ((tcph->flags & SYN) && (tcph->flags & ACK)) {
            set_port_state(POSITIVE, src_port, states);
        }
    }
    if (iph->protocol == IPPROTO_UDP) {
        udph = (udpheader_t *)proto_packet;

        src_port = ntohs(udph->src_port);
        set_port_state(POSITIVE, src_port, states);

        printf("udp/%-5d open\n", ntohs(udph->src_port));
    }
    if (iph->protocol == IPPROTO_ICMP) {
        printf("Detected an ICMP packet");
        icmph = (icmpheader_t *)proto_packet;

    }
}

int listener(char *interface, int scan, t_port_state_vector states) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *device;
    pcap_t *handle;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    (void) states;

    char *filter;
    struct bpf_program  compiled_filter;

    // TODO free me at the end and on error
    filter = create_filter(scan, states);
    if (!filter) {
        perror("malloc");
        return 1;
    }
    printf("%s\n", filter);

    // Find all devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }
 
    // Use the first device
    device = alldevs;
    for (; device != NULL; device = device->next) {
        printf("Device name: %s\n", device->name);
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
        // TODO free all devices?
        fprintf(stderr, "Couldn't open device %s: %s\n", device->name, errbuf);
        return 2;
    }
 
    // Compile and set the filter
    if (pcap_compile(handle, &compiled_filter, filter, 0, net) == -1) {
        // TODO free all devices?
        // TODO close handle?
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &compiled_filter) == -1) {
        // TODO free all devices?
        // TODO close handle?
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
        return 2;
    }
    // Start capturing packets
    pcap_loop(handle, -1, packet_handler, (u_char *)&states);
    pcap_freealldevs(alldevs);
    pcap_close(handle);
    return 0;
}


int main(int ac, char **av) {
    // TODO remove me, only for debug
    t_port_state_vector states;

    int scan;

    if (ac != 3) {
        fprintf(stderr, "Usage: %s <interface> <protocol name>\n", av[0]);
        return 1;
    }
    if (!strcmp("tcp", av[2])) {
        scan = SYN_SCAN;
    } else if (!strcmp("udp", av[2])) {
        scan = UDP_SCAN;
    } else {
        fprintf(stderr, "Please enter a valid scan name: tcp, udp\n");
        return 1;
    }

    states.ports = malloc(6 * sizeof(int));
    states.ports[0].port = 80;
    states.ports[1].port = 4350;
    states.ports[2].port = 4435;
    states.ports[3].port = 1252;
    states.ports[4].port = 65535;
    states.ports[5].port = 443;

    states.len = 6;
    (void)scan;
    (void)states;
    listener(av[1], scan, states);
    return 0;
}
