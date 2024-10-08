#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include "ft_nmap.h"

static inline void __set_port_state(uint8_t port_state, uint16_t port, t_port_state_vector *states) {
    for (size_t i = 0; i < states->len; i++) {
        if (states->ports[i].port == port) {
            states->ports[i].state = port_state;
            break;
        }
    }
}

static inline void __handle_tcp_packet(tcpheader_t *tcph, t_port_state_vector *states) {
	// tcp_visualizer(tcph);
	if (tcph->flags & RST) {
        __set_port_state(NEGATIVE, ntohs(tcph->src_port), states);
    } else if ((tcph->flags & SYN) && (tcph->flags & ACK)) {
        __set_port_state(POSITIVE, ntohs(tcph->src_port), states);
    }
	// printf("SOURCE PORT: %d\n", ntohs(tcph->src_port));
    // else if so the response can remain NOTHING on no response case
}

static inline void __handle_udp_packet(udpheader_t *udph, t_port_state_vector *states) {
    __set_port_state(POSITIVE, ntohs(udph->src_port), states);
}

static inline void __handle_icmp_packet(void *proto_packet, t_port_state_vector *states) {
    const icmpheader_t *icmph = (icmpheader_t *)proto_packet; 
    tcpheader_t *tcph;
    udpheader_t *udph;
    ipheader_t  *original_iph;

    if (icmph->type == 3 && icmph->code == 3) {
        // Skip the ICMP Packet
        proto_packet = (void *)icmph + sizeof(icmpheader_t);
        // Retrive the original IP header (IP header from our packet)
        original_iph = (ipheader_t *)proto_packet;
        // Skip the IP header to get the Transport Layer protocol header
        proto_packet += original_iph->ihl * 4;
        if (original_iph->protocol == IPPROTO_UDP) {
            udph = (udpheader_t *)proto_packet;
            __set_port_state(NEGATIVE, ntohs(udph->dest_port), states);
        } else if (original_iph->protocol == IPPROTO_TCP) {
            tcph = (tcpheader_t *)proto_packet;
            __set_port_state(NEGATIVE, ntohs(tcph->dest_port), states);
        } else {
            fprintf(stderr, "Unknown protocol\n");
        }
    }
}

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)header;
	// static int test = 0;
	// printf("Test is: %d\n", test++);
    const ipheader_t *iph = (ipheader_t *)(packet + 14); // Skip Ethernet header
    void *proto_packet = (void *)iph + iph->ihl * 4; // Skip IP header
    t_port_state_vector *states = (t_port_state_vector *)user;

    if (iph->protocol == IPPROTO_TCP)
        __handle_tcp_packet((tcpheader_t *)proto_packet, states);
    else if (iph->protocol == IPPROTO_UDP)
        __handle_udp_packet((udpheader_t *)proto_packet, states);
    else if (iph->protocol == IPPROTO_ICMP)
        __handle_icmp_packet((icmpheader_t *)proto_packet, states);
}
