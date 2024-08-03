#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
// #include "ft_nmap.h"
 
// struct pcap_if {
// 	struct pcap_if *next;
// 	char *name;		// name to hand to "pcap_open_live()"
// 	char *description;	// textual description of interface, or NULL 
// 	struct pcap_addr *addresses;
// 	bpf_u_int32 flags;	// PCAP_IF_ interface flags 
// };
 
 
 
 
// IP header structure
typedef struct ipheader_s {
    uint8_t     ihl:4, ver:4;
    uint8_t     tos;
    uint16_t    len;
    uint16_t    ident;
    uint16_t    flag:3, offset:13;
    uint8_t     ttl;
    uint8_t     protocol;
    uint16_t    chksum;
    uint32_t    src_ip;
    uint32_t    dest_ip;
} __attribute__((packed)) ipheader_t;
 
// TCP header structure
typedef struct tcpheader_s {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seqnum;
    uint32_t acknum;
    uint8_t  reserved:4, offset:4;
    uint8_t  flags;
    uint16_t win;
    uint16_t chksum;
    uint16_t urgptr;
} __attribute__((packed)) tcpheader_t;

// UDP header structure
typedef struct udpheader_s {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t len;
    uint16_t chksum;
} __attribute__((packed)) udpheader_t;


// TODO ICMP header
// TODO ICMP handler
 

void udp_packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
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

void tcp_packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("Entering TCP Packet handler\n");
    ipheader_t *iph = (ipheader_t *)(packet + 14); // Skip Ethernet header
    if (iph->protocol == IPPROTO_TCP) {
        tcpheader_t *tcph = (tcpheader_t *)(packet + 14 + iph->ihl * 4); // Skip IP header
 
        // Copy packed members to aligned local variables
        struct in_addr src_ip, dest_ip;
        memcpy(&src_ip, &iph->src_ip, sizeof(src_ip));
        memcpy(&dest_ip, &iph->dest_ip, sizeof(dest_ip));
 
        printf("Captured TCP packet from %s:%d to %s:%d\n",
               inet_ntoa(src_ip), ntohs(tcph->src_port),
               inet_ntoa(dest_ip), ntohs(tcph->dest_port));
    }
}

int main(int ac, char **av) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *device;
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net;
    bpf_u_int32 mask;
 
    if (ac != 3) {
        fprintf(stderr, "Usage: %s <interface> <protocol name>\n", av[0]);
        return 1;
    }

    // Find all devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }
 
    // Use the first device
    device = alldevs;
    for (; device != NULL; device = device->next) {
        printf("Device name: %s\n", device->name);
        if (!strcmp(device->name, av[1]))
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
        return 2;
    }
 
    // Compile and set the filter
    if (pcap_compile(handle, &fp, av[2], 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", av[2], pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", av[2], pcap_geterr(handle));
        return 2;
    }
    // Start capturing packets
    if (!strcmp(av[2], "tcp"))
        pcap_loop(handle, -1, tcp_packet_handler, NULL);
    else if (!strcmp(av[2], "udp"))
        pcap_loop(handle, -1, udp_packet_handler, NULL);
    else
        fprintf(stderr, "Unrecognized filter\n");
    pcap_freealldevs(alldevs);
    pcap_close(handle);
    return 0;
}
