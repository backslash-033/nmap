#include "ft_nmap.h"

// TODO remove the file, for debug

void icmp_visualizer(icmpheader_t *icmph) {
    // Convert multi-byte fields to host byte order
    uint16_t checksum = ntohs(icmph->checksum);
    uint16_t id = ntohs(icmph->id);
    uint16_t sequence = ntohs(icmph->sequence);

    // Print the ICMP header fields
    printf("ICMP Packet:\n");
    printf("  Type: %d\n", icmph->type);
    printf("  Code: %d\n", icmph->code);
    printf("  Checksum: 0x%04x\n", checksum);
    printf("  ID: %d\n", id);
    printf("  Sequence: %d\n", sequence);

    // Depending on the ICMP type, you might want to print additional information
    if (icmph->type == 3) {
        printf("  Destination Unreachable\n");
    } else if (icmph->type == 8) {
        printf("  Echo Request\n");
    } else if (icmph->type == 0) {
        printf("  Echo Reply\n");
    } else {
        printf("  Other ICMP Type\n");
    }
}

void udp_visualizer(udpheader_t *udph) {
    printf("UDP Header:\n");
    printf("  Source Port: %d\n", ntohs(udph->src_port));
    printf("  Destination Port: %d\n", ntohs(udph->dest_port));
    printf("  Length: %d\n", ntohs(udph->len));
    printf("  Checksum: 0x%04x\n", ntohs(udph->chksum));
}

void tcp_visualizer(tcpheader_t *tcph) {
    printf("TCP Header:\n");
    printf("  Source Port: %d\n", ntohs(tcph->src_port));
    printf("  Destination Port: %d\n", ntohs(tcph->dest_port));
    printf("  Sequence Number: %u\n", ntohl(tcph->seqnum));
    printf("  Acknowledgment Number: %u\n", ntohl(tcph->acknum));
    printf("  Data Offset: %d (words)\n", tcph->offset);
    printf("  Flags: 0x%02x\n", tcph->flags);
    printf("  Window: %d\n", ntohs(tcph->win));
    printf("  Checksum: 0x%04x\n", ntohs(tcph->chksum));
    printf("  Urgent Pointer: %d\n", ntohs(tcph->urgptr));
}

void ip_visualizer(ipheader_t *iph) {
    printf("IP Header:\n");
    printf("  Version: %d\n", iph->ver);
    printf("  Header Length: %d (words)\n", iph->ihl);
    printf("  Type of Service: %d\n", iph->tos);
    printf("  Total Length: %d\n", ntohs(iph->len));
    printf("  Identification: %d\n", ntohs(iph->ident));
    printf("  Flags: %d\n", iph->flag);
    printf("  Fragment Offset: %d\n", iph->offset);
    printf("  Time to Live: %d\n", iph->ttl);
    printf("  Protocol: %d\n", iph->protocol);
    printf("  Checksum: 0x%04x\n", ntohs(iph->chksum));
    printf("  Source IP: %s\n", inet_ntoa(*(struct in_addr *)&iph->src_ip));
    printf("  Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&iph->dest_ip));
}