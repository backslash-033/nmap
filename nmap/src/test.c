#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include "ft_nmap.h"

// Pseudo header needed for TCP checksum calculation
struct pseudo_header {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
};

// Function to calculate checksum
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Function to create raw TCP and IP packets
void create_raw_tcp_ip_packet(ipheader_t *ip, tcpheader_t *tcp, char *data, int data_len) {
    char packet[4096];
    memset(packet, 0, 4096);

    // Copy IP header
    memcpy(packet, ip, sizeof(ipheader_t));

    // Copy TCP header
    memcpy(packet + sizeof(ipheader_t), tcp, sizeof(tcpheader_t));

    // Copy data
    memcpy(packet + sizeof(ipheader_t) + sizeof(tcpheader_t), data, data_len);

    // Calculate IP checksum
    ip->chksum = 0;
    ip->chksum = checksum(packet, sizeof(ipheader_t));

    // Calculate TCP checksum
    tcp->chksum = 0;
    struct pseudo_header psh;
    psh.source_address = ip->sourceip;
    psh.dest_address = ip->destip;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(tcpheader_t) + data_len);

    int psize = sizeof(struct pseudo_header) + sizeof(tcpheader_t) + data_len;
    char *pseudogram = malloc(psize);

    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcp, sizeof(tcpheader_t) + data_len);

    tcp->chksum = checksum(pseudogram, psize);
    free(pseudogram);

    // Send the packet
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ip->destip;

    if (sendto(sockfd, packet, ntohs(ip->len), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto");
    }

    close(sockfd);
}

int main() {
    ipheader_t ip;
    tcpheader_t tcp;
    char data[] = "Hello, world!";

    // Fill in IP Header
    ip.ihl = 5;
    ip.ver = 4;
    ip.tos = 0;
    ip.len = htons(sizeof(ipheader_t) + sizeof(tcpheader_t) + sizeof(data));
    ip.ident = htons(54321);
    ip.flag = 0;
    ip.offset = 0;
    ip.ttl = 255;
    ip.protocol = IPPROTO_TCP;
    ip.chksum = 0;
    ip.sourceip = inet_addr("127.0.0.1"); // Source IP address (localhost)
    ip.destip = inet_addr("127.0.0.1"); // Destination IP address (localhost)

    // Fill in TCP Header
    tcp.srcport = htons(12345);
    tcp.destport = htons(81);
    tcp.seqnum = 0;
    tcp.acknum = 0;
    tcp.reserved = 0;
    tcp.offset = 5; // TCP header size
    tcp.flags = SYN; // SYN flag
    tcp.win = htons(5840);
    tcp.chksum = 0;
    tcp.urgptr = 0;

    // Create and send the raw TCP/IP packet
    create_raw_tcp_ip_packet(&ip, &tcp, data, sizeof(data));

    return 0;
}
