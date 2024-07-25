#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

// UDP header structure
typedef struct udpheader_s {
    uint16_t src_port;  // Source port
    uint16_t dest_port; // Destination port
    uint16_t len;       // Datagram length
    uint16_t chksum;    // Checksum
} __attribute__((packed)) udpheader_t;



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

// Function to create and send a UDP packet
void send_udp_packet(uint32_t src_ip, uint32_t dest_ip, uint16_t src_port, uint16_t dest_port, const char *data, int data_len) {
    int sockfd;
    struct sockaddr_in dest_addr;
    char *packet;
    udpheader_t *udp;
    struct pseudo_header psh;
    int packet_len = sizeof(udpheader_t) + data_len;

    // Create raw socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Allocate memory for packet
    packet = malloc(packet_len);
    if (!packet) {
        perror("malloc");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Set UDP header fields
    udp = (udpheader_t *)packet;
    udp->src_port = htons(src_port);
    udp->dest_port = htons(dest_port);
    udp->len = htons(packet_len);
    udp->chksum = 0;

    // Copy data to packet
    memcpy(packet + sizeof(udpheader_t), data, data_len);

    // Set up pseudo-header
    psh.src_ip = src_ip;
    psh.dest_ip = dest_ip;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(packet_len);

    // Calculate checksum
    int psize = sizeof(struct pseudo_header) + packet_len;
    char *pseudogram = malloc(psize);
    if (!pseudogram) {
        perror("malloc");
        free(packet);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udp, packet_len);
    udp->chksum = checksum(pseudogram, psize);
    free(pseudogram);

    // Set destination address
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = dest_ip;

    // Send packet
    if (sendto(sockfd, packet, packet_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
    } else {
        printf("UDP packet sent\n");
    }

    free(packet);
    close(sockfd);
}

int main() {
    uint32_t src_ip = inet_addr("192.168.1.1"); // Example source IP
    uint32_t dest_ip = inet_addr("192.168.1.2"); // Example destination IP
    uint16_t src_port = 12345; // Example source port
    uint16_t dest_port = 80; // Example destination port
    const char *data = "Hello, World!";
    int data_len = strlen(data);

    send_udp_packet(src_ip, dest_ip, src_port, dest_port, data, data_len);

    return 0;
}
