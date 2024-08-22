#include "ft_nmap.h"

static unsigned short checksum(void *b, int len) {
    unsigned short *buff = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buff++;
    if (len == 1)
        sum += *(unsigned char *)buff;
    sum = (sum >> 16) + (sum &0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

char *create_udp_packet(ipheader_t *iph, udpheader_t *udph, char *data, int data_len) {
    char *packet;
    int packet_size = sizeof(ipheader_t) + sizeof(udpheader_t) + data_len;

    packet = calloc(packet_size, sizeof(char));
    if (!packet) {
        perror("calloc");
        return NULL;
    }

    // Copy IP Header
    memcpy(packet, iph, sizeof(ipheader_t));

    // Copy UDP Header
    memcpy(packet + sizeof(ipheader_t), udph, sizeof(udpheader_t));

    // Copy data
    if (data_len > 0) {
        memcpy(packet + sizeof(ipheader_t) + sizeof(udpheader_t), data, data_len);
    }

    // Calculate IP Checksum
    iph->chksum = checksum(iph, sizeof(ipheader_t));
    memcpy(packet + offsetof(ipheader_t, chksum), &iph->chksum, sizeof(iph->chksum));

    // Compute UDP checksum
    struct pseudo_header psh;
    psh.src_ip = iph->src_ip;
    psh.dest_ip = iph->dest_ip;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.length = udph->len; // Length is already in network byte order

    int psize = sizeof(struct pseudo_header) + ntohs(udph->len);
    char *pseudogram = calloc(1, psize);
    if (!pseudogram) {
        perror("calloc");
        free(packet);
        return NULL;
    }

    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(udpheader_t));
    if (data_len > 0)
        memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(udpheader_t), data, data_len);
    udph->chksum = checksum(pseudogram, psize);
    free(pseudogram);

    // Update packet with calculated checksums
    memcpy(packet + sizeof(ipheader_t) + offsetof(udpheader_t, chksum), &udph->chksum, sizeof(udph->chksum));

    return packet;
}

char *create_tcp_packet(ipheader_t *iph, tcpheader_t *tcph, char *data, int data_len) {
    char *packet;
    int packet_size = sizeof(ipheader_t) + sizeof(tcpheader_t) + data_len;

    packet = calloc(packet_size, sizeof(char)); 
    if (!packet) {
        perror("calloc");
        return NULL;
    }

    // // Set Source IP Address
    // if (inet_pton(AF_INET, "172.18.0.2", &iph->src_ip) != 1) {
    //     perror("inet_pton - src_ip");
    //     free(packet);
    //     return NULL;
    // }

    // // Set Destination IP Address (Google's IP)
    // if (inet_pton(AF_INET, "142.250.190.14", &iph->dest_ip) != 1) {
    //     perror("inet_pton - dest_ip");
    //     free(packet);
    //     return NULL;
    // }

    // Copy IP Header
    memcpy(packet, iph, sizeof(ipheader_t));

    // Copy TCP Header
    memcpy(packet + sizeof(ipheader_t), tcph, sizeof(tcpheader_t));

    // Copy data
    if (data_len > 0)
        memcpy(packet + sizeof(ipheader_t) + sizeof(tcpheader_t), data, data_len);

    // Calculate IP Checksum
    iph->chksum = checksum(iph, sizeof(ipheader_t));
    memcpy(packet + offsetof(ipheader_t, chksum), &iph->chksum, sizeof(iph->chksum));

    // Compute TCP checksum
    struct pseudo_header psh;
    psh.src_ip = iph->src_ip;
    psh.dest_ip = iph->dest_ip;
    psh.placeholder = 0; 
    psh.protocol = IPPROTO_TCP;
    psh.length = htons(sizeof(tcpheader_t) + data_len); 
    
    int psize = sizeof(struct pseudo_header) + sizeof(tcpheader_t) + data_len; 
    char *pseudogram = calloc(1, psize);
    if (!pseudogram) {
        perror("calloc");
        free(packet);
        return NULL;
    }
    
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(tcpheader_t));
    if (data_len)
        memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(tcpheader_t), data, data_len);
    tcph->chksum = checksum(pseudogram, psize);
    free(pseudogram);
    memcpy(packet + sizeof(ipheader_t) + offsetof(tcpheader_t, chksum), &tcph->chksum, sizeof(tcph->chksum));

    return packet;
}

int send_packet(ipheader_t iph, char *packet, int dest_port) {
	int sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0) {
		free(packet);
		perror("socket");
		return -1;
	}

	// Bind the socket to the eth0 interface
	const char *interface = "eth0";
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)) < 0) {
		perror("setsockopt SO_BINDTODEVICE");
		close(sockfd);
		return -1;
	}

	int opt = 1;
	if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
		perror("setsockopt IP_HDRINCL");
		close(sockfd);
		return -1;
	}

	struct sockaddr_in dest;
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = iph.dest_ip;
	dest.sin_port = htons(dest_port);

	if (sendto(sockfd, packet, ntohs(iph.len), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
		perror("sendto");
		close(sockfd);
		free(packet);
		return -1;
	}

	close(sockfd);
	return 0;
}

