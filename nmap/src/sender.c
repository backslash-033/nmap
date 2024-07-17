#include "ft_nmap.h"

struct pseudo_header {
    unsigned int src_ip;
    unsigned int dest_ip;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
};

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

char *create_tcp_packet(ipheader_t *iph, tcpheader_t *tcph, char *data, int data_len) {
	char *packet;

	packet = calloc(4096, sizeof(char)); // TODO adapt me
	if (!packet) {
		perror("calloc");
		return NULL;
	}
	// Copy IP Header
    memcpy(packet, iph, sizeof(ipheader_t));

    // Copy TCP Header
    memcpy(packet + sizeof(ipheader_t), tcph, sizeof(tcpheader_t));

    // Copy data
    memcpy(packet + sizeof(ipheader_t) + sizeof(tcpheader_t), data, data_len);

    iph->chksum = checksum(packet, sizeof(ipheader_t));

    // Compute TCP checksum
    struct pseudo_header psh;
    psh.src_ip = iph->src_ip;
    psh.dest_ip = iph->dest_ip;
    psh.placeholder = 0; // TODO wtf
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(tcpheader_t) + data_len); 
    
    int psize = sizeof(struct pseudo_header) + sizeof(tcpheader_t) + data_len; 
    char *pseudogram = malloc(psize);
    if (!pseudogram) {
        fprintf(stderr, "Malloc failed in creating pseudogram\n");
        return NULL;
    }
    
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), &tcph, sizeof(tcpheader_t) + data_len);

    tcph->chksum = checksum(pseudogram, psize);
    free(pseudogram);

	return packet;
}

ipheader_t setup_iph(int src_ip, int dest_ip, char *data) {
    /*
    Setup basic parameters for the IP Header. Does NOT calculate the checksum.

    Args:
        int src_ip: source IP, result of inet_pton()
        int dest_ip: destination IP, result of inet_pton()
        char *data: the data to be sent in the TCP packet
    */
    ipheader_t iph;

    iph.ihl = 5;
    iph.ver = 4;
    iph.tos = 0;
    iph.len = htons(sizeof(ipheader_t) + sizeof(tcpheader_t) + sizeof(data));
    iph.ident = htons(54321); // TODO make me random
    iph.flag = 0; // TODO study me
    iph.offset = 0; // TODO study me
    iph.ttl = 255; // TODO experiment with variable ttl for --traceroute param
    iph.protocol = IPPROTO_TCP; // TODO make me variable (UDP scan)
    iph.chksum = 0; // Computed later
    iph.src_ip = src_ip; // TODO code me
    iph.dest_ip = dest_ip; // TODO same
    return iph;
}

tcpheader_t setup_tcph(int src_port, int dest_port, char *data) {
    /*
    Setup basic parameters for the TCP Header. Does NOT calculate the checksum,
    nor sets sequence number, acknowledgment number, offset, flags, variable
    window size and urgent pointer.

    Args:
        int src_port: source port
        int dest_port: destination port
        char *data: the data to be sent to the remote host
    */
   (void)data;
    tcpheader_t tcph;

    tcph.src_port = htons(src_port);
    tcph.dest_port = htons(dest_port);
    tcph.seqnum = 0; // TODO make me random
    tcph.acknum = 0; // TODO make me random or not
    tcph.reserved = 0;
    tcph.offset = 5; // TODO compute dynamically
    tcph.flags = SYN + ACK; // TODO set me with desired scan
    tcph.win = htons(1024); // TODO maybe make me adjustable
    tcph.chksum = 0; // TODO compute me dynamically later
    tcph.urgptr = 0; // TODO set me with desired scan
    return tcph;
}

int send_packet(ipheader_t iph, char *packet) {
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0) {
		perror("socket");
		return -1;
	}

	struct sockaddr_in dest;
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = iph.dest_ip;

	if (sendto(sockfd, packet, ntohs(iph.len), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
		perror("sendto");
		return -1;
	}
	close(sockfd);
	return 0;
}
