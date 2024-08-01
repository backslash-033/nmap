#include "ft_nmap.h"


static void ip_to_string(unsigned int ip, char *buffer, size_t buffer_size) {
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;
    inet_ntop(AF_INET, &ip_addr, buffer, buffer_size);
}

void print_ip_header(ipheader_t iph) {
    char ip_addr[INET_ADDRSTRLEN];

    printf("=============================IP  HEADER=============================\n");
    printf("IP Version: %d\n", iph.ver);
    printf("IP Header Length: %d\n", iph.ihl);
    printf("IP Type Of Service: %c\n", iph.tos);
    printf("IP Total Length: %d\n", iph.len);
    printf("IP Identification: %d\n", iph.ident);
    printf("IP Offset: %d\n", iph.offset);
    printf("IP Flag: %d\n", iph.flag);
    printf("IP Time To Live: %d\n", iph.ttl);
    printf("IP Protocol: %d\n", iph.protocol);
    printf("IP Checksum: %d\n", iph.chksum);
    ip_to_string(iph.src_ip, ip_addr, INET_ADDRSTRLEN);
    printf("IP Source IP: %s\n", ip_addr);
    ip_to_string(iph.dest_ip, ip_addr, INET_ADDRSTRLEN);
    printf("IP Destination IP: %s\n", ip_addr);
}

static void print_tcp_flags(unsigned char flags) {
    int ind = 1;
    const char *flag_names[9] = {
        "FIN",
        "SYN",
        "RST",
        "PSH",
        "ACK",
        "URG",
        "ECE",
        "CWR",
        "NS"
    };
    
    printf("TCP Flags:\n");
    for (int i = 0; i < 9; i++) {
        if (ind & flags)
            printf("- Flag %s\n", flag_names[i]);
        ind <<= 1;
    }
}


void print_tcp_header(tcpheader_t tcph) {
    printf("=============================TCP HEADER=============================\n");
    printf("TCP Source Port: %u\n", tcph.src_port);
    printf("TCP Destination Port: %u\n", tcph.dest_port);
    printf("TCP Sequence Number: %u\n", tcph.seqnum);
    printf("TCP Acknowledgment Number: %u\n", tcph.acknum);
    printf("TCP Data Offset: %u\n", tcph.offset);
    printf("TCP Reserved: %d\n", tcph.reserved);
    print_tcp_flags(tcph.flags);
    printf("TCP Window Size: %u\n", tcph.win); // TODO why the same output?
    printf("TCP Checksum: %u\n", tcph.chksum); // TODO why the same output?
    printf("TCP Urgent Pointer: %u\n", tcph.urgptr); // TODO why the same output?
}

int main() {
    int sockfd;
    ssize_t recvfrom_bytes;
    // int results[PORTS_SCANNED];
    // char *data = malloc(BUFFER_SIZE);
    // if (!data)
    //     return 1;
    // memset(data, 0, BUFFER_SIZE);
    // memcpy(data, "Hello, World!", 14);
    char *buff = malloc(BUFFER_SIZE);
    if (!buff)
        return 1;

    sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }
    // getaddrinfolocal();

    // // TODO create a structure to retrieve the network information about the incoming packet
    if (DEBUG) {
        for (;;) {
            recvfrom_bytes = recvfrom(sockfd, buff, BUFFER_SIZE, 0, NULL, NULL);
            if (recvfrom_bytes > 0) {
                ipheader_t *iph = (ipheader_t *)buff;
                // Print the data in iph
                print_ip_header(*iph);

                tcpheader_t *tcph = (tcpheader_t *)(buff + 4 * iph->ihl);
                // Print the data in tcph
                print_tcp_header(*tcph);

                // TODO maybe check if UDP?
                (void)tcph;
                buff = buff + sizeof(ipheader_t) + sizeof(tcpheader_t);
                printf("%s\n%ld\n", buff, recvfrom_bytes);
            }
        }
    }


}