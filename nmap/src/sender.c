#include "ft_nmap.h"

static ipheader_t setup_iph(int sourceip, int destip, char *data) {
    /*
    Setup basic parameters for the IP Header. Does NOT calculate the checksum.

    Args:
        sourceip: source IP, result of inet_pton()
        destip: destination IP, result of inet_pton()
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
    iph.sourceip = sourceip; // TODO code me
    iph.destip = destip; // TODO same
    return iph;
}

char *create_raw_packet(char *sourceip, char *destip, int sourceport, int destport, unsigned char scan, char *data) {
    struct sockaddr_in sa_source, sa_dest;
    ipheader_t iph, tcph;
    int ret;

    (void) tcph;

    // Get the source address into int format
    ret = inet_pton(AF_INET, sourceip, &(sa_source.sin_addr));
    if (ret == 0) {
        fprintf(stderr, "%s is not a valid source IP address\n", sourceip);
        return NULL;
    } else if (ret == -1) {
        perror("Error turning source IP to network format");
        return NULL;
    }
    ret = inet_pton(AF_INET, destip, &(sa_source.sin_addr));
    if (ret == 0) {
        fprintf(stderr, "%s is not a valid destination IP address\n", sourceip);
        return NULL;
    } else if (ret == -1) {
        perror("Error turning destination IP to network format");
        return NULL;
    }
    iph = setup_iph(sa_source.sin_addr.s_addr, sa_dest.sin_addr.s_addr, data);
    (void) iph;
    (void) sourceport;
    (void) destport;
    (void) scan;
    return NULL;
}























void getaddrinfolocal() {
    int status;
    int sockfd;
    struct addrinfo hints, *servinfo, *p;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((status = getaddrinfo(NULL, NMAP_PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        exit(1);
    }
    
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }

        if (send(sockfd, "salut\n", 6, 0) == -1) {
            close(sockfd);
            perror("client: send");
            continue;
        }
        break;
    }

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        // return NULL;
    }
}