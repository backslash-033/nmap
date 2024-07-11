#include "ft_nmap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

// IP header structure
typedef struct ipheader_s {
    unsigned char       ihl:4, ver:4;
    unsigned char       tos;
    unsigned short int  len;
    unsigned short int  ident;
    unsigned short int  flag:3, offset:13;
    unsigned char       ttl;
    unsigned char       protocol;
    unsigned short int  chksum;
    unsigned int        sourceip;
    unsigned int        destip;
}                       ipheader_t;

// TCP header structure
typedef struct tcpheader_s {
    unsigned short int  srcport;
    unsigned short int  destport;
    unsigned int        seqnum;
    unsigned int        acknum;
    unsigned char       reserved:4, offset:4;
    unsigned char       flags;
    unsigned short int  win;
    unsigned short int  chksum;
    unsigned short int  urgptr;
}                       tcpheader_t;

#define PORTS_SCANNED 90
#define IP_ADDRESS "127.0.0.1"
#define BUFFER_SIZE 4096


// TODO use getprotobyname() for different protocols

void sigint_handler() {
    exit(1);
}


int main() {
    int sockfd;
    // int results[PORTS_SCANNED];
    char buff[BUFFER_SIZE];

    sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, sigint_handler);

    // TODO create a structure to retrieve the network information about the incoming packet
    ssize_t recvfrom_bytes = recvfrom(sockfd, buff, BUFFER_SIZE, 0, NULL, NULL);
    if (recvfrom_bytes > 0) {
        ipheader_t *iph = (ipheader_t *)buff;
        tcpheader_t *tcph = (tcpheader_t *)(buff + 4 * iph->ihl);
        (void)tcph;
        // &buff = &buff + sizeof(tcpheader_t);
        printf("%s\n%ld\n", buff, recvfrom_bytes);
    }
}
