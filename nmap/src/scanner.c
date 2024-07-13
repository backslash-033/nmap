#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdbool.h>


#include "ft_nmap.h"

// TODO use getprotobyname() for different protocols

void sigint_handler() {
    exit(1);
}

int main() {
    int sockfd;
    // int results[PORTS_SCANNED];
    char *buff = malloc(BUFFER_SIZE);
    if (!buff)
        return 1;


    sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, sigint_handler);

    
    getaddrinfolocal();

    // TODO create a structure to retrieve the network information about the incoming packet
    if (DEBUG) {
        for (;;) {
            ssize_t recvfrom_bytes = recvfrom(sockfd, buff, BUFFER_SIZE, 0, NULL, NULL);
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
