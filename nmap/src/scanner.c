#include "ft_nmap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORTS_SCANNED 90
#define IP_ADDRESS "127.0.0.1"

int main() {
    int sockfd;
    int results[PORTS_SCANNED];

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof serv_addr);
    serv_addr.sin_family = AF_INET;

    if (inet_pton(AF_INET, IP_ADDRESS, &serv_addr.sin_addr) <= 0) { 
        perror("Invalid / unsupported address");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < PORTS_SCANNED; i++) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("Error creating socket");
            exit(EXIT_FAILURE);
        }

        serv_addr.sin_port = htons(i);
        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof serv_addr) < 0) {
            printf("Port %d is close\n", i);
            results[i] = 0;
        } else {
            printf("Port %d is open\n", i);
            results[i] = 1;
        }
        close(sockfd);
    }
    (void) results;
}
