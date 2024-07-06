#include "ft_nmap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORTS_SCANNED 1024

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
    serv_addr.sin_port = htons(80);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) { 
        perror("Invalid / unsupported address");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof serv_addr) < 0) {
        perror("Connection failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Connected!\n");

    char *http_request = ft_strdup("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: closedr\r\n\r\n");
    if (send(sockfd, http_request, ft_strlen(http_request), 0) < 0) {
        free(http_request);
        close(sockfd);
        perror("Error sending data");
        exit(EXIT_FAILURE);
    }
    free(http_request);

    char buffer[4096];
    ssize_t bytes_received;
    while ((bytes_received = recv(sockfd, buffer, sizeof buffer - 1, 0)) > 0) {
        buffer[bytes_received] = 0;
        printf("%s", buffer);
    }

    if (bytes_received < 0) {
        close(sockfd);
        perror("Error receiving data");
        exit(EXIT_FAILURE);
    }

    close(sockfd);
}
