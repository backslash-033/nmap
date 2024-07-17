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


// static int  udp_packet_handler(ip_addr_t src_ip, ip_addr_t dest_ip,
//                             int src_port, int dest_port,
//                             unsigned char scan,
//                             char *data, int data_len) {
// 	(void)src_ip;
// 	(void)dest_ip;
// 	(void)src_port;
// 	(void)dest_port;
// 	(void)scan;
// 	(void)data;
// 	(void)data_len;
// 	return 1;
// }

// static int  tcp_packet_handler(ip_addr_t src_ip, ip_addr_t dest_ip,
//                             int src_port, int dest_port,
//                             unsigned char scan,
//                             char *data, int data_len) {
//     /*
//     Creates, opens a connection and sends a TCP packet with the desired 
//     flags and data.
        
//     WARNING: Do NOT use this function for UDP scan or IPv6

//     Args:
//         char *src_ip: the source IP
//         char *dest_ip: the destination IP
//         int src_port: the source port
//         int dest_port: the destination port
//         unsigned char scan: the scan to perform (NO UDP)
//         char *data: the data to be transmitted alongside the IP and TCP headers
//         int data_len: the length (in bytes) of the data to be transmitted
//     */
//     // FIXME might not work yet
//     // char *packet = create_raw_packet(src_ip, dest_ip, src_port, dest_port, scan, data, data_len);
//     // if (!packet)
//     //     return -1;
// 	(void)src_ip;
// 	(void)dest_ip;
// 	(void)src_port;
// 	(void)dest_port;
// 	(void)scan;
// 	(void)data;
// 	(void)data_len;
// 	char *packet = NULL;
//     int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
//     if (sockfd < 0) {
//         perror("socket");
//         return -1;
//     }
//     // TODO fill dest with getaddrinfo()
//     struct sockaddr_in dest;
//     dest.sin_family = AF_INET;
//     // FIXME Operation done twice. Once in create_raw_socket, and here. Find a fix 
//     dest.sin_addr.s_addr = 0;

//     if (sendto(sockfd, packet, ntohs(0 /* TODO must be iph.len */), 0 /* TODO put necessary sendto() flags */, (struct sockaddr *)&dest, sizeof(dest)) < 0)
//         perror("sendto");
//     close(sockfd);
// 	return -1;
// }

void    scanner(ip_addr_t **ip_list,
				int *port_list, int len_port_list,
                ip_addr_t src_ip, int src_port,
                int scan, char *data, int data_len) {
    /*
    Core function of the Nmap scanner. Calls the necessary functions to perform
    the different scans proposed by the utilitary. The parameters MUST be
    already parsed, or set to default values (see args)

    Args:
        ip_addr_t **ip_list: the list of IPs to be scanned
			The array of ip_addr_t * MUST be NULL-terminated.
        int *port_list: the list of ports to be scanned.
        int len_port_list: the length of the list of ports to be scanned.
        ip_addr_t src_ip: the IP address to emit the packets from.
        int src_port: the port to emit the packets from.
        int scan: the scan to be performed on the hosts and ports.
        char *data: the data to transmit when sending a packet
            Doesn't need to be \0 terminated.
        int data_len: the length (in bytes) of the passed data
    
    Returns:
        Nothing    
    */
	int ret;
    (void)ip_list;
    (void)port_list;
	(void)len_port_list;
	(void)src_ip;
	(void)src_port;
    (void)scan;
	(void)data;
	(void)data_len;
    

	ip_addr_t *dest_ip = *ip_list;
	int dest_port;
	int (*scanner_func)(ip_addr_t, ip_addr_t, int, int, char *, int) = NULL;

	// Can be done in a single line
	switch (scan) {
		case SYN_SCAN:
			scanner_func = syn_scan;
			break;
		case NULL_SCAN:
			scanner_func = null_scan;
			break;
		case ACK_SCAN:
			scanner_func = ack_scan;
			break;
		case FIN_SCAN:
			scanner_func = fin_scan;
			break;
		case XMAS_SCAN:
			scanner_func = xmas_scan;
			break;
		case UDP_SCAN:
			scanner_func = udp_scan;
			break;
		default:
			fprintf(stderr, "Please choose valid scan option.\n");
			return ;
	}

	while (dest_ip) {
		for (int j = 0; j < len_port_list; j++) {
			dest_port = port_list[j];
			ret = scanner_func(src_ip, *dest_ip, src_port, dest_port, data, data_len);
			printf("IP: %s\nPort: %d\nRet: %d\n", dest_ip->printable, dest_port, ret);
		}
		dest_ip = *(++ip_list);
	}

    // =====Process IPs====
    // For IP in IPs:
    //   ====Process ports====
    //   For port in ports:
    //     ====If scan is UDP====
    //       TODO Handle
    //     packet = create_raw_packet(...)
    //     Open a socket on AF_INET, SOCK_RAW, IPPROTO_RAW
    //     sendto(TARGET)
    //     ====Follow up if necessary====
    //       packet = create_raw_packet(...)
    //       Open a socket on AF_INET, SOCK_RAW, IPPROTO_RAW
    //       sendto(TARGET)

}

// TODO use getprotobyname() for different protocols

void sigint_handler() {
    exit(1);
}

int main() {
    // int sockfd;
    // ssize_t recvfrom_bytes;
    // int results[PORTS_SCANNED];
    // char *data = malloc(BUFFER_SIZE);
    // if (!data)
    //     return 1;
    // memset(data, 0, BUFFER_SIZE);
    // memcpy(data, "Hello, World!", 14);
    // char *buff = malloc(BUFFER_SIZE);
    // if (!buff)
    //     return 1;

    // sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    // if (sockfd < 0) {
    //     perror("Error creating socket");
    //     exit(EXIT_FAILURE);
    // }

    signal(SIGINT, sigint_handler);
    char data[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    // create_raw_packet("127.0.0.1", "127.0.0.1", 12345, 80, 0, data, sizeof(data));
	int *port = malloc(sizeof(int) * 1);
	port[0] = 80;
	ip_addr_t **ips_to_scan = parse_ips(ft_split("127.0.0.1\n127.0.0.2\n", '\n'));

	if (!ips_to_scan) {
		fprintf(stderr, "Error parsing IPs\n");
		return 1;
	}
	ip_addr_t **copy_ips = ips_to_scan;
	ip_addr_t *addr = *ips_to_scan;
	while (addr) {
		printf("Printable is: %s\nInt is: %d\n", (*ips_to_scan)->printable, (*ips_to_scan)->network);
		addr = *(++ips_to_scan);
	}

	ips_to_scan = copy_ips;
	ip_addr_t src_ip;
	memset(&src_ip, 0, sizeof(src_ip));
	strncpy(src_ip.printable, IP_ADDRESS, INET_ADDRSTRLEN);
	src_ip.network = INADDR_LOOPBACK;

	scanner(ips_to_scan, port, 1, src_ip, 12345, SYN_SCAN, data, sizeof(data));

    // getaddrinfolocal();

    // printf("I am here\n");
    // // TODO create a structure to retrieve the network information about the incoming packet
    // if (DEBUG) {
    //     for (;;) {
    //         recvfrom_bytes = recvfrom(sockfd, buff, BUFFER_SIZE, 0, NULL, NULL);
    //         if (recvfrom_bytes > 0) {
    //             ipheader_t *iph = (ipheader_t *)buff;
    //             // Print the data in iph
    //             print_ip_header(*iph);

    //             tcpheader_t *tcph = (tcpheader_t *)(buff + 4 * iph->ihl);
    //             // Print the data in tcph
    //             print_tcp_header(*tcph);

    //             // TODO maybe check if UDP?
    //             (void)tcph;
    //             buff = buff + sizeof(ipheader_t) + sizeof(tcpheader_t);
    //             printf("%s\n%ld\n", buff, recvfrom_bytes);
    //         }
    //     }
    // }


}
