#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pcap.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>

#include "libft.h"

typedef char *	str;

typedef	struct host_data {
	str				basename;
	struct addrinfo	info;
} host_data;

typedef struct options {
	host_data		*host;
	uint32_t		host_len;
	uint8_t			scans;
	uint8_t			threads;
	uint16_t		*port;
	uint32_t		port_len;
} options;

typedef struct tdata_out {
	str	data;
} tdata_out;

typedef struct host_and_ports {
	host_data	host;
	uint16_t	*ports;
	uint32_t	ports_len;
} host_and_ports;

typedef struct tdata_in {
	host_and_ports	*hnp;
	uint8_t			scans;
	uint8_t			id;
	uint16_t		port;
	tdata_out		*output;
} tdata_in;

#define WARNING	"\033[33mWarning:\033[0m "
#define ERROR	"\033[31mError:\033[0m "

#define NEVER_ZERO(x) (x ? x : 1)

// Options
#define IS_SCAN_NOTHING(x)	(x == 0)
#define IS_SCAN_SYN(x)		((x & 0b00000001) == 0b00000001)
#define IS_SCAN_NULL(x)		((x & 0b00000010) == 0b00000010)
#define IS_SCAN_ACK(x)		((x & 0b00000100) == 0b00000100)
#define IS_SCAN_FIN(x)		((x & 0b00001000) == 0b00001000)
#define IS_SCAN_XMAS(x)		((x & 0b00010000) == 0b00010000)
#define IS_SCAN_UDP(x)		((x & 0b00100000) == 0b00100000)
#define IS_SCAN_ALL(x)		((x & 0b10111111) == 0b10111111)

#define LOWEST_PORT			1025
#define HIGHEST_PORT		UINT16_MAX
#define PORT_RANGE			(HIGHEST_PORT - LOWEST_PORT)

#define SCAN_AMOUNT			6

enum e_tcp_flags
{
	FIN = 1,
	SYN = FIN << 1,
	RST = SYN << 1,
	PSH = RST << 1,
    ACK = PSH << 1,
    URG = ACK << 1,
    ECE = URG << 1,
    CWR = ECE << 1,
    NS = CWR << 1
};

enum e_scans {
    SYN_SCAN = SYN,
    NULL_SCAN = 0,
    ACK_SCAN = ACK,
    FIN_SCAN = FIN,
    XMAS_SCAN = FIN + URG  + PSH,
    UDP_SCAN = -1
};

enum e_responses {
	POSITIVE = 1,       // TCP Response, UDP Response
	NEGATIVE = 1 << 1,  // TCP RST
	BAD      = 1 << 2,  // ICMP Unreachable
    NOTHING  = 0        // No response 
};

// IP header structure
typedef struct ipheader_s {
    uint8_t  ihl:4, ver:4;
    uint8_t  tos;
    uint16_t len;
    uint16_t ident;
    uint16_t flag:3, offset:13;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t chksum;
    uint32_t src_ip;
    uint32_t dest_ip;
} __attribute__((packed)) ipheader_t;


// TCP header structure
typedef struct tcpheader_s {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seqnum;
    uint32_t acknum;
    uint8_t  reserved:4, offset:4;
    uint8_t  flags;
    uint16_t win;
    uint16_t chksum;
    uint16_t urgptr;
} __attribute__((packed)) tcpheader_t;

// UDP header structure
typedef struct udpheader_s {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t len;
    uint16_t chksum;
} __attribute__((packed)) udpheader_t;

// ICMP header structure
typedef struct icmpheader_s {
    uint8_t     type; 
    uint8_t     code;
    uint16_t    checksum;
    uint16_t    id;   
    uint16_t    sequence;
} __attribute__((packed)) icmpheader_t;

// Pseudo-header for checksum calculation
struct pseudo_header {
    uint32_t src_ip;
    uint32_t dest_ip;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t length;
} __attribute__((packed));


typedef struct  s_vector {
    int *list;
    size_t len;
}               t_vector;

typedef struct s_uint16_vector {
	uint16_t	*list;
	size_t		len;
}				t_uint16_vector;

typedef struct ip_addr_s {
    char    printable[INET_ADDRSTRLEN];
    int     network;
}           ip_addr_t;

typedef struct  s_port_state {
    u_int16_t   port;  // the port number
    u_int8_t    state; // see e_port_states
}               t_port_state;

// TODOinit the port list with port state nothing
typedef struct      s_port_state_vector {
    t_port_state    *ports;
    size_t          len;
}                   t_port_state_vector;



// TODO maybe remove later
#define PORTS_SCANNED 90
#define IP_ADDRESS "127.0.0.1"
#define TEST_ADDRESS "127.127.127.127"
#define BUFFER_SIZE 4096
#define DEBUG true
#define NMAP_PORT "3490"

ip_addr_t	**parse_ips(char **ips);

// main.c
void		display_port_range(uint16_t *array, uint32_t size);
void		free_tdata_out_array(tdata_out *array, const uint8_t size);
void		free_tdata_out(tdata_out d);

// options.c
options 	options_handling(int argc, char **argv, struct addrinfo ***addrinfo_to_free);
void		free_options(options *opts);

// threads.c
tdata_out	**threads(options *opt, struct timeval *before, struct timeval *after);

// main_thread.c
void		main_thread(const uint16_t *ports, const uint32_t size);

// routine.c
void		*routine(void *);

// scanner.c
void    scanner(ip_addr_t **ip_list,
				t_uint16_vector port_vector,
                ip_addr_t src_ip, int src_port,
                int scan, char *data, int data_len);

// sender.c
char 		*create_tcp_packet(ipheader_t *iph, tcpheader_t *tcph, char *data, int data_len);
char 		*create_udp_packet(ipheader_t *iph, udpheader_t *udph, char *data, int data_len);
int			send_packet(ipheader_t iph, char *packet, int dest_port);
int			wait_for_tcp_response(char **response, ipheader_t *response_iph, tcpheader_t *response_tcph);

// setup.c
ipheader_t	setup_iph(int src_ip, int dest_ip, int data_len, int protocol);
tcpheader_t	setup_tcph(int src_port, int dest_port);
udpheader_t setup_udph(int src_port, int dest_port, int data_len);

// scans.c
int tcp_scan(ip_addr_t src_ip, ip_addr_t dest_ip,
            int src_port, int dest_port,
			int scan,
            char *data, int data_len);
int udp_scan(ip_addr_t src_ip, ip_addr_t dest_ip,
            int src_port, int dest_port,
			int scan __attribute__((unused)),
            char *data, int data_len);


// filter.c
char *create_filter(int scan, t_port_state_vector dest_ports);

// parsing.c
ip_addr_t	**parse_ips(char **ips);
void free_linked_list(t_list **list);

// visualizers.c // TODO remove me
void icmp_visualizer(icmpheader_t *icmph);
void udp_visualizer(udpheader_t *udph);
void tcp_visualizer(tcpheader_t *tcph);
void ip_visualizer(ipheader_t *iph);

// packet_handler.c
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

// listener.c
int listener(char *interface, int scan, t_port_state_vector states);

#endif