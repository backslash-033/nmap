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
#include <sys/ioctl.h>
#include <ifaddrs.h>

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
	bool			fast;
	uint8_t			ttl;
	uint16_t		win;
	str				data;
	int				source;
	uint16_t		timeout;
} options;

typedef struct host_and_ports {
	host_data	host;
	uint16_t	*ports;
	uint32_t	ports_len;
} host_and_ports;

typedef struct tdata_in {
	host_and_ports	hnp;
	uint8_t			scans;
	uint8_t			id;
	uint16_t		port;
	const options	*opts;
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

// listener

#define	COND_LOCKED		0
#define COND_UNLOCKED	1
#define LISTENER_ERR_DEVICE	-1
#define LISTENER_ERR_ALLOC	-2
#define LISTENER_ERR_PCAP	-3

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

enum e_scans_print_len {
	SYN_LEN = 9,
	NULL_LEN = 14,
	ACK_LEN = 11,
	FIN_LEN = 14,
	XMAS_LEN = 14,
	UDP_LEN = 14
};

enum e_responses {
	POSITIVE = 1,       // TCP Response, UDP Response
	NEGATIVE = 1 << 1,  // TCP RST or ICMP Unreachable
    NOTHING  = 1 << 2   // No response 
};

enum e_port_states {
	P_OPEN = 1,
	P_CLOSED = 1 << 1,
	P_FILTERED = 1 << 2,
	P_UNFILTERED = 1 << 3
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
    u_int8_t    state; // see e_reponse
}               t_port_state;

typedef struct      s_port_state_vector {
    t_port_state    *ports;
    size_t          len;
}                   t_port_state_vector;

typedef struct          s_scan {
    int                 type;
    t_port_state_vector *results;
	bool				error;
}                       t_scan;

typedef struct s_thread_cond {
	pthread_mutex_t	mutex;
	pthread_cond_t	cond;
	bool			ready;
}					t_thread_cond;

typedef struct	s_listener_in {
	t_scan			scan;
	t_thread_cond	listener_cond;
	bool			is_lo;
	size_t			nb_ports;
	host_data		dest_ip;
	uint16_t		timeout;
	uint8_t			nb_threads;
}					t_listener_in;

ip_addr_t	**parse_ips(char **ips);

// main.c
void		display_port_range(uint16_t *array, uint32_t size);

// options.c
options 	options_handling(int argc, char **argv, struct addrinfo ***addrinfo_to_free);
void		free_options(options *opts);

// threads.c
bool		threads(options *opt);
uint8_t		amount_of_scans(const uint8_t opt_scan);

// routine.c
void		*routine(void *);

// scanner.c
int			scanner(ip_addr_t **ip_list,
				t_uint16_vector port_vector,
                ip_addr_t src_ip, int src_port,
                int scan, char *data, size_t data_len,
				const options *opts);

// sender.c
char 		*create_tcp_packet(ipheader_t *iph, tcpheader_t *tcph, char *data, size_t data_len);
char 		*create_udp_packet(ipheader_t *iph, udpheader_t *udph, char *data, size_t data_len);
int			send_packet(ipheader_t iph, char *packet, int dest_port);

// setup.c
ipheader_t	setup_iph(int src_ip, int dest_ip, size_t data_len, int protocol, const options *opts);
tcpheader_t	setup_tcph(int src_port, int dest_port, const options *opts);
udpheader_t setup_udph(int src_port, int dest_port, size_t data_len);

// scans.c
int			tcp_scan(ip_addr_t src_ip, ip_addr_t dest_ip,
				int src_port, int dest_port,
				int scan,
				char *data, size_t data_len, const options *opts);
int			udp_scan(ip_addr_t src_ip, ip_addr_t dest_ip,
				int src_port, int dest_port,
				int scan __attribute__((unused)),
				char *data, size_t data_len, const options *opts);

// show_results.c
int			print_results(t_scan *scans, size_t len_scans);

// filter.c
char		*create_filter(int scan, host_data dest_ip);

// utils.c
t_port_state_vector *create_port_state_vector(const uint16_t *ports, size_t len);
void				free_port_state_vector(t_port_state_vector **vector);

// parsing.c
ip_addr_t	**parse_ips(char **ips);

// interpreters.c
void	interpret_syn_scan(uint16_t state, char *results);
void	interpret_null_scan(uint16_t state, char *results);
void	interpret_ack_scan(uint16_t state, char *results);
void	interpret_fin_scan(uint16_t state, char *results);
void	interpret_xmas_scan(uint16_t state, char *results);
void	interpret_udp_scan(uint16_t state, char *results);


// packet_handler.c
void	packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

// listener.c
void	*listener(void *data);

#endif