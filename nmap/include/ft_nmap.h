/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tgernez <tgernez@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/06/10 08:55:53 by nguiard           #+#    #+#             */
/*   Updated: 2024/07/14 14:55:46 by tgernez          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

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

#include "libft.h"

typedef char *	str;

typedef	struct host_data {
	str				basename;
	struct addrinfo	info;
} host_data;

typedef struct options {
	host_data		*host;
	uint32_t		host_amout;
	uint8_t			scans;
	uint8_t			threads;
	uint16_t		*port;
	uint32_t		port_amount;
} options;

#define WARNING	"\033[33mWarning:\033[0m "
#define ERROR	"\033[31mError:\033[0m "

// Options

#define IS_SCAN_NOTHING(x)	(x == 0)
#define IS_SCAN_SYN(x)		((x & 0b00000001) == 0b00000001)
#define IS_SCAN_NULL(x)		((x & 0b00000010) == 0b00000010)
#define IS_SCAN_ACK(x)		((x & 0b00000100) == 0b00000100)
#define IS_SCAN_FIN(x)		((x & 0b00001000) == 0b00001000)
#define IS_SCAN_XMAS(x)		((x & 0b00010000) == 0b00010000)
#define IS_SCAN_UDP(x)		((x & 0b00100000) == 0b00100000)
#define IS_SCAN_ALL(x)		((x & 0b10111111) == 0b10111111)

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
    NS = ECE << 1
};

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
    unsigned int        src_ip;
    unsigned int        dest_ip;
}                       ipheader_t;

// TCP header structure
typedef struct tcpheader_s {
    unsigned short int  src_port;
    unsigned short int  dest_port;
    unsigned int        seqnum;
    unsigned int        acknum;
    unsigned char       reserved:4, offset:4;
    unsigned char       flags;
    unsigned short int  win;
    unsigned short int  chksum;
    unsigned short int  urgptr;
}                       tcpheader_t;

// TODO maybe remove later
#define PORTS_SCANNED 90
#define IP_ADDRESS "127.0.0.1"
#define BUFFER_SIZE 4096
#define DEBUG true
#define NMAP_PORT "3490"

options options_handling(int argc, char **argv);
void	free_options(options *opts);
void	getaddrinfolocal();
void    print_tcp_header(tcpheader_t tcph);
void    print_ip_header(ipheader_t iph);
char    *create_raw_packet(char *src_ip, char *dest_ip, int src_port, int dest_port, unsigned char scan, char *data, int data_len);

#endif