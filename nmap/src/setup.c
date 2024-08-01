#include "ft_nmap.h"

ipheader_t setup_iph(int src_ip, int dest_ip, int data_len, int protocol) {
    /*
    Setup basic parameters for the IP Header. Does NOT calculate the checksum.

    Args:
        int src_ip: source IP, result of inet_pton()
        int dest_ip: destination IP, result of inet_pton()
		int data_len: the length (in bytes) of the data to be transmitted
		int protocol: the protocol used to transmit the packet (IPPROTO_TCP or IPPROTO_UDP)
    */
    ipheader_t iph;

    iph.ihl = 5;
    iph.ver = 4;
    iph.tos = 0;
    if (protocol == IPPROTO_TCP) {
        iph.len = htons(sizeof(ipheader_t) + sizeof(tcpheader_t) + data_len);
    } else if (protocol == IPPROTO_UDP) {
        iph.len = htons(sizeof(ipheader_t) + sizeof(udpheader_t) + data_len);
    }
	iph.ident = htons(54321); // TODO make me random
    iph.flag = 0; // TODO study me
    iph.offset = 0; // TODO study me
    iph.ttl = 255; // TODO experiment with variable ttl for --traceroute param
    iph.protocol = protocol;
    iph.chksum = 0;
    iph.src_ip = src_ip;
    iph.dest_ip = dest_ip;
    return iph;
}

tcpheader_t setup_tcph(int src_port, int dest_port) {
    /*
    Setup basic parameters for the TCP Header. Does NOT calculate the checksum,
    nor sets sequence number, acknowledgment number, offset, flags, variable
    window size and urgent pointer.

    Args:
        int src_port: source port
        int dest_port: destination port

    */
    tcpheader_t tcph;

    tcph.src_port = htons(src_port);
    tcph.dest_port = htons(dest_port);
    tcph.seqnum = htonl(random_uint32(0, UINT32_MAX)); // TODO Make me random automatically
    tcph.acknum = htonl(random_uint32(0, UINT32_MAX)); // TODO Make me random automatically
    tcph.reserved = 0;
    tcph.offset = 5; // Normally, is fixed
    tcph.flags = 0; 
    tcph.win = htons(33280); // TODO maybe make me adjustable
    tcph.chksum = 0;
    tcph.urgptr = 0; // TODO set me with desired scan
    printf("Setting up TCP header: src_port=%d, dest_port=%d\n", src_port, dest_port);

	return tcph;
}

udpheader_t setup_udph(int src_port, int dest_port, int data_len) {
    udpheader_t udph;

    udph.src_port = htons(src_port);
    udph.dest_port = htons(dest_port);
    udph.len = htons(sizeof(udpheader_t) + data_len);
    udph.chksum = 0; // Calculated later
    printf("Setting up UDP header: src_port=%d, dest_port=%d\n", src_port, dest_port);

    return udph;
}