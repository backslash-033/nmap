#include "ft_nmap.h"

int syn_scan(ip_addr_t src_ip, ip_addr_t dest_ip,
            int src_port, int dest_port,
            char *data, int data_len) {
	
	/*
		SYN SCAN (or half-open / stealth scan)
		1. Nmap sends a SYN Packet
		2. Target responds with:
			- SYN/ACK: the port is OPEN
			- RST: the port is CLOSED
			- Nothing: the port is FILTERED
		3. If received SYN/ACK, Nmap sends a RST packet to close the connection 
	*/
	// unsigned char flags = SYN_SCAN;
	(void) src_ip;
	(void) dest_ip;
	(void) src_port;
	(void) dest_port;
	(void) data;
	(void) data_len;
	ipheader_t iph;
	tcpheader_t tcph;
	char *packet;
	char *response;
	ipheader_t response_iph;
	tcpheader_t response_tcph;

	// Setup the IP Header
	iph = setup_iph(src_ip.network, dest_ip.network, data_len);

	// Setup the TCP Header
	tcph = setup_tcph(src_port, dest_port); // TODO add flags and all

	// Set the appropriate flag for the SYN scan
	tcph.flags = SYN_SCAN;

	packet = create_tcp_packet(&iph, &tcph, data, data_len);
	if (!packet)
		return -1;
	printf("Created packet\n");
	if (send_packet(iph, packet) == -1)
		return -1;
	printf("Sent packet\n");
	if (wait_for_tcp_response(&response, &response_iph, &response_tcph) == -1)
		return -1;
	printf("Received packet\n");
	return 0;
}

int null_scan(ip_addr_t src_ip, ip_addr_t dest_ip,
            int src_port, int dest_port,
            char *data, int data_len) {
	
	/*
		NULL SCAN
		1. Nmap sends a NULL Packet (no flags)
		2. Target responds with:
			- RST: the port is CLOSED
			- Nothing: the port is OPEN or FILTERED
	*/
	// unsigned char flags = NULL_SCAN;
	(void) src_ip;
	(void) dest_ip;
	(void) src_port;
	(void) dest_port;
	(void) data;
	(void) data_len;
	return 1;
}

int ack_scan(ip_addr_t src_ip, ip_addr_t dest_ip,
            int src_port, int dest_port,
            char *data, int data_len) {
	
	/*
		ACK SCAN (used to check filtering status)
		1. Nmap sends a ACK Packet
		2. Target responds with:
			- RST: the port is CLOSED or OPEN
			- Nothing: the port is FILTERED
	*/
	// unsigned char flags = ACK_SCAN;
	(void) src_ip;
	(void) dest_ip;
	(void) src_port;
	(void) dest_port;
	(void) data;
	(void) data_len;
	return 1;
}

int fin_scan(ip_addr_t src_ip, ip_addr_t dest_ip,
            int src_port, int dest_port,
            char *data, int data_len) {
	
	/*
		FIN SCAN
		1. Nmap sends a FIN Packet
		2. Target responds with:
			- RST: the port is CLOSED
			- Nothing: the port is OPEN or FILTERED
	*/
	// unsigned char flags = FIN_SCAN;
	(void) src_ip;
	(void) dest_ip;
	(void) src_port;
	(void) dest_port;
	(void) data;
	(void) data_len;
	return 1;
}

int xmas_scan(ip_addr_t src_ip, ip_addr_t dest_ip,
            int src_port, int dest_port,
            char *data, int data_len) {
	
	/*
		XMAS SCAN
		1. Nmap sends a FIN, PSH, URG Packet
		2. Target responds with:
			- RST: the port is CLOSED
			- Nothing: the port is OPEN or FILTERED
	*/
	// unsigned char flags = XMAS_SCAN;
	(void) src_ip;
	(void) dest_ip;
	(void) src_port;
	(void) dest_port;
	(void) data;
	(void) data_len;
	return 1;
}

int udp_scan(ip_addr_t src_ip, ip_addr_t dest_ip,
            int src_port, int dest_port,
            char *data, int data_len) {
	
	/*
		UDP SCAN
		1. Nmap sends a UDP Packet
		2. Target responds with:
			- ICMP Port Unreachable message: the port is CLOSED
			- Nothing: the port is OPEN or FILTERED
			- UDP Response: the port is OPEN and a service responds
	*/
	// unsigned char flags = UDP_SCAN;
	(void) src_ip;
	(void) dest_ip;
	(void) src_port;
	(void) dest_port;
	(void) data;
	(void) data_len;
	return 1;
}
