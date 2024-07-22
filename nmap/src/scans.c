#include "ft_nmap.h"

// TODO refactor code (lots of boiler plate code)

int syn_scan(ip_addr_t src_ip, ip_addr_t dest_ip,
            int src_port, int dest_port,
            char *data, int data_len) {
	/*
	Performs a SYN TCP Scan, from ONE source ip and port to ONE destination ip
	and port.

	Args:
		ip_addr_t src_ip: source ip
		ip_addr_t dest_ip: destination ip
		int src_port: source port
		int dest_port: destination port
		char *data: data to be sent alongside the packet
		int data_len: length (in bytes) of the data to be sent

	Returns:
		-1 on error
		0 if the port is closed
		1 if the port is open
		2 the port is filtered

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
	pid_t pid;

	printf("SYN SCAN\n");

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
	
	// Fork to setup sender and listener
	pid = fork();
	if (pid < 0) {
		perror("fork");
		free(packet);
		return -1;
	}
	// Handle Child Process: listener, wait for TCP Response
	if (pid == 0) {
		if (wait_for_tcp_response(&response, &response_iph, &response_tcph) == -1) {
			free(response);
			exit(EXIT_FAILURE); // TODO Free packet?
		}
		free(response);
		printf("Packet received\n");
		exit(EXIT_SUCCESS);
	} else {
		if (send_packet(iph, packet) == -1) {
			kill(pid, SIGKILL);
			wait(NULL);
			free(packet);
			return -1;
		}
		printf("Sent packet\n");
		wait(NULL);
	}
	free(packet);
	return 0;
}

int null_scan(ip_addr_t src_ip, ip_addr_t dest_ip,
            int src_port, int dest_port,
            char *data, int data_len) {
	/*
	Performs a NULL TCP Scan, from ONE source ip and port to ONE destination ip
	and port.

	Args:
		ip_addr_t src_ip: source ip
		ip_addr_t dest_ip: destination ip
		int src_port: source port
		int dest_port: destination port
		char *data: data to be sent alongside the packet
		int data_len: length (in bytes) of the data to be sent

	Returns:
		-1 on error
		0 if the port is closed
		3 if the port is open|filtered

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
	ipheader_t iph;
	tcpheader_t tcph;
	char *packet;
	char *response;
	ipheader_t response_iph;
	tcpheader_t response_tcph;
	pid_t pid;

	printf("NULL SCAN\n");

	// Setup the IP Header
	iph = setup_iph(src_ip.network, dest_ip.network, data_len);

	// Setup the TCP Header
	tcph = setup_tcph(src_port, dest_port); // TODO add flags and all

	// Set the appropriate flag for the SYN scan
	tcph.flags = NULL_SCAN;

	packet = create_tcp_packet(&iph, &tcph, data, data_len);
	if (!packet)
		return -1;
	printf("Created packet\n");
	
	// Fork to setup sender and listener
	pid = fork();
	if (pid < 0) {
		perror("fork");
		free(packet);
		return -1;
	}
	// Handle Child Process: listener, wait for TCP Response
	if (pid == 0) {
		if (wait_for_tcp_response(&response, &response_iph, &response_tcph) == -1) {
			free(response);
			exit(EXIT_FAILURE); // TODO Free packet?
		}
		free(response);
		printf("Packet received\n");
		exit(EXIT_SUCCESS);
	} else {
		if (send_packet(iph, packet) == -1) {
			kill(pid, SIGKILL);
			wait(NULL);
			free(packet);
			return -1;
		}
		printf("Sent packet\n");
		wait(NULL);
	}
	free(packet);
	return 0;
}

int ack_scan(ip_addr_t src_ip, ip_addr_t dest_ip,
            int src_port, int dest_port,
            char *data, int data_len) {
	/*
	Performs a ACK TCP Scan, from ONE source ip and port to ONE destination ip
	and port.

	Args:
		ip_addr_t src_ip: source ip
		ip_addr_t dest_ip: destination ip
		int src_port: source port
		int dest_port: destination port
		char *data: data to be sent alongside the packet
		int data_len: length (in bytes) of the data to be sent

	Returns:
		-1 on error
		2 if the port is filtered
		4 if the port is closed|open

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

	printf("ACK SCAN\n");


	return 1;
}

int fin_scan(ip_addr_t src_ip, ip_addr_t dest_ip,
            int src_port, int dest_port,
            char *data, int data_len) {
	/*
	Performs a FIN TCP Scan, from ONE source ip and port to ONE destination ip
	and port.

	Args:
		ip_addr_t src_ip: source ip
		ip_addr_t dest_ip: destination ip
		int src_port: source port
		int dest_port: destination port
		char *data: data to be sent alongside the packet
		int data_len: length (in bytes) of the data to be sent

	Returns:
		-1 on error
		0 if the port is closed
		3 if the port is open|filtered

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

	printf("FIN SCAN\n");

	return 1;
}

int xmas_scan(ip_addr_t src_ip, ip_addr_t dest_ip,
            int src_port, int dest_port,
            char *data, int data_len) {
	/*
	Performs a XMAS TCP Scan, from ONE source ip and port to ONE destination ip
	and port.

	Args:
		ip_addr_t src_ip: source ip
		ip_addr_t dest_ip: destination ip
		int src_port: source port
		int dest_port: destination port
		char *data: data to be sent alongside the packet
		int data_len: length (in bytes) of the data to be sent

	Returns:
		-1 on error
		0 if the port is closed
		3 if the port is open|filtered

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

	printf("XMAS SCAN\n");

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
