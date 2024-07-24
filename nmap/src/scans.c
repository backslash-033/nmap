#include "ft_nmap.h"

int tcp_scan(ip_addr_t src_ip, ip_addr_t dest_ip,
            int src_port, int dest_port,
			int scan,
            char *data, int data_len) {
	ipheader_t iph;
	tcpheader_t tcph;
	char *packet;


	// Setup the IP Header
	iph = setup_iph(src_ip.network, dest_ip.network, data_len);

	// Setup the TCP Header
	tcph = setup_tcph(src_port, dest_port);
	// Set the appropriate flag for the SYN scan
	tcph.flags = scan;

	packet = create_tcp_packet(&iph, &tcph, data, data_len);
	if (!packet)
		return -1;
	printf("Created packet\n");
	if (send_packet(iph, packet) == -1) {
		free(packet);
		return -1;
	}
	printf("Sent packet\n");
	free(packet);	
	return 0;
}

int udp_scan(ip_addr_t src_ip, ip_addr_t dest_ip,
            int src_port, int dest_port,
			int port __attribute__((unused)),
            char *data, int data_len) {
	(void) src_ip;
	(void) dest_ip;
	(void) src_port;
	(void) dest_port;
	(void) data;
	(void) data_len;
	return -1;
}
