#include "ft_nmap.h"

int tcp_scan(ip_addr_t src_ip, ip_addr_t dest_ip,
            int src_port, int dest_port,
			int scan,
            char *data, size_t data_len, const options *opts) {
	ipheader_t iph;
	tcpheader_t tcph;
	char *packet;

	// Setup the IP Header
	iph = setup_iph(src_ip.network, dest_ip.network, data_len, IPPROTO_TCP, opts);

	// Setup the TCP Header
	tcph = setup_tcph(src_port, dest_port, opts);
	// Set the appropriate flag for the SYN scan
	tcph.flags = scan;

	packet = create_tcp_packet(&iph, &tcph, data, data_len);
	if (!packet)
		return -1;
	if (send_packet(iph, packet, dest_port) == -1) {
		free(packet);
		return -1;
	}
	free(packet);	
	return 0;
}

int udp_scan(ip_addr_t src_ip, ip_addr_t dest_ip,
            int src_port, int dest_port,
			int scan __attribute__((unused)),
            char *data, size_t data_len, const options *opts) {
	ipheader_t iph;
	udpheader_t udph;
	char *packet;

	// Setup the IP Header
	iph = setup_iph(src_ip.network, dest_ip.network, data_len, IPPROTO_UDP, opts);

	// Setup the UDP Header
	udph = setup_udph(src_port, dest_port, data_len);
	packet = create_udp_packet(&iph, &udph, data, data_len);
	if (!packet)
		return -1;
	if (send_packet(iph, packet, dest_port) == -1) {
		free(packet);
		return -1;
	}
	free(packet);	
	return 0;
}
