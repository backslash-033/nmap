#include "ft_nmap.h"

void	main_thread() {
	char		errbuff[PCAP_ERRBUF_SIZE];
	pcap_if_t	*interface;
	pcap_t		*snifferz;

	return;

	if (pcap_findalldevs(&interface, errbuff) == -1) {
		fprintf(stderr, ERROR "libpcap could not find any devices: %s\n", errbuff);
		return;
	}

	printf("%s", interface->name);

	snifferz = pcap_open_live(interface->name, BUFSIZ, 5000, 0, errbuff);
	if (!snifferz) {
		fprintf(stderr, ERROR "libpcap could not open device %s: %s\n", interface->name, errbuff);
		pcap_freealldevs(interface);
		return;
	}


}