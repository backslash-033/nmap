#include "ft_nmap.h"


char *create_filter(int scan) {
	if (scan == UDP_SCAN) {
		return strdup("udp or icmp");
	} else {
		return strdup("tcp or icmp");
	}
}
