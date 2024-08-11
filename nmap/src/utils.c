#include "ft_nmap.h"

// TODO function char_to_flags, give the uchar from the tcpheader_t and
// returns a struct tcp_flags_s with the different flags as booleans,
// set the correct ones to true -> actually, could even do hex to flags

uint32_t random_uint32(uint32_t min, uint32_t max) {
	if (min > max)
		return 0;

	const uint32_t diff = max - min;
	
	srand(time(NULL));
	return (rand() % diff) + min;
}

uint16_t random_uint16(uint16_t min, uint16_t max) {
	if (min > max)
		return 0;

	const uint16_t diff = max - min;
	
	srand(time(NULL));
	return (rand() % diff) + min;
}