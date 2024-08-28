#include "ft_nmap.h"

void interpret_syn_scan(uint16_t state, char *results) {
	switch (state) {
		case POSITIVE:
			strncat(results, "open    ", SYN_LEN);
			break;
		case NEGATIVE:
			strncat(results, "closed  ", SYN_LEN);
			break;
		case NOTHING:
			strncat(results, "filtered", SYN_LEN);
			break;
	}
}

void interpret_null_scan(uint16_t state, char *results) {
	switch (state) {
		case POSITIVE:
			// Not happening 
			break;
		case NEGATIVE:
			strncat(results, "closed       ", NULL_LEN);
			break;
		case NOTHING:
			strncat(results, "open|filtered", NULL_LEN);
			break;
	}
}

void interpret_ack_scan(uint16_t state, char *results) {
	switch (state) {
		case POSITIVE:
			// Not happening 
			break;
		case NEGATIVE:
			strncat(results, "unfiltered", ACK_LEN);
			break;
		case NOTHING:
			strncat(results, "filtered  ", ACK_LEN);
			break;
	}
}

void interpret_fin_scan(uint16_t state, char *results) {
	switch (state) {
		case POSITIVE:
			// Not happening 
			break;
		case NEGATIVE:
			strncat(results, "closed       ", FIN_LEN);
			break;
		case NOTHING:
			strncat(results, "open|filtered", FIN_LEN);
			break;
	}
}

void interpret_xmas_scan(uint16_t state, char *results) {
	switch (state) {
		case POSITIVE:
			// Not happening 
			break;
		case NEGATIVE:
			strncat(results, "closed       ", XMAS_LEN);
			break;
		case NOTHING:
			strncat(results, "open|filtered", XMAS_LEN);
			break;
	}
}

void interpret_udp_scan(uint16_t state, char *results) {
	switch (state) {
		case POSITIVE:
			strncat(results, "open         ", UDP_LEN);
			break;
		case NEGATIVE:
			strncat(results, "closed       ", UDP_LEN);
			break;
		case NOTHING:
			strncat(results, "open|filtered", UDP_LEN);
			break;
	}
}
