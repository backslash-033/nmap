#include "ft_nmap.h"

// void show_results(t_port_state_vector *scans) {
//     /*

//     */
//     char    *str_ips = NULL;
//     size_t  len = 0;
//     char    *str_scans = NULL;
//     int     nb_threads = 0;

//     // Print in main thread before scanning
//     // TODO nathan
//     // puts("Scan configuration:\n");
//     // printf("Target IP addresses:\n%s\n", str_ips);
//     // printf("Number of ports to scan: %d\n", len);
//     // printf("Scans to be performed: %s\n", str_scans);
//     // printf("Number of threads: %d\n", nb_threads);
//     // puts("Starting to scan\n");


// }

// TODO need to record elpased time during the scn


typedef struct	s_results {
	uint16_t	syn;
	uint16_t	null;
	uint16_t	ack;
	uint16_t	fin;
	uint16_t	xmas;
	uint16_t	udp;
}			t_results;


static inline size_t __scans_strings_len(t_scan *scans, size_t len_scans) {
	size_t len = 0;
	
	for (size_t i = 0; i < len_scans; i++) {
		switch (scans[i].type) {
			case SYN_SCAN:
				len += SYN_LEN;
				break;
			case NULL_SCAN:
				len += NULL_LEN;
				break;
			case ACK_SCAN:
				len += ACK_LEN;
				break;
			case FIN_SCAN:
				len += FIN_LEN;
				break;
			case XMAS_SCAN:
				len += XMAS_LEN;
				break;
			case UDP_SCAN:
				len += UDP_LEN;
				break;
		}
		// ++len; // For the separator -> NOW DIRECTLY IN THE MACRO
	}
	return len;
}

static inline void __write_header_scans(t_scan *scans, size_t len_scans,
										char *results) {
	
	for (size_t i = 0; i < len_scans; i++) {
		switch (scans[i].type) {
			case SYN_SCAN:
				strncat(results, "SYN     ", SYN_LEN);
				break;
			case NULL_SCAN:
				strncat(results, "NULL         ", NULL_LEN);
				break;
			case ACK_SCAN:
				strncat(results, "ACK       ", ACK_LEN);
				break;
			case FIN_SCAN:
				strncat(results, "FIN          ", FIN_LEN);
				break;
			case XMAS_SCAN:
				strncat(results, "XMAS         ", XMAS_LEN);
				break;
			case UDP_SCAN:
				strncat(results, "UDP          ", UDP_LEN);
				break;
		}
		strncat(results, " ", 2);
	}
}

// TODO might return str if last time needed
static inline int __compute_conclusion(t_results results) {
	
	if (results.syn == POSITIVE || results.udp == POSITIVE) {
		return P_OPEN;
	}
	if (results.ack != 0) {
		if (!(results.ack == NEGATIVE)) { // If it's unfiltered
			if (results.null == NOTHING || results.fin == NOTHING || \
				results.xmas == NOTHING || results.udp == NOTHING) {
				return P_OPEN;
			}
		} else { // If it's filtered
			if (results.null == NOTHING || results.fin == NOTHING || \
				results.xmas == NOTHING || results.udp == NOTHING) {
				return P_FILTERED;
			}
		}
	} else {
		if (results.null == NOTHING || results.fin == NOTHING || \
			results.xmas == NOTHING || results.udp == NOTHING) {
						return P_OPEN + P_FILTERED;
		}
	}
	return P_CLOSED;
}

static inline int __get_conclusion(t_scan *scans, size_t len_scans, size_t ind) {
	t_results results;

	memset(&results, 0, sizeof(t_results));
	for (size_t i = 0; i < len_scans; i++) {
		switch (scans[i].type) {
			case SYN_SCAN:
				results.syn = scans[i].results->ports[ind].state;
				break;
			case NULL_SCAN:
				results.null = scans[i].results->ports[ind].state;
				break;
			case ACK_SCAN:
				results.ack = scans[i].results->ports[ind].state;
				break;
			case FIN_SCAN:
				results.fin = scans[i].results->ports[ind].state;
				break;
			case XMAS_SCAN:
				results.xmas = scans[i].results->ports[ind].state;
				break;
			case UDP_SCAN:
				results.udp = scans[i].results->ports[ind].state;
				break;
		}
	}
	return __compute_conclusion(results);
}

static void _write_results(t_scan *scans, size_t len_scans, char *results, size_t ind) {
	// const uint16_t port = scans->results->ports[ind].port;

	for (size_t i = 0; i < len_scans; i++) {
		switch (scans[i].type) {
			case SYN_SCAN:
				interpret_syn_scan(scans[i].results->ports[ind].state, results);
				break;
			case NULL_SCAN:
				interpret_null_scan(scans[i].results->ports[ind].state, results);
				break;
			case ACK_SCAN:
				interpret_ack_scan(scans[i].results->ports[ind].state, results);
				break;
			case FIN_SCAN:
				interpret_fin_scan(scans[i].results->ports[ind].state, results);
				break;
			case XMAS_SCAN:
				interpret_xmas_scan(scans[i].results->ports[ind].state, results);
				break;
			case UDP_SCAN:
				interpret_udp_scan(scans[i].results->ports[ind].state, results);
				break;
		}
		strncat(results, " ", 2);
	}
}

static void _print_port_results(t_scan *scans, size_t len_scans, char *results) {
	int conclusion;
	struct servent *service;

	for (size_t ind = 0; ind < scans->results->len; ind++) { // Vertical traversal of all ports
		sprintf(results, "%-5d ", scans->results->ports[ind].port);
		_write_results(scans, len_scans, results, ind);
		
		conclusion = __get_conclusion(scans, len_scans, ind);
		switch (conclusion) {
			case P_OPEN:
				strncat(results, "open         ", 14);
				break;
			case P_CLOSED:
				strncat(results, "closed       ", 14);
				break;
			case P_OPEN + P_FILTERED:
				strncat(results, "open|filtered", 14);
				break;
			case P_FILTERED:
				strncat(results, "filtered     ", 14);
				break;
			default:
				printf("%-5d bad ccl: %d\n", scans->results->ports[ind].port, conclusion);
		}
		service = getservbyport(htons(scans->results->ports[ind].port), NULL);
		if (service)
			strncat(results, service->s_name, 16);
		puts(results);
	}
}

int    print_results(t_scan *scans, size_t len_scans) {
	char *results;
	size_t len = 5 + 1 + 13 + 16; // Size of 65535 + ' ' + size of conclusion field + arbirtrary size for service

	len += __scans_strings_len(scans, len_scans);
	results = malloc(len * sizeof(char));
	if (!results) {
		perror("malloc");
		return -1;
	}
	memset(results, 0, len);

	strncpy(results, "PORT  ", 7);
	__write_header_scans(scans, len_scans, results);
	strncat(results, "CONCLUSION    ", 15);
	strncat(results, "SERVICE", 8);
	puts(results);

	memset(results, '-', --len); // To prevent overwriting the final 0
	puts(results);
	_print_port_results(scans, len_scans, results);
	free(results);
	return 0;
}


// // TODO delete me
static void change_response(t_port_state_vector *vector, int response) {
	for (size_t i = 0; i < vector->len; i++) {
		vector->ports[i].state = response;
	}
}

int main() {
    size_t len_scans = 3;
    t_scan *scans;
    size_t len_ports = 10;
    int *ports = malloc(len_ports * sizeof(int));

    ports[0] = 80;
    ports[1] = 443;
    ports[2] = 65535;
    ports[3] = 2605;
    ports[4] = 739;
    ports[5] = 1245;
    ports[6] = 2153;
    ports[7] = 27467;
    ports[8] = 26214;
    ports[9] = 8567;


	// TODO Maybe all of the scans can point to the same port_state_vector?
    scans = malloc(len_scans * sizeof(t_scan));
    scans[0].type = SYN_SCAN;
    scans[0].results = create_port_state_vector(ports, len_ports);
	scans[1].type = UDP_SCAN;
	scans[1].results = create_port_state_vector(ports, len_ports);
	scans[2].type = ACK_SCAN;
	scans[2].results = create_port_state_vector(ports, len_ports);


	// len_scans = 1;
    // scans = malloc(len_scans * sizeof(t_scan));
    // scans[0].type = SYN_SCAN;
    // scans[0].results = create_port_state_vector(ports, len_ports);

	// change_response(scans[0].results, POSITIVE);
	change_response(scans[2].results, NOTHING);

    print_results(scans, len_scans);
	free(ports);
	free_port_state_vector(&(scans[0].results));
	free_port_state_vector(&(scans[1].results));
	free_port_state_vector(&(scans[2].results));
	free(scans);
}