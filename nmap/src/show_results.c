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
		++len; // For the separator
	}
	return len;
}

static inline void __write_header_scans(t_scan *scans, size_t len_scans,
										char *results) {
	
	for (size_t i = 0; i < len_scans; i++) {
		switch (scans[i].type) {
			case SYN_SCAN:
				strncat(results, "SYN     ", 9);
				break;
			case NULL_SCAN:
				strncat(results, "NULL         ", 14);
				break;
			case ACK_SCAN:
				strncat(results, "ACK       ", 11);
				break;
			case FIN_SCAN:
				strncat(results, "FIN         ", 14);
				break;
			case XMAS_SCAN:
				strncat(results, "XMAS         ", 14);
				break;
			case UDP_SCAN:
				strncat(results, "UDP     ", 9);
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

static inline void __print_sole_scan(t_scan *scans, char *results, size_t len) {
	(void)scans;
	(void)results;
	(void)len;
}

static void _print_ports(t_scan *scans, size_t len_scans, char *results, size_t len) {
	int conclusion;

	(void) results;
	(void)len;
	(void)conclusion;
	if (len_scans == 1) {
		return __print_sole_scan(scans, results, len);
	}
	for (size_t ind = 0; ind < scans->results->len; ind++) { // Vertical traversal of all ports
		conclusion = __get_conclusion(scans, len_scans, ind);
		switch (conclusion) {
			case P_OPEN:
				printf("%-5d open\n", scans->results->ports[ind].port);
				break;
			case P_CLOSED:
				printf("%-5d closed\n", scans->results->ports[ind].port);
				break;
			case P_OPEN + P_FILTERED:
				printf("%-5d open|filtered\n", scans->results->ports[ind].port);
				break;
			case P_FILTERED:
				printf("%-5d filtered\n", scans->results->ports[ind].port);
				break;
			default:
				printf("%-5d bad ccl: %d\n", scans->results->ports[ind].port, conclusion);
		}
	}
}

int    print_scans(t_scan *scans, size_t len_scans) {
	char *results;
	size_t len = 5 + 1 + 13 + 80; // Size of 65535 + ' ' + size of conclusion field + arbirtrary size for service

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
	printf("%s\n", results);

	memset(results, '-', len);
	printf("%s\n", results);
	_print_ports(scans, len_scans, results, len);
	return 0;
}


// TODO delete me
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


	// Maybe all of the scans can point to the same port_state_vector?
    scans = malloc(3 * sizeof(t_scan));
    scans[0].type = SYN_SCAN;
    scans[0].results = create_port_state_vector(ports, len_ports);
	scans[1].type = UDP_SCAN;
	scans[1].results = create_port_state_vector(ports, len_ports);
	scans[2].type = ACK_SCAN;
	scans[2].results = create_port_state_vector(ports, len_ports);

	// change_response(scans[0].results, POSITIVE);
	change_response(scans[2].results, NOTHING);

    print_scans(scans, len_scans);
}