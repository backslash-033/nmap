#include "ft_nmap.h"

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
		// The length for the separator is directly in the *_LEN macro
	}
	return len;
}

static inline void __write_header_scans(t_scan *scans, size_t len_scans,
										char *results) {
	/*

	*/
	
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

static inline const char *__compute_conclusion(t_results results) {
	/*
		Returns a padded string of the conclusion of the port state based on 
		the t_results stuct.

		Args:
			- results: see __get_conclusion() below
		
		Returns:
			A padded string of length 14 representing the conclusion computed
			on the different elements of the t_results argument
	*/
	if (results.syn == POSITIVE || results.udp == POSITIVE)
		return "open         ";
	if (results.syn == NOTHING)
		return "filtered     ";
	if (results.ack == 0 && \
		(results.null == NOTHING || results.fin == NOTHING || \
		results.xmas == NOTHING || results.udp == NOTHING))
		return "open|filtered ";
	if (results.ack == NEGATIVE) { // unfiltered
		// There is another scan
		if (results.null == NOTHING || results.fin == NOTHING || \
			results.xmas == NOTHING || results.udp == NOTHING)
			return "open         ";
		// There is not another scan
		else
			return "unfiltered   ";
	} 
	else if (results.ack == NOTHING) // filtered
		return "filtered     ";
	return "closed       ";
}

static inline const char *__get_conclusion(t_scan *scans, size_t len_scans, size_t ind) {
	/*
		Fills a t_result structure, that will be used by compute conclusion.
		Each field of t_result represents a type of scan and will be filled by
		the state of the response received (see enum e_responses)

		Args:
			- scans: the list of performed scans
			- len_scans: the number of performed scans
			- ind: the index of the port number in the port list of the scans

		Returns:
			The result of __compute_conlusion
	*/
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
	/*
		Write the result of each scan of scans in results, for the port of index ind

		Args:
			- scans: the list of performed scans
			- len_scans: the number of performed scans
			- results: the string representing the results of a given port for the different scans
			- ind: the index of the port number in the port list of the scans
	*/

	for (size_t i = 0; i < len_scans; i++) { // Iterate through all the scans
		switch (scans[i].type) { // Each scan can yield a different conclusion, interpret the results
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
		strncat(results, " ", 2); // Add a separator between each scan interpretation
	}
}

static void _print_port_results(t_scan *scans, size_t len_scans, char *results) {
	struct servent *service;

	for (size_t ind = 0; ind < scans->results->len; ind++) { // Vertical traversal of all ports
		sprintf(results, "%-5d ", scans->results->ports[ind].port); // Write the port number
		_write_results(scans, len_scans, results, ind); // Write the result of eachs scan
		strncat(results, __get_conclusion(scans, len_scans, ind), 15); // Write the conclusion
		service = getservbyport(htons(scans->results->ports[ind].port), NULL); // Resolve the suspected service
		if (service)
			strncat(results, service->s_name, 16);	// Write the service name
		puts(results); // Prints everything
	}
}

int    print_results(t_scan *scans, size_t len_scans) {
	char *results;
	size_t len = 5 + 1 + 13 + 16; // Length of 65535 + ' ' + size of conclusion field + arbirtrary size for service

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

// void change_response(t_port_state_vector *vector, enum e_responses state) {
// 	for (size_t i = 0; i < vector->len; i++) {
// 		vector->ports[i].state = state;
// 	}
// }

// void reset_scans(t_scan *scans, size_t len_scans) {
// 	for (size_t i = 0; i < len_scans; i++) {
// 		change_response(scans[i].results, NOTHING);
// 	}
// }

// void set_6_scans(int syn, int null, int ack, int fin, int xmas, int udp, t_scan *scans, size_t len_scans) {
// 	if (len_scans != 6) {
// 		fprintf(stderr, "Error: must contain 6 scans in scans\n");
// 	}
// 	change_response(scans[0].results, syn);
// 	change_response(scans[1].results, null != POSITIVE ? null : NOTHING); // To treat impossible cases
// 	change_response(scans[2].results, ack != POSITIVE ? ack : NOTHING);
// 	change_response(scans[3].results, fin != POSITIVE ? fin : NOTHING);
// 	change_response(scans[4].results, xmas != POSITIVE ? xmas : NOTHING);
// 	change_response(scans[5].results, udp);
// }

// int main() {
//     size_t len_scans = 3;
//     t_scan *scans;
//     size_t len_ports = 10;
//     uint16_t *ports = malloc(len_ports * sizeof(int));

//     ports[0] = 80;
//     ports[1] = 443;
//     ports[2] = 65535;
//     ports[3] = 2605;
//     ports[4] = 739;
//     ports[5] = 1245;
//     ports[6] = 2153;
//     ports[7] = 27467;
//     ports[8] = 26214;
//     ports[9] = 8567;

// 	/* Test if one scanners work: conclusion matches well the only result */
// 	// int scan_types[] = {SYN_SCAN, NULL_SCAN, ACK_SCAN, FIN_SCAN, XMAS_SCAN, UDP_SCAN};
// 	// int responses[] = {POSITIVE, NEGATIVE, NOTHING};
// 	// len_scans = 1;
//     // scans = malloc(len_scans * sizeof(t_scan));
//     // scans[0].results = create_port_state_vector(ports, len_ports);

// 	// for (int i = 0; i < 6; i++) {
//     // 	scans[0].type = scan_types[i];
// 	// 	for (int j = 0; j < 3; j++) {
// 	// 		change_response(scans[0].results, responses[j]);
// 	// 		print_results(scans, len_scans);
// 	// 	}
// 	// }
// 	// free_port_state_vector(&(scans[0].results));
// 	// free(scans);

// 	len_scans = 6;
//     scans = malloc(len_scans * sizeof(t_scan));
//     scans[0].type = SYN_SCAN;
//     scans[0].results = create_port_state_vector(ports, len_ports);
//     scans[1].type = NULL_SCAN;
//     scans[1].results = create_port_state_vector(ports, len_ports);
//     scans[2].type = ACK_SCAN;
//     scans[2].results = create_port_state_vector(ports, len_ports);
//     scans[3].type = FIN_SCAN;
//     scans[3].results = create_port_state_vector(ports, len_ports);
//     scans[4].type = XMAS_SCAN;
//     scans[4].results = create_port_state_vector(ports, len_ports);
//     scans[5].type = UDP_SCAN;
//     scans[5].results = create_port_state_vector(ports, len_ports);
// 	printf("=======================================\nALL AT NOTHING\n");
// 	print_results(scans, len_scans);
// 	reset_scans(scans, len_scans);

// 	printf("=======================================\nSYN POSITIVE; REMAINDER NEGATIVE \n");
// 	printf("SHOULD BE: open closed unfiltered closed closed closed open\n");
// 	set_6_scans(POSITIVE, NEGATIVE, NEGATIVE, NEGATIVE, NEGATIVE, NEGATIVE, scans, len_scans);
// 	print_results(scans, len_scans);
// 	reset_scans(scans, len_scans);

// 	printf("=======================================\nSYN & ACK NEGATIVE; REMAINDER NOTHING \n");
// 	printf("SHOULD BE: closed open|filetered unfiltered open|filetered open|filetered open|filetered open\n");
// 	set_6_scans(NEGATIVE, NOTHING, NEGATIVE, NOTHING, NOTHING, NOTHING, scans, len_scans);
// 	print_results(scans, len_scans);
// 	reset_scans(scans, len_scans);

// 	free_port_state_vector(&(scans[0].results));
// 	free_port_state_vector(&(scans[1].results));
// 	free_port_state_vector(&(scans[2].results));
// 	free_port_state_vector(&(scans[3].results));
// 	free_port_state_vector(&(scans[4].results));
// 	free_port_state_vector(&(scans[5].results));
// 	free(ports);
// 	free(scans);
// }