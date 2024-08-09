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

void    print_scans() {
    struct winsize w;

    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    printf("Rows: %d and columns: %d\n", w.ws_row, w.ws_col);
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

    print_scans();
}