#include "ft_nmap.h"

void show_results(t_port_state_vector *scans) {
    /*

    */

}

int main() {
    t_scan *scans;
    size_t len = 10;
    int *ports = malloc(len * sizeof(int));

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


    scans = malloc(3 * sizeof(t_scan));
    scans[0].scan_type = SYN_SCAN;
    scans[0].results = create_port_state_vector()
}