#include "ft_nmap.h"

static void	display_options(options opt);

int main(int argc, char **argv) {
	options opt;

	opt = options_handling(argc, argv);

	display_options(opt);

	free_options(&opt);
}

static void	display_options(options opt) {
	bool	already_displayed_a_scan = false;
	bool	in_range = false;
	printf("Threads: %d\n", opt.threads);
	printf("Scans: ");
	
	if (IS_SCAN_ALL(opt.scans))
		printf("ALL\n");
	else {
		if (IS_SCAN_SYN(opt.scans)) {
			printf("SYN");
			already_displayed_a_scan = true;
		}
		if (IS_SCAN_NULL(opt.scans)) {
			if (already_displayed_a_scan)
				putc(',', stdout);
			printf("NULL");
			already_displayed_a_scan = true;
		}
		if (IS_SCAN_ACK(opt.scans)) {
			if (already_displayed_a_scan)
				putc(',', stdout);
			printf("ACK");
			already_displayed_a_scan = true;
		}
		if (IS_SCAN_FIN(opt.scans)) {
			if (already_displayed_a_scan)
				putc(',', stdout);
			printf("FIN");
			already_displayed_a_scan = true;
		}
		if (IS_SCAN_XMAS(opt.scans)) {
			if (already_displayed_a_scan)
				putc(',', stdout);
			printf("XMAS");
			already_displayed_a_scan = true;
		}
		if (IS_SCAN_UDP(opt.scans)) {
			if (already_displayed_a_scan)
				putc(',', stdout);
			printf("UDP");
		}
		putc('\n', stdout);
	}

	printf("Ports: ");

	if (opt.port_amount == 1) {
		printf("%hu\n", opt.port[0]);
	}
	else {
		for (uint32_t i = 0; i != (opt.port_amount - 1); i++) {
			if (!in_range)
				printf("%hu", opt.port[i]);
			if (opt.port[i] + 1 == opt.port[i + 1] && !in_range) {
				in_range = true;
				printf("-");
			}
			if (opt.port[i] + 1 != opt.port[i + 1] && in_range) {
				in_range = false;
				printf("%hu,", opt.port[i]);
			}
		}
		printf("%hu\n", opt.port[opt.port_amount - 1]);
	}

	printf("Hosts:\n");
	for (uint32_t i = 0; i < opt.host_amout; i++) {
		printf("- %s\n", opt.host[i].basename);
	}
}