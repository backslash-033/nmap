#include "ft_nmap.h"

static void	display_options(options opt);

int main(int argc, char **argv) {
	options 	opt;
	tdata_out	*thread_output;

	opt = options_handling(argc, argv);

	display_options(opt);

	thread_output = threads(&opt);

	printf("\n\033[31mExecution endend:\033[0m\n\n");

	for (int i = 0; i < opt.threads; i++) {
		printf("\033[90mthread %d\033[0m\n%s", i, thread_output[i].data);
	}

	free(thread_output);
	free_options(&opt);
}

static void	display_options(options opt) {
	bool	already_displayed_a_scan = false;
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

	display_port_range(opt.port, opt.port_len);
	puts("");

	printf("Hosts:\n");
	for (uint32_t i = 0; i < opt.host_len; i++) {
		printf("- %s\n", opt.host[i].basename);
	}
}

void	display_port_range(uint16_t *array, uint32_t size) {
	bool	in_range = false;

	if (size == 1) {
		printf("%hu\n", array[0]);
	}
	else {
		for (uint32_t i = 0; i != (size - 1); i++) {
			if (!in_range)
				printf("%hu", array[i]);
			if (array[i] + 1 == array[i + 1] && !in_range) {
				in_range = true;
				printf("-");
			}
			if (array[i] + 1 != array[i + 1] && in_range) {
				in_range = false;
				printf("%hu,", array[i]);
			}
		}
		printf("%hu", array[size - 1]);
	}
}