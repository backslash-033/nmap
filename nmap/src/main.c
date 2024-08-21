#include "ft_nmap.h"

static void	display_options(options opt);
static void	print_exec_time(struct timeval before, struct timeval after);
static void	free_every_addrinfo(struct addrinfo **to_free);
static void free_end_of_main(options opt, struct addrinfo **addrinfo_to_free, t_scan *result);

int main(int argc, char **argv) {
	options 		opt;
	struct timeval	before, after;
	struct addrinfo	**addrinfo_to_free;
	t_scan			*result;

	opt = options_handling(argc, argv, &addrinfo_to_free);

	display_options(opt);

	result = threads(&opt, &before, &after);
	if (result == NULL) {
		free_end_of_main(opt, addrinfo_to_free, result);
		fprintf(stderr, ERROR "Error creating thread data.\n");
		exit(1);
	}

	printf("\n\033[31mExecution ended: ");
	print_exec_time(before, after);
	printf("\033[0m\n\n");

	print_results(result, amount_of_scans(opt.scans));

	free_end_of_main(opt, addrinfo_to_free, result);
}

static void free_end_of_main(options opt, struct addrinfo **addrinfo_to_free, t_scan *result) {
	free_options(&opt);
	if (addrinfo_to_free)
		free_every_addrinfo(addrinfo_to_free);
	if (result) {
		for (int i = amount_of_scans(opt.scans) - 1; (i + 1) != 0; i--) {
			free(result[i].results->ports);
			free(result[i].results);
		}
		free(result);
	}
}

static void	free_every_addrinfo(struct addrinfo **to_free) {
	for (int i = 0; to_free[i]; i++) {
		freeaddrinfo(to_free[i]);
	}
	free(to_free);
}

static void	print_exec_time(struct timeval before, struct timeval after) {
	uint64_t	msec = ((after.tv_sec - before.tv_sec) * 1000) + ((after.tv_usec - before.tv_usec) / 1000);
	uint64_t	sec = msec / 1000;
	uint64_t	min = sec / 60;

	if (min) {
		printf("%lum ", min);
	}
	if (sec) {
		printf("%lus ", sec % 60);
		printf("%03lums", msec % 1000);
	}
	else {
		printf("%lums", msec % 1000);
	}
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
			if (!in_range) {
				printf("%hu", array[i]);
			}
			if (array[i] + 1 == array[i + 1] && !in_range) {
				in_range = true;
				printf("-");
			}
			if (array[i] + 1 != array[i + 1] && in_range) {
				in_range = false;
				printf("%hu,", array[i]);
			}
			else if (array[i] + 1 != array[i + 1]) {
				printf(",");
			}
		}
		printf("%hu", array[size - 1]);
	}

	printf("\n---\n\n");
}