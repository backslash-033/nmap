#include "ft_nmap.h"

static void	display_options(options opt);
static void	print_exec_time(struct timeval before, struct timeval after);

int main(int argc, char **argv) {
	options 		opt;
	tdata_out		**thread_output;
	struct timeval	before, after;

	opt = options_handling(argc, argv);

	display_options(opt);

	thread_output = threads(&opt, &before, &after);

	printf("\n\033[31mExecution ended: ");
	print_exec_time(before, after);
	printf("\033[0m\n\n");

	for (int j = 0; j < SCAN_AMOUNT; j++) {
		if (thread_output[j] == NULL)
			continue;
		for (int i = 0; i < opt.threads; i++) {
			printf("\033[90mthread %d scan %d\033[0m\n%s", i, j, thread_output[j][i].data);
		}
	}

	for (int i = 0; i < SCAN_AMOUNT; i++) {
		free_tdata_out_array(thread_output[i], opt.threads);
	}

	free(thread_output);
	free_options(&opt);
}

void	free_tdata_out(tdata_out d) {
	if (d.data) {
		free(d.data);
	}
}

void	free_tdata_out_array(tdata_out *array, const uint8_t size) {
	if (!array)
		return;
	for (uint8_t i = 0; i < size; i++) {
		free_tdata_out(array[i]);
	}
	free(array);
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

	printf("\n---\n\n");
}