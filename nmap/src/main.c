#include "ft_nmap.h"

static void	display_options(options opt);
static void	free_every_addrinfo(struct addrinfo **to_free);
static void free_end_of_main(options opt, struct addrinfo **addrinfo_to_free);

// TODO: Faut check que la réponse n’est pas « NOTHING » avant de réécrire un truc
// Le nothing c’est la réponse par défaut
// Genre si au premier scan le packet a eu une réponse et pas au 2e faut pas overwrite
// Et faut faire la même chose dans l’interpréteur ICMP

int main(int argc, char **argv) {
	options 		opt;
	struct addrinfo	**addrinfo_to_free;
	bool	result;

	if (geteuid() != 0) {
		fprintf(stderr, ERROR "You are no running as root, the scans cannot work. Aborting.\n");
		exit(1);
	}

	opt = options_handling(argc, argv, &addrinfo_to_free);

	display_options(opt);

	// TODO: change this to bool
	result = threads(&opt);
	if (result == true) {
		free_end_of_main(opt, addrinfo_to_free);
		fprintf(stderr, ERROR "Fatal error.\n");
		exit(1);
	}

	free_end_of_main(opt, addrinfo_to_free);
}

static void free_end_of_main(options opt, struct addrinfo **addrinfo_to_free) {
	free_options(&opt);
	if (addrinfo_to_free)
		free_every_addrinfo(addrinfo_to_free);
}

static void	free_every_addrinfo(struct addrinfo **to_free) {
	for (int i = 0; to_free[i]; i++) {
		freeaddrinfo(to_free[i]);
	}
	free(to_free);
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
	printf("\n---\n\n");
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
}