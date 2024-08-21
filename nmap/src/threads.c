#include "ft_nmap.h"

static tdata_in			*build_threads_input(const options *opt, uint8_t *th_amount, const host_data host);
static t_scan 			launch_threads(const options *opt, tdata_in *threads_input, uint8_t amount, enum e_scans scan);
static host_and_ports	*every_host_and_ports(const options opt, uint8_t *th_amount, const host_data host);
static host_and_ports	host_and_ports_one_thread(const options opt, const uint32_t per_thread, const host_data host);
static void				free_host_and_ports(host_and_ports h);
static void				free_host_and_ports_array(host_and_ports *array);
static void				already_open_ports(uint16_t *array);
static uint16_t			assign_port(uint16_t *already_open_ports);
static enum e_scans		convert_option_scan(uint8_t opt_scan);
static void				print_exec_time(struct timeval before, struct timeval after);

bool	threads(options *opt) {
	tdata_in		*threads_input = NULL;
	uint8_t			th_amount = NEVER_ZERO(opt->threads);
	struct timeval	before, after;
	t_scan			*out;
	uint8_t			scan_amout = amount_of_scans(opt->scans);

	printf("Starting scan...\n\n");

	for (int h = 0; h < (int)opt->host_len; h++) {
		printf("Host: %s\n", opt->host[h].basename);
		out = calloc(sizeof(t_scan), scan_amout + 1);
		if (out == NULL)
			return true;

		gettimeofday(&before, NULL);
		threads_input = build_threads_input(opt, &th_amount, opt->host[h]);
		if (threads_input == NULL) {
			free(out);
			return true;
		}

		for (int scan = 0b00000001, i = 0; scan != 0b01000000; scan <<= 1) {
			if (scan & opt->scans) {
				out[i] = launch_threads(opt, threads_input, th_amount, convert_option_scan(scan));
				i++;
			}
		}

		gettimeofday(&after, NULL);

		printf("Execution time: ");
		print_exec_time(before, after);
		printf("\n");
		print_results(out, scan_amout);

		if (h + 1!= (int)opt->host_len)
			printf("\n---\n\n");

		for (int i = scan_amout - 1; (i + 1) != 0; i--) {
			free(out[i].results->ports);
			free(out[i].results);
		}
		free(out);
		for (int i = 0; i < th_amount; i++) {
			free(threads_input[i].hnp.ports);
		}
		free(threads_input);
		out = NULL;
	}

	opt->threads = th_amount;
	return false;
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

uint8_t	amount_of_scans(const uint8_t opt_scan) {
	uint8_t i = 0;

	for (int scan = 0b00000001; scan != 0b01000000; scan <<= 1) {
		if (scan & opt_scan)
			i++;
	}
	return i;
}

static enum e_scans	convert_option_scan(uint8_t opt_scan) {
	if (IS_SCAN_SYN(opt_scan))
		return SYN_SCAN;
	else if (IS_SCAN_FIN(opt_scan))
		return FIN_SCAN;
	else if (IS_SCAN_NULL(opt_scan))
		return NULL_SCAN;
	else if (IS_SCAN_ACK(opt_scan))
		return ACK_SCAN;
	else if (IS_SCAN_XMAS(opt_scan))
		return XMAS_SCAN;
	else if (IS_SCAN_UDP(opt_scan))
		return UDP_SCAN;
	return 0;
}

static t_scan	launch_threads(const options *opt, tdata_in *threads_input, uint8_t amount, enum e_scans scan) {
	pthread_t	tid[256];
	uint16_t	taken_ports[PORT_RANGE + 1];
	t_scan		res;

	bzero(taken_ports, (PORT_RANGE + 1) * sizeof(uint16_t));
	already_open_ports(taken_ports);
	srand(time(0));

	for (uint8_t i = 0; i < amount; i++) {
		threads_input[i].port = assign_port(taken_ports);
		threads_input[i].scans = scan;
		pthread_create(&(tid[i]), NULL, routine, &(threads_input[i]));
	}

	res = main_thread(opt->port, opt->port_len, scan);

	for (uint8_t i = 0; i < amount; i++) {
		pthread_join(tid[i], NULL);
	}

	return res;
}

static void	already_open_ports(uint16_t *array) {
	uint16_t	i = 0;
	FILE		*f;
	char		buff[256];
	uint16_t	port;

	f = fopen("/proc/net/tcp", "r");
	if (f != NULL) {
		if (fgets(buff, 256, f) == NULL) {
			return;
		}
		while (fgets(buff, 256, f)) {
			sscanf(buff, "%*d: %*64[0-9A-Fa-f]:%hx", &port);
			if (port >= LOWEST_PORT && port < HIGHEST_PORT) {
				array[i] = port;
				i++;
			}
		}
	}
	fclose(f);
	f = fopen("/proc/net/udp", "r");
	if (f != NULL) {
		if (fgets(buff, 256, f) == NULL) {
			return;
		}
		while (fgets(buff, 256, f)) {
			sscanf(buff, "%*d: %*64[0-9A-Fa-f]:%hx", &port);
			if (port >= LOWEST_PORT && port < HIGHEST_PORT) {
				array[i] = port;
				i++;
			}
		}
	}
	fclose(f);
}

static uint16_t	assign_port(uint16_t *already_open_ports) {
	uint16_t	res;
	bool		same = false;

	while (true) {
		res = LOWEST_PORT + (rand() % PORT_RANGE);

		for (int i = 0; already_open_ports[i]; i++) {
			if (already_open_ports[i] == res) {
				same = true;
				break;
			}
		}
		if (same == true) {
			same = false;
			continue;
		}
		return res;
	}
}

static tdata_in	*build_threads_input(const options *opt, uint8_t *th_amount, const host_data host) {
	tdata_in		*res;
	host_and_ports	*every_hnp;

	every_hnp = every_host_and_ports(*opt, th_amount, host);
	if (every_hnp == NULL)
		return NULL;

	res = calloc(*th_amount, sizeof(tdata_in));
	if (res == NULL) {
		free_host_and_ports_array(every_hnp);
		return NULL;
	}

	for (uint8_t i = 0; i < *th_amount; i++) {
		res[i].hnp = every_hnp[i];
		res[i].id = i;
		res[i].scans = 0;
		res[i].opts = opt;
	}
	free(every_hnp);

	return res;
}

static host_and_ports *every_host_and_ports(const options opt, uint8_t *th_amount, const host_data host) {
	host_and_ports	*res;
	uint32_t		per_thread;
	uint8_t			more;
	uint8_t			i = 0;

	per_thread = opt.port_len / NEVER_ZERO(opt.threads);
	*th_amount = per_thread ? opt.threads : opt.port_len;

	more = opt.port_len % NEVER_ZERO(opt.threads);

	res = calloc(*th_amount + 1, sizeof(host_and_ports));

	for (; i < more; i++) {
		res[i] = host_and_ports_one_thread(opt, per_thread + 1, host);
	}
	for (; i < *th_amount; i++) {
		res[i] = host_and_ports_one_thread(opt, per_thread, host);
	}

	return res;
}

static host_and_ports host_and_ports_one_thread(const options opt, const uint32_t per_thread, const host_data host) {
	static uint32_t	port_index = 0;
	host_and_ports	hnp;
	uint32_t		loop_port_index = 0;

	bzero(&hnp, sizeof(host_and_ports));

	hnp.host = host;
	hnp.ports = calloc(per_thread, sizeof(uint16_t));
	if (hnp.ports == NULL) {
		errno = ENOMEM;
		return hnp;
	}
	hnp.ports_len = per_thread;

	for (uint32_t i = 0; i < per_thread; i++) {
		// printf("\033[35mhnp.ports: %p | i: %u, opt.ports: %p | opt.port_len: %u | port_index: %u | op.port[%u]: %u\033[0m\n", hnp.ports, i, opt.port, opt.port_len, port_index, port_index, opt.port[port_index]);
		hnp.ports[loop_port_index] = opt.port[port_index];
		loop_port_index++;
		port_index++;
		if (port_index >= opt.port_len) {
			port_index = 0;
			break;
		}
	}

	// printf("Before displaying the range:\nres: %p\nsize: %u\nres[size - 1].ports: %p\n", res, size, res[size - 1].ports);
	// printf("port_index: %u\n", port_index);
	// printf("host_index: %u\n", host_index);
	// printf("hnp.ports_len: %u\n", hnp.ports_len);
	// printf("size: %u\n", size);
	// display_port_range(res[size - 1].ports, res[size - 1].ports_len);
	// puts("");

	return hnp;
}

void	free_host_and_ports(host_and_ports h) {
	free(h.ports);
}

void	free_host_and_ports_array(host_and_ports *array) {
	for (int i = 0; array[i].ports; i++) {
		free_host_and_ports(array[i]);
	}
	free(array);
}