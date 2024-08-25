#include "ft_nmap.h"

static tdata_in			*build_threads_input(options *opt, uint8_t *th_amount, const host_data host);
static t_scan 			launch_threads(options *opt, tdata_in *threads_input, uint8_t amount, enum e_scans scan, host_data dest_ip);
static host_and_ports	*every_host_and_ports(options opt, uint8_t *th_amount, const host_data host);
static host_and_ports	host_and_ports_one_thread(options opt, const uint32_t per_thread, const host_data host);
static void				free_host_and_ports(host_and_ports h);
static void				free_host_and_ports_array(host_and_ports *array);
static void				already_open_ports(uint16_t *array);
static uint16_t			assign_port(uint16_t *already_open_ports);
static enum e_scans		convert_option_scan(uint8_t opt_scan);
static void				print_exec_time(struct timeval before, struct timeval after);

uint32_t get_local_ip() {
	struct ifaddrs *ifaddr, *ifa;
	uint32_t ip_int = 0;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		return 0;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;

		// Check for IPv4, non-loopback, and non-link-local address
		if (ifa->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in *addr_in = (struct sockaddr_in *)ifa->ifa_addr;
			if (addr_in->sin_addr.s_addr != htonl(INADDR_LOOPBACK) &&
				addr_in->sin_addr.s_addr != htonl(INADDR_ANY)) {
				ip_int = addr_in->sin_addr.s_addr;
				break; // Found a valid IP address
			}
		}
	}

	freeifaddrs(ifaddr);
	return ip_int;
}


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
				out[i] = launch_threads(opt, threads_input, th_amount, convert_option_scan(scan), opt->host[h]);
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

static t_scan	launch_threads(options *opt, tdata_in *threads_input, uint8_t amount, enum e_scans scan, host_data dest_ip) {
	pthread_t	tid[512];
	uint16_t	taken_ports[PORT_RANGE + 1];
	t_scan		res = {
		.type = scan
	};
	t_uint16_vector ports = {
		.len = (size_t)opt->port_len,
		.list = opt->port,
	};
	pthread_t		listener_id;
	void			*listener_ret;

	bzero(tid, sizeof(pthread_t) * 512);
	bzero(taken_ports, (PORT_RANGE + 1) * sizeof(uint16_t));
	already_open_ports(taken_ports);
	srand(time(0));

	t_listener_in listener_data = {
		.cond = PTHREAD_COND_INITIALIZER,
		.mutex = PTHREAD_MUTEX_INITIALIZER,
		.ready = 0,
		.nb_ports = ports.len,
		.dest_ip = dest_ip,
	};

	res.results = create_port_state_vector(ports.list, ports.len);
	if (!res.results) {
		exit(1);
		// TODO clear properly
	}
	res.type = scan;
	listener_data.scan = res;

	struct sockaddr *ip = threads_input[0].hnp.host.info.ai_addr;

	listener_data.is_lo = ntohl(((struct sockaddr_in *)ip)->sin_addr.s_addr) >> 24 == 127;

	listener_data.timeout = opt->timeout;

	pthread_create(&listener_id, NULL, main_thread, (void *)&listener_data);

	pthread_mutex_lock(&listener_data.mutex);
	while (listener_data.ready == 0) {
		pthread_cond_wait(&listener_data.cond, &listener_data.mutex);
	}
	pthread_mutex_unlock(&listener_data.mutex);

	for (uint8_t i = 0; i < amount; i++) {
		threads_input[i].port = assign_port(taken_ports);
		threads_input[i].scans = scan;
		pthread_create(&(tid[i]), NULL, routine, &(threads_input[i]));
		if (scan == UDP_SCAN)
			pthread_create(&(tid[i + amount]), NULL, routine, &(threads_input[i]));
	}

	for (uint8_t i = 0; i < amount; i++) {
		pthread_join(tid[i], NULL);
		if (scan == UDP_SCAN)
			pthread_join(tid[i + amount], NULL);
	}

	pthread_join(listener_id, &listener_ret);
	free(listener_ret);
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

static tdata_in	*build_threads_input(options *opt, uint8_t *th_amount, const host_data host) {
	tdata_in		*res;
	host_and_ports	*every_hnp;

	every_hnp = every_host_and_ports(*opt, th_amount, host);
	if (every_hnp == NULL)
		return NULL;

	if (strcmp(host.basename, "localhost"))
		opt->source = get_local_ip();
	if (!opt->source) {
		free_host_and_ports_array(every_hnp);
		return NULL;
	}

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

static host_and_ports *every_host_and_ports(options opt, uint8_t *th_amount, const host_data host) {
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

static host_and_ports host_and_ports_one_thread(options opt, const uint32_t per_thread, const host_data host) {
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