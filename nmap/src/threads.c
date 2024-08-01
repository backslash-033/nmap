#include "ft_nmap.h"

static tdata_in			*build_threads_input(const options opt, uint8_t *th_amount);
static void 			launch_threads(tdata_in *threads_input, uint8_t amount);
static host_and_ports	**every_host_and_ports(const options opt, uint8_t *th_amount);
static host_and_ports	*host_and_ports_one_thread(const options opt, const uint32_t per_thread);
static void				free_host_and_ports(host_and_ports h);
static void				free_host_and_ports_array(host_and_ports *array);
static void				free_tdata_in(tdata_in d);
static void				free_tdata_in_array(tdata_in *array, uint8_t size);
static void				already_open_ports(uint16_t *array);
static uint16_t			assign_port(uint16_t *already_open_ports);

tdata_out	*threads(options *opt, struct timeval *before, struct timeval *after) {
	tdata_in		*threads_input;
	uint8_t			th_amount = NEVER_ZERO(opt->threads);
	tdata_out		*out;

	threads_input = build_threads_input(*opt, &th_amount);

	out = calloc((size_t)th_amount, sizeof(tdata_out));
	if (out == NULL) {
		free_tdata_in_array(threads_input, th_amount);
		return NULL;
	}

	for (int i = 0; i < th_amount; i++)
		threads_input[i].output = &(out[i]);

	gettimeofday(before, NULL);
	launch_threads(threads_input, th_amount);
	gettimeofday(after, NULL);

	free_tdata_in_array(threads_input, th_amount);
	opt->threads = th_amount;
	return out;
}

static void launch_threads(tdata_in *threads_input, uint8_t amount) {
	pthread_t	tid[256];
	uint16_t	taken_ports[PORT_RANGE + 1];

	bzero(taken_ports, (PORT_RANGE + 1) * sizeof(uint16_t));
	already_open_ports(taken_ports);
	srand(time(0));

	for (uint8_t i = 0; i < amount; i++) {
		threads_input[i].port = assign_port(taken_ports);
		pthread_create(&(tid[i]), NULL, routine, &(threads_input[i]));
	}

	main_thread();

	for (uint8_t i = 0; i < amount; i++) {
		pthread_join(tid[i], NULL);
	}
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
	uint16_t res;

	while (true) {
		res = LOWEST_PORT + (rand() % PORT_RANGE);

		for (int i = 0; already_open_ports[i]; i++) {
			if (already_open_ports[i] == res)
				continue;
		}
		return res;
	}
}

static tdata_in	*build_threads_input(const options opt, uint8_t *th_amount) {
	tdata_in		*res;
	host_and_ports	**every_hnp;

	every_hnp = every_host_and_ports(opt, th_amount);
	if (every_hnp == NULL)
		return NULL;

	res = calloc(*th_amount, sizeof(tdata_in));
	if (res == NULL) {
		// TODO: Free every hnp
		return NULL;
	}

	for (uint8_t i = 0; i < *th_amount; i++) {
		res[i].hnp = every_hnp[i];
		res[i].id = i;
		res[i].scans = opt.scans;
		res[i].output = NULL;
	}
	free(every_hnp);

	return res;
}

static host_and_ports **every_host_and_ports(const options opt, uint8_t *th_amount) {
	host_and_ports	**res;
	uint32_t		per_thread;
	uint64_t		hosts_times_ports = opt.host_len * opt.port_len;
	uint8_t			more;
	uint8_t			i = 0;

	per_thread = hosts_times_ports / NEVER_ZERO(opt.threads);
	*th_amount = per_thread ? opt.threads : hosts_times_ports;

	more = hosts_times_ports % NEVER_ZERO(opt.threads);

	res = calloc(*th_amount, sizeof(host_and_ports *));

	for (; i < more; i++) {
		res[i] = host_and_ports_one_thread(opt, per_thread + 1);
	}
	for (; i < *th_amount; i++) {
		res[i] = host_and_ports_one_thread(opt, per_thread);
	}

	return res;
}

static host_and_ports *host_and_ports_one_thread(const options opt, const uint32_t per_thread) {
	static uint32_t	host_index = 0;
	static uint32_t	port_index = 0;
	uint32_t		size = 1;
	host_and_ports	*res;
	host_and_ports	*tmp;
	host_and_ports	hnp;
	uint32_t		loop_port_index = 0;
	const uint32_t	first_ports_size = per_thread > (opt.port_len - port_index) ? (opt.port_len - port_index) : per_thread;

	// printf("\n--- Entree dans hnp_one_thread ---\n");

	res = calloc(size + 1, sizeof(host_and_ports));
	if (res == NULL)
		return NULL;

	hnp.host = opt.host[host_index];
	hnp.ports = calloc(first_ports_size, sizeof(uint16_t));
	if (hnp.ports == NULL) {
		free(res);
		return NULL;
	}
	hnp.ports_len = first_ports_size;

	for (uint32_t i = 0; i < per_thread; i++) {
		// printf("hnp.ports: %p | i: %u, opt.ports: %p | opt.port_len: %u | port_index: %u | host_index: %u | op.port[port_index] %u\n", hnp.ports, i, opt.port, opt.port_len, port_index, host_index, opt.port[port_index]);
		hnp.ports[loop_port_index] = opt.port[port_index];
		loop_port_index++;
		port_index++;
		if (port_index >= opt.port_len) {
			loop_port_index = 0;
			port_index = 0;
			host_index++;
			if (host_index == opt.host_len)
				break;

			uint32_t	remaining_ports;
			remaining_ports = (per_thread - i - 1) > opt.port_len ? opt.port_len : (per_thread - i - 1);


			// printf("Remaining: %u\n", remaining_ports);
			// printf("Per thread: %u\n", per_thread);
			// printf("opt.port_len: %u\n", opt.port_len);
			// printf("i: %u\n", i);
			// printf("Bytes allocated: %lu\n", remaining_ports * sizeof(uint16_t));

			if (remaining_ports <= 0)
				break;

			res[size - 1] = hnp;
			size++;
			tmp = calloc(size + 1, sizeof(host_and_ports));
			if (tmp == NULL) {
				free_host_and_ports_array(res);
				return NULL;
			}

			memcpy(tmp, res, (size - 1) * sizeof(host_and_ports));

			free(res);
			res = tmp;


			hnp.host = opt.host[host_index];
			hnp.ports = calloc(remaining_ports, sizeof(uint16_t));
			if (hnp.ports == NULL) {
				free_host_and_ports_array(res);
				free(tmp);
				return NULL;
			}
			hnp.ports_len = remaining_ports;
		}
	}
	res[size - 1] = hnp;

	// printf("Before displaying the range:\nres: %p\nsize: %u\nres[size - 1].ports: %p\n", res, size, res[size - 1].ports);
	// printf("port_index: %u\n", port_index);
	// printf("host_index: %u\n", host_index);
	// printf("hnp.ports_len: %u\n", hnp.ports_len);
	// printf("size: %u\n", size);
	// display_port_range(res[size - 1].ports, res[size - 1].ports_len);
	// puts("");

	res[size] = (host_and_ports){.ports = NULL, .ports_len = 0};

	return res;
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

void	free_tdata_in(tdata_in d) {
	free_host_and_ports_array(d.hnp);
}

void	free_tdata_in_array(tdata_in *array, uint8_t size) {
	for (int i = 0; i < size; i++) {
		free_tdata_in(array[i]);
	}
	free(array);
}