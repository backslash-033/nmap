#include "ft_nmap.h"

#define ARGS_NOTHING	-1
#define ARGS_SPEED		0
#define ARGS_SCANS		1
#define ARGS_PORTS		2
#define ARGS_FILE		3
#define ARGS_IP			4
#define ARGS_TTL		5
#define ARGS_WIN		6
#define ARGS_DATA		7
#define ARGS_SOURCE		8
#define ARGS_HELP		11
#define ARGS_FAST		10
#define SCAN_NOTHING	0
#define SCAN_SYN		0b00000001
#define SCAN_NULL		0b00000010
#define SCAN_ACK		0b00000100
#define SCAN_FIN		0b00001000
#define SCAN_XMAS		0b00010000
#define SCAN_UDP		0b00100000
#define SCAN_ALL		0b10111111
#define RANGE_ALLOCERR	0xffff0000
#define RANGE_SIZEERR	0xff000000

static void			print_help_message();
static options		default_options();
static int			get_option(char const *arg);
static bool			opt_speed(options *opts, str arg);
static bool			opt_scans(options *opts, str arg);
static bool			opt_ports(options *opts, str arg);
static bool			opt_file(options *opts, str arg);
static bool			opt_ip(options *opts, str arg);
static bool			opt_ttl(options *opts, str arg);
static bool			opt_win(options *opts, str arg);
static bool			opt_data(options *opts, str arg);
static bool			opt_source(options *opts, str arg);
static uint8_t		get_scan(str scan);
static uint32_t		range_size(str arg);
static uint16_t 	*range_values(str arg, uint32_t *size);
static void			add_range_to_ports(uint16_t *ports, uint32_t *port_len,
									uint16_t *range, uint32_t range_size);
static uint16_t		*sort_port_range(uint16_t *ports, uint32_t *port_len);
static bool			add_hostname(options *opts, str hostname);
static host_data	resolve_hostname(const str hostname) ;
static uint16_t		*fast_ports();

typedef bool	(*parsing_function)(options *, str);

static struct addrinfo	*addrinfo_to_keep = NULL;

uint16_t top_100_ports[] = {
    80, 631, 161, 137, 123, 138, 1434, 445, 135, 67,
    23, 443, 21, 139, 22, 500, 68, 520, 1900, 25,
    4500, 514, 49152, 162, 69, 5353, 111, 49154, 3389, 110,
    1701, 998, 996, 997, 999, 3283, 49153, 1812, 136, 143,
    2222, 3306, 2049, 32768, 5060, 8080, 1025, 1433, 3456, 1723,
    995, 993, 20031, 1026, 7, 5900, 1646, 1645, 593, 518,
    2048, 626, 1027, 587, 177, 1719, 427, 497, 8888, 4444,
    1023, 65024, 199, 19, 9, 49193, 1029, 1720, 49, 465,
    88, 1028, 17185, 1718, 49186, 548, 113, 81, 6001, 2000,
    10000, 31337, 49192, 515, 2223, 49181, 179, 1813, 120, 49152
};

static parsing_function handlers[9] = {
	opt_speed,	// 1
	opt_scans,	// 1
	opt_ports,	// 2
	opt_file,	// 3
	opt_ip,		// 4
	opt_ttl,	// 5
	opt_win,	// 6
	opt_data,	// 7
	opt_source,	// 8
};

options options_handling(int argc, char **argv, struct addrinfo ***addrinfo_to_free) {
	options res;
	uint8_t	addrinfo_amount = 0;
	int		args_status = ARGS_NOTHING;

	if (argc == 1) {
		fprintf(stderr, ERROR "No arguments.\n\n");
		print_help_message();
		exit(2);
	}
	res = default_options();

	(*addrinfo_to_free) = calloc(addrinfo_amount, sizeof(struct addrinfo *));

	for (int i = 1; i < argc; i++) {
		if (args_status == ARGS_NOTHING) {
			args_status = get_option(argv[i]);
			switch (args_status) {
				case ARGS_HELP:
					print_help_message();
					free_options(&res);
					exit(0);
					break;
				case ARGS_FAST:
					res.fast = true;
					args_status = ARGS_NOTHING;
					break;
			}
			if (args_status == ARGS_HELP) {
				print_help_message();
				free_options(&res);
				exit(0);
			}
		} else {
			if (handlers[args_status](&res, argv[i]) == true) {
				free_options(&res);
				exit(1);
			}
			if (addrinfo_to_keep) {
				struct addrinfo **tmp = calloc(addrinfo_amount + 2, sizeof(struct addrinfo *));
				memcpy(tmp, (*addrinfo_to_free), addrinfo_amount * sizeof(struct addrinfo *));
				free((*addrinfo_to_free));
				(*addrinfo_to_free) = tmp;
				(*addrinfo_to_free)[addrinfo_amount] = addrinfo_to_keep;
				addrinfo_amount++;
				addrinfo_to_keep = NULL;
			}
			args_status = ARGS_NOTHING;
		}
	}

	if (res.scans == SCAN_NOTHING)
		res.scans = SCAN_ALL;
	else if ((res.scans & 0b00111111) == 0b00111111 &&
			!(res.scans & 0x10000000))
		res.scans = SCAN_ALL;

	if (res.fast == true) {
		free(res.port);
		res.port = fast_ports();
		if (res.port == NULL) {
			fprintf(stderr, ERROR "Error allocating memory, aborting.\n");
			free_options(&res);
			exit(1);
		}
		res.port_len = 100;
	}

	uint16_t *sorted = sort_port_range(res.port, &res.port_len);

	if (sorted == NULL && (unsigned)errno == RANGE_ALLOCERR) {
		fprintf(stderr, ERROR "Error allocating memory\n");
		free_options(&res);
		exit(1);
	} else if (sorted == NULL && (unsigned)errno == RANGE_SIZEERR) {
		fprintf(stderr, ERROR "Cannot scan more than 1024 ports.\n");
		free_options(&res);
		exit(1);
	}

	res.port = sorted;

	if (res.host_len == 0 || res.host == NULL) {
		fprintf(stderr, ERROR "No valid IP address or FQDN provided.\n");
		free_options(&res);
		exit(1);
	}

	if (res.host_len > 20) {
		fprintf(stderr, ERROR "Too much hosts provided, max: 20.\n");
		free_options(&res);
		exit(1);
	}

	if (res.data == NULL) {
		res.data = calloc(1, 1); // "\0"
	}

	if (res.threads == 0)
		res.threads = 1;

	return res;
}

static uint16_t *fast_ports() {
	uint16_t	*array;

	array = calloc(100, sizeof(uint16_t));
	if (array == NULL)
		return NULL;
	
	memcpy(array, top_100_ports, sizeof(uint16_t) * 100);
	return array;
}

void	free_options(options *opts) {
	if (opts->port) {
		free(opts->port);
	}
	if (opts->host) {
		for (uint32_t i = 0; i < opts->host_len; i++) {
			free(opts->host[i].basename);
		}
		free(opts->host);
	}
	if (opts->data) {
		free(opts->data);
	}
}

void	free_host_data(host_data data) {
	free(data.basename);
}

static bool opt_speed(options *opts, str arg) {
	int thread_nb = atoi(arg);
	if (thread_nb > 250 || thread_nb < 0) {
		fprintf(stderr, WARNING "--speedup can only be between 0 and 250 included. "
						"Argument given: %d. "
						"Setting default value of 1 thread.\n", thread_nb);
		opts->threads = 0;
		return false;
	}
	opts->threads = thread_nb;
	return false;
}

static bool opt_scans(options *opts, str arg) {
	uint8_t	scans = SCAN_NOTHING;

	str *splitted = ft_split(arg, ',');
	if (splitted == NULL)
		return true;

	for (int i = 0; splitted[i]; i++)
		scans |= get_scan(splitted[i]);
	
	free_darray((void **)splitted);

	opts->scans |= scans;
	return false;
}

static bool opt_ports(options *opts, str arg) {
	uint32_t	size = 0;

	if (opts->fast == true)
		return false;

	str			*splitted = ft_split(arg, ',');
	uint16_t	*tmp_ports = NULL;
	uint32_t	tmp_port_len = 0;

	if (splitted == NULL)
		return true;

	for (int i = 0; splitted[i]; i++) {
		errno = 0;
		if (!strcmp("-", splitted[i])) {
			fprintf(stderr, ERROR "Cannot scan more than 1024 ports.\n");
			free_darray((void **)splitted);
			return true;
		}

		uint32_t range_size_value = range_size(splitted[i]);

		if (!range_size_value && (unsigned int)errno == RANGE_ALLOCERR) {
			fprintf(stderr, ERROR "Error allocating memory\n");
			free_darray((void **)splitted);
			return true;
		} else if (!range_size_value && (unsigned int)errno == RANGE_SIZEERR) {
			fprintf(stderr, ERROR "The port range has to be between 0 and 65535 included.\n");
			free_darray((void **)splitted);
			return true;
		} else if (range_size_value > 1024) {
			fprintf(stderr, ERROR "Cannot scan more than 1024 ports.\n");
			free_darray((void **)splitted);
			return true;
		}
		size += range_size_value;
	}

	tmp_ports = calloc(sizeof(uint16_t), size > 0x10000 ? 0x10000 : size);
	if (tmp_ports == NULL) {
		fprintf(stderr, ERROR "Error allocating memory\n");
		free_darray((void **)splitted);
		return true;
	}
	tmp_port_len = 0;

	for (int i = 0; splitted[i]; i++) {
		errno = 0;
		uint32_t real_size = 0;
		uint16_t *range = range_values(splitted[i], &real_size);

		if (!range && (unsigned int)errno == RANGE_ALLOCERR) {
			fprintf(stderr, ERROR "Error allocating memory\n");
			free_darray((void **)splitted);
			free(tmp_ports);
			return true;
		} else if (!range && (unsigned int)errno == RANGE_SIZEERR) {
			fprintf(stderr, ERROR "The port range has to be between 0 and 65535 included.\n");
			free_darray((void **)splitted);
			free(tmp_ports);
			return true;
		}

		add_range_to_ports(tmp_ports, &tmp_port_len, range, real_size);
		free(range);
	}

	if (opts->port == NULL) {
		opts->port = tmp_ports;
		opts->port_len = tmp_port_len;
	}
	else {
		uint16_t *merge = calloc(sizeof(uint16_t), opts->port_len + tmp_port_len);
		uint32_t merge_size = 0;
		if (merge == NULL) {
			fprintf(stderr, ERROR "Error allocating memory\n");
			free_darray((void **)splitted);
			free(tmp_ports);
			return true;
		}
		add_range_to_ports(merge, &merge_size, opts->port, opts->port_len);
		add_range_to_ports(merge, &merge_size, tmp_ports, tmp_port_len);
		free(opts->port);
		opts->port = merge;
		opts->port_len = merge_size;
		free(tmp_ports);
	}

	free_darray((void **)splitted);
	return false;
}

static bool opt_file(options *opts, str arg) {
	int	fd = 0;
	str	all_file;
	str	*splitted;

	fd = open(arg, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, WARNING "Could not open file '%s'\n", arg);
	}
	else if (read(fd, "", 0)) {
		fprintf(stderr, WARNING "Could not read from file '%s'\n", arg);
		close(fd);
	}
	else {
		all_file = get_whole_file(fd);
		if (all_file == NULL) {
			if (errno == ENOMEM)
				return true;
			fprintf(stderr, WARNING "Read nothing from file '%s'\n", arg);
			return false;
		}
		splitted = ft_split(all_file, '\n');
		free(all_file);
		if (splitted == NULL)
			return true;
		for (size_t i = 0; splitted[i]; i++) {
			if (add_hostname(opts, splitted[i])) {
				free_darray((void **)splitted);
				return true;
			}
		}
		free_darray((void **)splitted);
	}
	return false;
}

static bool opt_ip(options *opts, str arg) {
	return add_hostname(opts, arg);
}

static bool opt_ttl(options *opts, str arg) {
	int		res;

	res = atoi(arg);
	if (res < 0 || res > 255)
		fprintf(stderr, WARNING "ttl option `%s` is invalid, the range is 0-255 included.\n", arg);
	else
		opts->ttl = (uint8_t)res;
	return false;
}

static bool opt_source(options *opts, str arg) {
    uint32_t	ip_int;
	int			result;

	result = inet_pton(AF_INET, arg, &ip_int);
    if (result == 1) {
   		opts->source = ntohl(ip_int);
    } else {
		fprintf(stderr, WARNING "inet_pton wasnt able to parse the `%s` IP address, makes sure it follows a IPv4 address format.\n", arg);
	}

    return false;
}

static bool opt_win(options *opts, str arg) {
	int		res;

	res = atoi(arg);
	if (res < 0 || res > UINT16_MAX)
		fprintf(stderr, WARNING "win option `%s` is invalid, the range is 0-65535 included.\n", arg);
	else
		opts->win = (uint8_t)res;
	return false;
}

static bool opt_data(options *opts, str arg) {

	if (strlen(arg) > 500)
		fprintf(stderr, WARNING "Data size need to be maximum 500 bytes.\n");
	else {
		if (opts->data)
			free(opts->data);
		opts->data = strndup(arg, 500);
		if (opts->data == NULL) {
			fprintf(stderr, ERROR "Could not allocate memory, aborting.\n");
			return true;
		}
	}
	return false;
}

static bool	add_hostname(options *opts, const str hostname) {
	host_data	to_add;
	host_data	*tmp;

	to_add = resolve_hostname(hostname);
	if (to_add.basename == NULL) {
		if (errno == ENOMEM)
			return true;
		return false;
	}

	tmp = calloc(opts->host_len + 1, sizeof(host_data));
	if (tmp == NULL) {
		free(to_add.basename);
		return true;
	}

	if (opts->host != NULL) {
		memcpy(tmp, opts->host, sizeof(host_data) * opts->host_len);
		free(opts->host);
	}
	opts->host = tmp;
	opts->host[opts->host_len] = to_add;
	opts->host_len += 1;
	return false;
}

static host_data	resolve_hostname(const str hostname) {
	host_data		ret;
	struct addrinfo	hints, *result, *result_base;
	char			buff[INET6_ADDRSTRLEN + 1];
	void			*ptr = NULL;

	bzero(&ret, sizeof(host_data));
	bzero(&hints, sizeof(struct addrinfo));
	bzero(buff, INET6_ADDRSTRLEN + 1);

	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_CANONNAME;

	ret.basename = strdup(hostname);
	if (!ret.basename)
		return ret;

	if (getaddrinfo(hostname, NULL, &hints, &result_base)) {
		fprintf(stderr, WARNING "Could not get address info of '%s'\n", hostname);
		free(ret.basename);
		ret.basename = NULL;
		return ret;
	}

	result = result_base;
	addrinfo_to_keep = result_base;

	while (result) {
		inet_ntop(result->ai_family, result->ai_addr->sa_data, buff, INET6_ADDRSTRLEN + 1);

		switch (result->ai_family) {
		case AF_INET:
			ptr = &((struct sockaddr_in *) result->ai_addr)->sin_addr;
				break;
        case AF_INET6:
			ptr = &((struct sockaddr_in6 *) result->ai_addr)->sin6_addr;
			break;
		}
		inet_ntop(result->ai_family, ptr, buff, 100);

		ret.info = *result;
		result = result->ai_next;
	}

	return ret;
}

static uint16_t *sort_port_range(uint16_t *ports, uint32_t *port_len) {
	uint16_t tmp;

	if (!ports || (port_len && *port_len == 0)) {
		if (ports)
			free(ports);
		ports = calloc(1024, sizeof(uint16_t));
		if (!ports) {
			errno = RANGE_ALLOCERR;
			return NULL;
		}
		for (uint16_t i = 1; i < 1025; i++)
			ports[i - 1] = i;
		*port_len = 1024;
		return ports;
	}

	if (*port_len > 1024) {
		errno = RANGE_SIZEERR;
		return NULL;
	}

	for (uint32_t _ = 0; _ < *port_len; _++) {
		for (uint32_t i = 0; i < (*port_len - 1); i++) {
			if (ports[i] > ports[i + 1]) {
				tmp = ports[i + 1];
				ports[i + 1] = ports[i];
				ports[i] = tmp;
			}
		}
	}

	return ports;
}

static void	add_range_to_ports(uint16_t *ports, uint32_t *port_len, uint16_t *range, uint32_t range_size) {
	bool	present;
	
	for (uint32_t i = 0; i < range_size; i++) {
		present = false;
		for (uint32_t j = 0; j < (*port_len); j++) {
			if (ports[j] == range[i]) {
				present = true;
				break;
			}
		}
		if (present == false) {
			ports[(*port_len)] = range[i];
			(*port_len)++;
		}
	}
}

static uint32_t	range_size(str arg) {
	int	low = 0;
	int	high = 0xffff;
	char *dash = strchr(arg, '-');

	if (dash == NULL) {
		return 1;
	}
	else if (dash == arg) {
		if (strlen(arg) == 1)
			return high + 1;
		high = atoi(arg + 1);
		if (high < 0 || high > 0xffff) {
			errno = RANGE_SIZEERR;
			return 0;
		}
		return (high + 1);
	}
	else if (dash == arg + strlen(arg) - 1) {
		low = atoi(arg);
		if (low < 0 || low > 0xffff) {
			errno = RANGE_SIZEERR;
			return 0;
		}
		return (high - low + 1);
	}
	else {
		str *range = ft_split(arg, '-');
		if (!range) {
			errno = RANGE_ALLOCERR;
			return 0;
		}
		else if (range[2] != NULL)
			;
		else {
			low = atoi(range[0]);
			high = atoi(range[1]);
			if ((high > 0xffff || low > 0xffff) ||
				(low < 0 || high < 0)) {
				free_darray((void **)range);
				errno = RANGE_SIZEERR;
				return 0;
			}
			if (low <= high && low != high) {
				free_darray((void **)range);
				return high - low + 1;
			}
		}
		free_darray((void **)range);
	}
	return 0;
}

static uint16_t *range_values(str arg, uint32_t *size) {
	int			low = 0;
	int			high = 0xffff;
	char		*dash = strchr(arg, '-');
	uint16_t	*res = NULL;

	if (dash == NULL) {
		res = calloc(sizeof(uint16_t), 1);
		if (res == NULL) {
			errno = RANGE_ALLOCERR;
			return NULL;
		}
		*size = 1;
		res[0] = atoi(arg);
		return res;
	}
	else if (dash == arg) {
		if (strlen(arg) != 1) {
			high = atoi(arg + 1);
			if (high < 0 || high > 0xffff) {
				errno = RANGE_SIZEERR;
				return NULL;
			}
		}
	}
	else if (dash == arg + strlen(arg) - 1) {
		low = atoi(arg);
		if (low < 0 || low > 0xffff) {
			errno = RANGE_SIZEERR;
			return NULL;
		}
	}
	else {
		str *range = ft_split(arg, '-');
		if (!range) {
			errno = RANGE_ALLOCERR;
			return NULL;
		}
		else if (range[2] != NULL)
			;
		else {
			low = atoi(range[0]);
			high = atoi(range[1]);
			if ((high > 0xffff || low > 0xffff) ||
				(low < 0 || high < 0)) {
				free_darray((void **)range);
				errno = RANGE_SIZEERR;
				return NULL;
			}
			if (low < high) {
				free_darray((void **)range);
			}
		}
	}
	res = calloc(sizeof(uint16_t), high - low + 1);
	if (res == NULL) {
		errno = RANGE_ALLOCERR;
		return NULL;
	}
	*size = high - low + 1;
	for (int i = 0; low + i <= high; i++)
		res[i] = low + i;
	return res;
}

static uint8_t	get_scan(str scan) {
	if (!scan)
		return SCAN_NOTHING;

	if (!strncmp(scan, "ALL", 3))
		return SCAN_ALL;
	if (!strncmp(scan, "SYN", 3))
		return SCAN_SYN;
	if (!strncmp(scan, "NULL", 4))
		return SCAN_NULL;
	if (!strncmp(scan, "ACK", 3))
		return SCAN_ACK;
	if (!strncmp(scan, "FIN", 3))
		return SCAN_FIN;
	if (!strncmp(scan, "XMAS", 4))
		return SCAN_XMAS;
	if (!strncmp(scan, "UDP", 3))
		return SCAN_UDP;

	fprintf(stderr, WARNING "Unknown scan type: '%s'\n", scan);
	return SCAN_NOTHING;
}

static int	get_option(char const *arg) {
	if (!arg)
		return ARGS_NOTHING;
	if (strncmp(arg, "--", 2)) {
		fprintf(stderr, WARNING "Could not reckognised option '%s'.\n", arg);
		return ARGS_NOTHING;
	}

	if (strlen(arg) > 2) {
		arg = arg + 2;
		if (!strncmp(arg, "speedup", 7))
			return ARGS_SPEED;
		if (!strncmp(arg, "scan", 4))
			return ARGS_SCANS;
		if (!strncmp(arg, "ports", 5))
			return ARGS_PORTS;
		if (!strncmp(arg, "file", 4))
			return ARGS_FILE;
		if (!strncmp(arg, "ip", 2))
			return ARGS_IP;
		if (!strncmp(arg, "help", 4))
			return ARGS_HELP;
		if (!strncmp(arg, "fast", 4))
			return ARGS_FAST;
		if (!strncmp(arg, "ttl", 3))
			return ARGS_TTL;
		if (!strncmp(arg, "win", 3))
			return ARGS_WIN;
		if (!strncmp(arg, "data", 4))
			return ARGS_DATA;
		if (!strncmp(arg, "source", 6))
			return ARGS_SOURCE;
		fprintf(stderr, WARNING "Could not reckognised option '%s'.\n", arg - 2);
		return ARGS_NOTHING;
	}

	fprintf(stderr, WARNING "Could not reckognised option '%s'.\n", arg);
	return ARGS_NOTHING;
}

static void print_help_message() {
	puts("ft_nmap: help\n");
	puts("Usage:");
	puts("ft_nmap [--help] [--ports [NUMBER/RANGED]] --ip IP_ADDRESS [--speedup [NUMBER]] [--scan [TYPE]]");
	puts("ft_nmap [--help] [--ports [NUMBER/RANGED]] --file FILE [--speedup [NUMBER]] [--scan [TYPE]]\n");
	puts("Options:");
	puts("--help         Shows this help message");
	puts("--ports        Range of ports to scan");
	puts("--file         File name to read the list of IP addresses from (one per line)");
	puts("--ip           IP address or FQDN to scan");
	puts("--speedup      Number of threads to use. Default: 1");
	puts("--scan         Type of scan to use. Default: ALL");
}

static options default_options() {
	options ret;

	ret.host = NULL;
	ret.host_len = 0;
	ret.scans = SCAN_NOTHING;
	ret.threads = 0;
	ret.port = NULL;
	ret.port_len = 0;
	ret.ttl = 64;
	ret.win = UINT16_MAX;
	ret.data = NULL;
	ret.source = 16777343;

	return ret;
}