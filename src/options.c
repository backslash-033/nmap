/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   options.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: nguiard <nguiard@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/06/11 14:56:53 by nguiard           #+#    #+#             */
/*   Updated: 2024/06/25 08:47:51 by nguiard          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

#define ARGS_NOTHING	-1
#define ARGS_SPEED		0
#define ARGS_SCANS		1
#define ARGS_PORTS		2
#define ARGS_FILE		3
#define ARGS_IP			4
#define ARGS_HELP		5
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
static uint8_t		get_scan(str scan);
static uint32_t		range_size(str arg);
static uint16_t 	*range_values(str arg, uint32_t *size);
static void			add_range_to_ports(uint16_t *ports, uint32_t *port_amount,
									uint16_t *range, uint32_t range_size);
static uint16_t		*sort_port_range(uint16_t *ports, uint32_t *port_amout);
static bool			add_hostname(options *opts, str hostname);
static host_data	resolve_hostname(const str hostname) ;

typedef bool	(*parsing_function)(options *, str);

static parsing_function handlers[5] = {
	opt_speed,
	opt_scans,
	opt_ports,
	opt_file,
	opt_ip,
};

options options_handling(int argc, char **argv) {
	options res;
	int		args_status = ARGS_NOTHING;

	if (argc == 1) {
		fprintf(stderr, ERROR "No arguments.\n\n");
		print_help_message();
		exit(2);
	}
	res = default_options();

	for (int i = 1; i < argc; i++) {
		if (args_status == ARGS_NOTHING) {
			args_status = get_option(argv[i]);
			if (args_status == ARGS_HELP) {
				print_help_message();
				free_options(&res);
				exit(0);
			}
		} else {
			if (handlers[args_status](&res, argv[i]) == true) {
				fprintf(stderr, ERROR "Error allocating memory\n");
				free_options(&res);
				exit(1);
			}
			args_status = ARGS_NOTHING;
		}
	}

	if (res.scans == SCAN_NOTHING)
		res.scans = SCAN_ALL;
	else if ((res.scans & 0b00111111) == 0b00111111 &&
			!(res.scans & 0x10000000))
		res.scans = SCAN_ALL;

	uint16_t *sorted = sort_port_range(res.port, &res.port_amount);

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

	if (res.host_amout == 0 || res.host == NULL) {
		fprintf(stderr, ERROR "No valid IP address or FQDN provided\n");
		free_options(&res);
		exit(1);
	}

	return res;
}

void	free_options(options *opts) {
	if (opts->port) {
		free(opts->port);
	}
	if (opts->host) {
		for (uint32_t i = 0; i < opts->host_amout; i++) {
			free(opts->host[i].basename);
		}
		free(opts->host);
	}
}

static bool opt_speed(options *opts, str arg) {
	int thread_nb = ft_atoi(arg);
	if (thread_nb > 250 || thread_nb < 0) {
		fprintf(stderr, WARNING "--speedup can only be between 0 and 250 included. "
						"Argument given: %d. "
						"Default to 0 additional threads.\n", thread_nb);
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
	str			*splitted = ft_split(arg, ',');
	uint16_t	*tmp_ports = NULL;
	uint32_t	tmp_port_amount = 0;

	if (splitted == NULL)
		return true;

	for (int i = 0; splitted[i]; i++) {
		errno = 0;
		uint32_t range_size_value = range_size(splitted[i]);

		if (!range_size_value && (unsigned int)errno == RANGE_ALLOCERR) {
			free_darray((void **)splitted);
			return true;
		} else if (!range_size_value && (unsigned int)errno == RANGE_SIZEERR) {
			fprintf(stderr, ERROR "The port range has to be between 0 and 65535 included.\n");
			free_darray((void **)splitted);
			return true;
		}
		size += range_size_value;
	}

	tmp_ports = ft_calloc(sizeof(uint16_t), size > 0x10000 ? 0x10000 : size);
	if (tmp_ports == NULL) {
		free_darray((void **)splitted);
		return true;
	}
	tmp_port_amount = 0;

	for (int i = 0; splitted[i]; i++) {
		errno = 0;
		uint32_t real_size = 0;
		uint16_t *range = range_values(splitted[i], &real_size);

		if (!range && (unsigned int)errno == RANGE_ALLOCERR) {
			free_darray((void **)splitted);
			free(tmp_ports);
			return true;
		} else if (!range && (unsigned int)errno == RANGE_SIZEERR) {
			fprintf(stderr, ERROR "The port range has to be between 0 and 65535 included.\n");
			free_darray((void **)splitted);
			free(tmp_ports);
			return true;
		}

		add_range_to_ports(tmp_ports, &tmp_port_amount, range, real_size);
		free(range);
	}

	if (opts->port == NULL) {
		opts->port = tmp_ports;
		opts->port_amount = tmp_port_amount;
	}
	else {
		uint16_t *merge = ft_calloc(sizeof(uint16_t), opts->port_amount + tmp_port_amount);
		uint32_t merge_size = 0;
		if (merge == NULL) {
			free_darray((void **)splitted);
			free(tmp_ports);
			return true;
		}
		add_range_to_ports(merge, &merge_size, opts->port, opts->port_amount);
		add_range_to_ports(merge, &merge_size, tmp_ports, tmp_port_amount);
		free(opts->port);
		opts->port = merge;
		opts->port_amount = merge_size;
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

static bool	add_hostname(options *opts, const str hostname) {
	host_data	to_add;
	host_data	*tmp;

	to_add = resolve_hostname(hostname);
	if (to_add.basename == NULL) {
		if (errno == ENOMEM)
			return true;
		return false;
	}

	tmp = ft_calloc(opts->host_amout + 1, sizeof(host_data));
	if (tmp == NULL) {
		free(to_add.basename);
		return true;
	}

	if (opts->host != NULL) {
		ft_memcpy(tmp, opts->host, sizeof(host_data) * opts->host_amout);
		free(opts->host);
	}
	opts->host = tmp;
	opts->host[opts->host_amout] = to_add;
	opts->host_amout += 1;
	return false;
}

static host_data	resolve_hostname(const str hostname) {
	host_data		ret;
	struct addrinfo	hints, *result, *result_base;
	char			buff[INET6_ADDRSTRLEN + 1];
	void			*ptr = NULL;

	ft_bzero(&ret, sizeof(host_data));
	ft_bzero(&hints, sizeof(struct addrinfo));
	ft_bzero(buff, INET6_ADDRSTRLEN + 1);

	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_CANONNAME;

	ret.basename = ft_strdup(hostname);
	if (!ret.basename)
		return ret;

	if (getaddrinfo(hostname, NULL, &hints, &result_base)) {
		fprintf(stderr, WARNING "Could not get address info of '%s'\n", hostname);
		free(ret.basename);
		ret.basename = NULL;
		return ret;
	}

	result = result_base;

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
		inet_ntop (result->ai_family, ptr, buff, 100);

		ret.info = *result;
		result = result->ai_next;
	}

	freeaddrinfo(result_base);

	return ret;
}

static uint16_t *sort_port_range(uint16_t *ports, uint32_t *port_amout) {
	uint16_t tmp;

	if (!ports || (port_amout && *port_amout == 0)) {
		if (ports)
			free(ports);
		ports = ft_calloc(1024, sizeof(uint16_t));
		if (!ports) {
			errno = RANGE_ALLOCERR;
			return NULL;
		}
		for (uint16_t i = 1; i < 1025; i++)
			ports[i - 1] = i;
		*port_amout = 1024;
		return ports;
	}

	if (*port_amout > 1024) {
		errno = RANGE_SIZEERR;
		return NULL;
	}

	for (uint32_t _ = 0; _ < *port_amout; _++) {
		for (uint32_t i = 0; i < (*port_amout - 1); i++) {
			if (ports[i] > ports[i + 1]) {
				tmp = ports[i + 1];
				ports[i + 1] = ports[i];
				ports[i] = tmp;
			}
		}
	}

	return ports;
}

static void	add_range_to_ports(uint16_t *ports, uint32_t *port_amount, uint16_t *range, uint32_t range_size) {
	bool	present;
	
	for (uint32_t i = 0; i < range_size; i++) {
		present = false;
		for (uint32_t j = 0; j < (*port_amount); j++) {
			if (ports[j] == range[i]) {
				present = true;
				break;
			}
		}
		if (present == false) {
			ports[(*port_amount)] = range[i];
			(*port_amount)++;
		}
	}
}

static uint32_t	range_size(str arg) {
	int	low = 0;
	int	high = 0xffff;
	char *dash = ft_strchr(arg, '-');

	if (dash == NULL) {
		return 1;
	}
	else if (dash == arg) {
		if (ft_strlen(arg) == 1)
			return high + 1;
		high = ft_atoi(arg + 1);
		if (high < 0 || high > 0xffff) {
			errno = RANGE_SIZEERR;
			return 0;
		}
		return (high + 1);
	}
	else if (dash == arg + ft_strlen(arg) - 1) {
		low = ft_atoi(arg);
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
			low = ft_atoi(range[0]);
			high = ft_atoi(range[1]);
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
	char		*dash = ft_strchr(arg, '-');
	uint16_t	*res = NULL;

	if (dash == NULL) {
		res = ft_calloc(sizeof(uint16_t), 1);
		if (res == NULL) {
			errno = RANGE_ALLOCERR;
			return NULL;
		}
		*size = 1;
		res[0] = ft_atoi(arg);
		return res;
	}
	else if (dash == arg) {
		if (ft_strlen(arg) != 1) {
			high = ft_atoi(arg + 1);
			if (high < 0 || high > 0xffff) {
				errno = RANGE_SIZEERR;
				return NULL;
			}
		}
	}
	else if (dash == arg + ft_strlen(arg) - 1) {
		low = ft_atoi(arg);
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
			low = ft_atoi(range[0]);
			high = ft_atoi(range[1]);
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
	res = ft_calloc(sizeof(uint16_t), high - low + 1);
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

	if (!ft_strncmp(scan, "ALL", 3))
		return SCAN_ALL;
	if (!ft_strncmp(scan, "SYN", 3))
		return SCAN_SYN;
	if (!ft_strncmp(scan, "NULL", 4))
		return SCAN_NULL;
	if (!ft_strncmp(scan, "ACK", 3))
		return SCAN_ACK;
	if (!ft_strncmp(scan, "FIN", 3))
		return SCAN_FIN;
	if (!ft_strncmp(scan, "XMAS", 4))
		return SCAN_XMAS;
	if (!ft_strncmp(scan, "UDP", 3))
		return SCAN_UDP;

	fprintf(stderr, WARNING "Unknown scan type: '%s'\n", scan);
	return SCAN_NOTHING;
}

static int	get_option(char const *arg) {
	if (!arg)
		return ARGS_NOTHING;
	if (ft_strncmp(arg, "--", 2)) {
		fprintf(stderr, WARNING "Could not reckognised option '%s'.\n", arg);
		return ARGS_NOTHING;
	}

	if (ft_strlen(arg) > 2) {
		arg = arg + 2;
		if (!ft_strncmp(arg, "speedup", 7))
			return ARGS_SPEED;
		if (!ft_strncmp(arg, "scan", 4))
			return ARGS_SCANS;
		if (!ft_strncmp(arg, "ports", 5))
			return ARGS_PORTS;
		if (!ft_strncmp(arg, "file", 4))
			return ARGS_FILE;
		if (!ft_strncmp(arg, "ip", 2))
			return ARGS_IP;
		if (!ft_strncmp(arg, "help", 4))
			return ARGS_HELP;
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
	ret.host_amout = 0;
	ret.scans = SCAN_NOTHING;
	ret.threads = 0;
	ret.port = NULL;
	ret.port_amount = 0;

	return ret;
}