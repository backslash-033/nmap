/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   options.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: nguiard <nguiard@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/06/11 14:56:53 by nguiard           #+#    #+#             */
/*   Updated: 2024/06/12 11:19:31 by nguiard          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

#define ARGS_NOTHING	-1
#define ARGS_SPEED		0
#define ARGS_SCANS		1
#define ARGS_PORTS		2
#define ARGS_FILE		3
#define ARGS_IP			4
#define SCAN_NOTHING	0
#define SCAN_SYN		0b00000001
#define SCAN_NULL		0b00000010
#define SCAN_ACK		0b00000100
#define SCAN_FIN		0b00001000
#define SCAN_XMAS		0b00010000
#define SCAN_UDP		0b00100000
#define SCAN_ALL		0b10111111

static void		print_help_message();
static options	default_options();
static int		get_option(char const *arg);
static bool		opt_speed(options *opts, str arg);
static bool		opt_scans(options *opts, str arg);
static bool		opt_ports(options *opts, str arg);
static bool		opt_file(options *opts, str arg);
static bool		opt_ip(options *opts, str arg);
static uint8_t	get_scan(str scan);

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
		fprintf(stderr, "Error: no arguments.\n\n");
		print_help_message();
		exit(2);
	}
	res = default_options();

	for (int i = 1; i < argc; i++) {
		if (args_status == ARGS_NOTHING) {
			args_status = get_option(argv[i]);
		} else {
			if (handlers[args_status](&res, argv[i])) {
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

	return res;
}

void	free_options(options *opts) {
	if (opts->ports) {
		free(opts->ports);
	}
}

static bool opt_speed(options *opts, str arg) {
	int thread_nb = ft_atoi(arg);
	if (thread_nb > 250 || thread_nb < 0) {
		fprintf(stderr, "\033[33mWarning:\033[0m --speedup can only be between 0 and 250 included. "
						"Argument given: %d. "
						"Defaulting to 0 additional threads.\n", thread_nb);
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

	opts->scans |= scans;
	return false;
}

static bool opt_ports(options *opts, str arg) {
	(void)opts;
	printf("in opt_ports: %s\n", arg);
	return false;
}

static bool opt_file(options *opts, str arg) {
	(void)opts;
	printf("in opt_file: %s\n", arg);
	return false;
}

static bool opt_ip(options *opts, str arg) {
	(void)opts;
	printf("in opt_ip: %s\n", arg);
	return false;
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

	fprintf(stderr, "\033[33mWarning:\033[0m Unknown scan type: '%s'\n", scan);
	return SCAN_NOTHING;
}

static int	get_option(char const *arg) {
	if (!arg)
		return ARGS_NOTHING;
	if (ft_strncmp(arg, "--", 2)) {
		fprintf(stderr, "Could not reckognised option '%s'.\n", arg);
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
		fprintf(stderr, "Could not reckognised option '%s'.\n", arg - 2);
		return ARGS_NOTHING;
	}

	fprintf(stderr, "Could not reckognised option '%s'.\n", arg);
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
	puts("--file         File name to read the list of IP addresses from");
	puts("--ip           IP address of FQDN to scan");
	puts("--speedup      Number of threads to use. Default: 1");
	puts("--scan         Type of scan to use. Default: ALL");
}

static options default_options() {
	options ret;

	ret.addresses = NULL;
	ret.scans = SCAN_NOTHING;
	ret.threads = 0;
	ret.ports = NULL;
	ret.port_amount = 0;

	return ret;
}