/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: nguiard <nguiard@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/06/06 13:54:44 by nguiard           #+#    #+#             */
/*   Updated: 2024/06/19 16:44:58 by nguiard          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

int main(int argc, char **argv) {
	options opt;

	opt = options_handling(argc, argv);

	printf("Number of threads: %d\n", opt.threads);
	printf("Scans: A.UXFANS\n");
	printf("       ");
	for (int i = 0x80; i != 0; i >>= 1)
		putc(i & opt.scans ? 'X': ' ', stdout);

	printf("\n");

	for (uint32_t i = 0; i != opt.port_amount; i++) {
		printf("%hu ", opt.ports[i]);
	}
	printf("\n");

	free_options(&opt);
}