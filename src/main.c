/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: nguiard <nguiard@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/06/06 13:54:44 by nguiard           #+#    #+#             */
/*   Updated: 2024/06/12 12:42:52 by nguiard          ###   ########.fr       */
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

	free_options(&opt);
}