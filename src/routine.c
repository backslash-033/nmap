/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   routine.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: nguiard <nguiard@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/06/26 17:23:51 by nguiard           #+#    #+#             */
/*   Updated: 2024/06/26 17:47:09 by nguiard          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	*routine(void *thread_arg) {
	tdata_in	data = *((tdata_in *)thread_arg);

	printf("Thread id: %d\n", data.id);
	puts("Exiting thread");

	return NULL;
}