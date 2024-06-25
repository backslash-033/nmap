/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   threads.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: nguiard <nguiard@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/06/25 08:53:47 by nguiard           #+#    #+#             */
/*   Updated: 2024/06/25 19:04:43 by nguiard          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static tdata_in			*build_chunks(const options opt, uint8_t *th_amount);
static host_and_port	*every_host_and_port(const options opt, uint32_t *size);
static void				free_chunks(tdata_in *chunks, uint8_t size);

void	threads(const options opt) {
	tdata_in	*chunks;
	uint8_t		th_amount = NEVER_ZERO(opt.threads);
	tdata_out	*out;

	chunks = build_chunks(opt, &th_amount);

	out = ft_calloc(th_amount, sizeof(tdata_out));
	if (out == NULL) {
		free_chunks(chunks, th_amount);
		return;
	}

	for (int i = 0; i < th_amount; i++)
		chunks[i].output = out;

	free_chunks(chunks, th_amount);
	free(out);
}

static void	free_chunks(tdata_in *chunks, uint8_t size) {
	for (int i = 0; i < size; i++) {
		for (uint32_t j = 0; j < chunks[i].hnp_len; j++)
			free_host_data(chunks[i].hnp[j].host);
		free(chunks[i].hnp);
	}
	free(chunks);
}

static tdata_in	*build_chunks(const options opt, uint8_t *th_amount) {
	host_and_port	*raw_hnp;
	uint32_t		raw_hnp_len = 0;
	uint32_t		per_thread;
	tdata_in		*res = NULL;

	raw_hnp = every_host_and_port(opt, &raw_hnp_len);

	per_thread = raw_hnp_len / NEVER_ZERO(opt.threads);

	*th_amount = per_thread ? opt.threads : raw_hnp_len;

	if (per_thread == 0) {
		res = ft_calloc(raw_hnp_len + 1, sizeof(tdata_in));
		if (res == NULL) {
			free(raw_hnp);
			return NULL;
		}
		for (uint32_t i = 0; i < raw_hnp_len; i++) {
			res[i].hnp = ft_calloc(1, sizeof(host_and_port));
			if (res[i].hnp == NULL) {
				free_chunks(res, i);
				return NULL;
			}
			res[i].hnp[0] = raw_hnp[i];
			res[i].hnp[0].host.basename = ft_strdup(raw_hnp[i].host.basename);
			res[i].hnp_len = 1;
			res[i].id = i;
			res[i].scans = opt.scans;
		}
	} else {
		uint8_t more = raw_hnp_len % NEVER_ZERO(opt.threads);

		res = ft_calloc(NEVER_ZERO(opt.threads), sizeof(host_and_port));
		if (res == NULL) {
			free(raw_hnp);
			return NULL;
		}
		*th_amount = NEVER_ZERO(opt.threads);
		for (uint8_t i = 0; i < more; i++) {
			res[i].hnp = ft_calloc(per_thread + 1, sizeof(host_and_port));
			if (res[i].hnp == NULL) {
				free_chunks(res, i);
				return NULL;
			}
			for (uint32_t j = 0; j < per_thread + 1; j++) {
				res[i].hnp[j] = raw_hnp[i * (per_thread + 1) + j];
				res[i].hnp[j].host.basename = ft_strdup(raw_hnp[i * (per_thread + 1) + j].host.basename);
			}
			res[i].hnp_len = per_thread + 1;
			res[i].id = i;
			res[i].scans = opt.scans;
		}
		for (uint8_t i = more; i < *th_amount; i++) {
			uint32_t already_filled = more * (per_thread + 1) + (i - more) * per_thread;
			res[i].hnp = ft_calloc(per_thread, sizeof(host_and_port));
			if (res[i].hnp == NULL) {
				free_chunks(res, i);
				return NULL;
			}
			for (uint32_t j = 0; j < per_thread; j++) {
				res[i].hnp[j] = raw_hnp[already_filled + j];
				res[i].hnp[j].host.basename = ft_strdup(raw_hnp[already_filled + j].host.basename);
			}
			res[i].hnp_len = per_thread;
			res[i].id = i;
			res[i].scans = opt.scans;
		}
	}

	free(raw_hnp);
	return res;
}

static host_and_port *every_host_and_port(const options opt, uint32_t *size) {
	host_and_port	*res;
	uint32_t		i = 0;
	host_and_port	tmp;

	res = ft_calloc(opt.host_len * opt.port_len, sizeof(host_and_port));
	if (res == NULL)
		return NULL;

	*size = opt.host_len * opt.port_len;

	for (uint32_t h = 0; h < opt.host_len; h++) {
		tmp.host = opt.host[h];
		for (uint32_t p = 0; p < opt.port_len; p++) {
			tmp.port = opt.port[p];
			res[i] = tmp;
			i++;
		}
	}

	return res;
}
