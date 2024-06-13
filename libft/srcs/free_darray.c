/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   free_tabtab.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: nguiard <nguiard@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/05/05 13:03:15 by nguiard           #+#    #+#             */
/*   Updated: 2024/06/13 11:48:58 by nguiard          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

/*	free() un double tableau de n'importe quelle sorte	*/
void	free_darray(void **dtab)
{
	int	i;

	i = 0;
	while (dtab[i])
	{
		free(dtab[i]);
		i++;
	}
	free(dtab);
}
