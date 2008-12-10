/* util.c - utility functions
 *
 * (C) 2005-2007 Nicholas J. Kain <njkain at gmail dot com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>

#include "util.h"
#include "log.h"

void *xmalloc(size_t size) {
	void *ret;

	ret = malloc(size);
	if (ret == NULL)
		suicide("FATAL - malloc() failed\n");
	return ret;
}

void null_crlf(char *data) {
	char *p = data;

	while (*p != '\0') {
		if (isalnum(*p) || ispunct(*p)) {
			++p;
			continue;
		}
		*p = '\0';
		++p;
	}
}

size_t write_response(char *buf, size_t size, size_t nmemb, void *dat)
{
	conn_data_t *data = (conn_data_t *)dat;
	size_t j;

	for (j=0; data->idx < data->buflen - 1 && j < size*nmemb;
			 ++data->idx, ++j)
		data->buf[data->idx] = buf[j];
	data->buf[data->idx + 1] = '\0';

	return j;
}

