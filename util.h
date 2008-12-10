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

#ifndef __NJK_UTIL_H_
#define __NJK_UTIL_H_ 1
typedef struct {
	char *buf;
	size_t buflen;
	size_t idx;
} conn_data_t;

void *xmalloc(size_t size);
void null_crlf(char *data);
size_t write_response(char *buf, size_t size, size_t nmemb, void *dat);
#endif

