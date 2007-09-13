/* util.h
   (C) 2005-2007 Nicholas J. Kain <njk@aerifal.cx>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   version 2.1 as published by the Free Software Foundation.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA */

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

