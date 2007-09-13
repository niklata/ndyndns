/* checkip.c - checkip-specific functions
 *
 * (C) 2007 Nicholas J. Kain <njk@aerifal.cx>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <curl/curl.h>

#include "defines.h"
#include "log.h"
#include "nstrl.h"
#include "util.h"

static time_t last_time = 0;

/* allocates from heap for return;
 * returns NULL if remote host fails to give ip
 */
char *query_curip(void)
{
	CURL *h;
	CURLcode ret;
	char curlerror[CURL_ERROR_SIZE];
	conn_data_t data;
	char *ip = NULL, *retval = NULL, *p = NULL;
	int len;
	time_t now;

	now = time(NULL);

	/* query no more than once every ten minutes */
	if (now - last_time < 600)
	    return retval;

	data.buf = xmalloc(MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1);
	memset(data.buf, '\0', MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1);
	data.buflen = MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1;
	data.idx = 0;

	h = curl_easy_init();
	curl_easy_setopt(h, CURLOPT_URL, "http://checkip.dyndns.com");
	curl_easy_setopt(h, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	curl_easy_setopt(h, CURLOPT_ERRORBUFFER, curlerror);
	curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_response);
	curl_easy_setopt(h, CURLOPT_WRITEDATA, &data);
	ret = curl_easy_perform(h);
	curl_easy_cleanup(h);

	last_time = time(NULL);

	if (ret != CURLE_OK) {
		log_line("Failed to get ip from remote: [%s]\n", curlerror);
		goto out;
	}

	ip = strstr(data.buf, "Current IP Address: ");
	if (!ip)
	    goto out;
	ip += strlen("Current IP Address: ");

	for (p = ip, len = 0; *p != '\0' && *p != '<'; ++p, ++len);
	if (!len)
	    goto out;
	++len;

	retval = xmalloc(len);
	strlcpy(retval, ip, len);
out:
	free(data.buf);
	return retval;
}

