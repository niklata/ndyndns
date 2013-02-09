/* checkip.c - checkip-specific functions
 *
 * (C) 2007-2013 Nicholas J. Kain <njkain at gmail dot com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <errno.h>
#include <curl/curl.h>

#include "defines.h"
#include "dns_helpers.h"
#include "log.h"
#include "strl.h"
#include "util.h"
#include "malloc.h"

static time_t last_time = 0;

/* allocates from heap for return;
 * returns NULL if remote host fails to give ip
 */
char *query_curip(void)
{
    conn_data_t data;
    char *ip = NULL, *ret = NULL, *p = NULL;
    int len;
    time_t now;

    now = clock_time();

    /* query no more than once every ten minutes */
    if (now - last_time < 600)
        return ret;

    data.buf = xmalloc(MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1);
    memset(data.buf, '\0', MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1);
    data.buflen = MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1;
    data.idx = 0;

    if (dyndns_curl_send("http://checkip.dyndns.com", &data, NULL)) {
        log_line("Failed to get IP from remote host.");
        goto out;
    }
    last_time = clock_time();

    ip = strstr(data.buf, "Current IP Address:");
    if (!ip)
        goto out;
    ip += strlen("Current IP Address:");
    for (; isspace(*ip); ++ip);

    for (p = ip, len = 0; *p == '.' || isdigit(*p); ++p, ++len);
    if (!len)
        goto out;
    ++len;

    ret = xmalloc(len);
    strlcpy(ret, ip, len);
out:
    free(data.buf);
    return ret;
}

