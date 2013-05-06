/* checkip.c - checkip-specific functions
 *
 * Copyright (c) 2007-2013 Nicholas J. Kain <njkain at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
    strnkcpy(ret, ip, len);
out:
    free(data.buf);
    return ret;
}

