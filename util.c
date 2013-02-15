/* util.c - utility functions
 *
 * Copyright (c) 2005-2013 Nicholas J. Kain <njkain at gmail dot com>
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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>

#include "util.h"
#include "log.h"

void null_crlf(char *data) {
    char *p = data;

    while (*p != '\0') {
        if (*p != '\r' && *p != '\n') {
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

    for (j=0; data->idx < data->buflen - 1 && j < size*nmemb; ++data->idx, ++j)
        data->buf[data->idx] = buf[j];
    data->buf[data->idx + 1] = '\0';

    return j;
}

time_t clock_time(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts))
        suicide("%s: clock_gettime failed: %s", __func__, strerror(errno));
    return ts.tv_sec;
}

