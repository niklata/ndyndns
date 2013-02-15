/* dns_helpers.h - common functions for dynamic dns service updates
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

#ifndef NDYNDNS_DNS_HELPERS_H_
#define NDYNDNS_DNS_HELPERS_H_

#include <stdbool.h>
#include "util.h" /* for conn_data_t */

extern int use_ssl;

typedef enum {
    RET_DO_NOTHING,
    RET_BADSYS,
    RET_BADAGENT,
    RET_BADAUTH,
    RET_NOTDONATOR,
    RET_GOOD,
    RET_NOCHG,
    RET_NOTFQDN,
    RET_NOHOST,
    RET_NOTYOURS,
    RET_ABUSE,
    RET_NUMHOST,
    RET_DNSERR,
    RET_911
} return_codes;

void write_dnsdate(char *host, time_t date);
void write_dnsip(char *host, char *ip);
void write_dnserr(char *host, return_codes code);
void dyndns_curlbuf_cpy(char *dst, char *src, size_t size);
void dyndns_curlbuf_cat(char *dst, char *src, size_t size);
int dyndns_curl_send(char *url, conn_data_t *data, char *unpwd);

#define DDCB_CPY(dst, src) do { \
    dyndns_curlbuf_cpy(dst, src, sizeof dst); } while (0)
#define DDCB_CAT(dst, src) do { \
    dyndns_curlbuf_cat(dst, src, sizeof dst); } while (0)

#endif
