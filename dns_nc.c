/* dns_nc.c
 *
 * Copyright (c) 2010-2013 Nicholas J. Kain <njkain at gmail dot com>
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

#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#include "config.h"
#include "defines.h"
#include "dns_nc.h"
#include "dns_helpers.h"
#include "log.h"
#include "util.h"
#include "strl.h"
#include "malloc.h"

namecheap_conf_t namecheap_conf;

void init_namecheap_conf()
{
    namecheap_conf.password = NULL;
    namecheap_conf.hostlist = NULL;
}

static void modify_nc_hostip_in_list(namecheap_conf_t *conf, char *host,
                                     char *ip)
{
    hostdata_t *t;
    size_t len;
    char *buf;

    if (!conf || !host || !conf->hostlist)
        return;

    for (t = conf->hostlist; t && strcmp(t->host, host); t = t->next);

    if (!t)
        return; /* not found */

    free(t->ip);
    if (!ip) {
        t->ip = ip;
        return;
    }
    len = strlen(ip) + 1;
    buf = xmalloc(len);
    strnkcpy(buf, ip, len);
    t->ip = buf;
}

static void modify_nc_hostdate_in_list(namecheap_conf_t *conf, char *host,
                                       time_t time)
{
    hostdata_t *t;

    if (!conf || !host || !conf->hostlist)
        return;

    for (t = conf->hostlist; t && strcmp(t->host, host); t = t->next);

    if (!t)
        return; /* not found */

    t->date = time;
}

static void nc_update_host(char *host, char *curip)
{
    int hostname_size = 0, domain_size = 0, dotc = 0;
    char url[MAX_BUF];
    char *hostname = NULL, *domain = NULL;
    size_t ic;
    conn_data_t data;

    if (!host || !curip)
        return;

    ic = strlen(host);
    if (strnkcpy(url, host, sizeof url)) {
        log_line("nc_update_host: hostname is too long");
        return;
    }
    for (; ic > 0; --ic) {
        if (url[ic] == '.') {
            ++dotc;
            if (dotc == 2) {
                // This is the . before the domain name.
                domain_size = strlen(url+ic+1) + 1;
                domain = xmalloc(domain_size);
                strnkcpy(domain, url+ic+1, domain_size);
                url[ic] = '\0';
            }
        }
    }
    if (dotc >= 2) {
        hostname_size = strlen(url) + 1;
        hostname = xmalloc(hostname_size);
        strnkcpy(hostname, url, hostname_size);
    } else {
        domain_size = strlen(url) + 1;
        domain = xmalloc(domain_size);
        strnkcpy(domain, url, domain_size);
        hostname_size = 2;
        hostname = xmalloc(hostname_size);
        hostname[0] = '@';
        hostname[1] = '\0';
    }
    memset(url, 0, sizeof url);

    /* set up the authentication url */
    if (use_ssl)
        DDCB_CPY(url, "https");
    else
        DDCB_CPY(url, "http");
    DDCB_CAT(url, "://dynamicdns.park-your-domain.com/update?");
    DDCB_CAT(url, "host=");
    DDCB_CAT(url, hostname);
    DDCB_CAT(url, "&domain=");
    DDCB_CAT(url, domain);
    DDCB_CAT(url, "&password=");
    DDCB_CAT(url, namecheap_conf.password);
    DDCB_CAT(url, "&ip=");
    DDCB_CAT(url, curip);

    data.buf = xmalloc(MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1);
    memset(data.buf, '\0', MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1);
    data.buflen = MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1;
    data.idx = 0;

    if (!dyndns_curl_send(url, &data, NULL)) {
        log_line("response returned: [%s]", data.buf);
        if (strstr(data.buf, "<ErrCount>0")) {
            log_line("%s: [good] - Update successful.", host);
            write_dnsip(host, curip);
            write_dnsdate(host, clock_time());
            modify_nc_hostdate_in_list(&namecheap_conf, host, clock_time());
            modify_nc_hostip_in_list(&namecheap_conf, host, curip);
        } else {
            log_line("%s: [fail] - Failed to update.", host);
        }
    }
    free(data.buf);
    free(hostname);
    free(domain);
}

void nc_work(char *curip)
{
    for (hostdata_t *t = namecheap_conf.hostlist; t != NULL; t = t->next) {
        if (strcmp(curip, t->ip)) {
            log_line("adding for update [%s]", t->host);
            nc_update_host(t->host, curip);
        }
    }
}


