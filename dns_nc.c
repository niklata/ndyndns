/* (c) 2010-2013 Nicholas J. Kain <njkain at gmail dot com>
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
    strlcpy(buf, ip, len);
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
    int hostname_size = 0, domain_size = 0;
    char url[MAX_BUF];
    char *hostname = NULL, *domain = NULL, *p;
    conn_data_t data;

    if (!host || !curip)
        return;

    p = strrchr(host, '.');
    if (!p)
        return;
    p = strrchr(p+1, '.');
    if (!p) {
        domain_size = strlen(host) + 1;
        hostname_size = 2;
        hostname = alloca(hostname_size);
        hostname[0] = '@';
        hostname[1] = '\0';
        domain = host;
    } else {
        hostname_size = p - host + 1;
        domain_size = hostname + strlen(host) - p;
        hostname = alloca(hostname_size);
        domain = alloca(domain_size);
        strlcpy(hostname, host, hostname_size);
        strlcpy(domain, p+1, domain_size);
    }

    if (!hostname || !domain)
        return;

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


