/* dns_he.c
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
#include "dns_he.h"
#include "dns_helpers.h"
#include "log.h"
#include "util.h"
#include "strl.h"
#include "malloc.h"

he_conf_t he_conf;

void init_he_conf()
{
    he_conf.userid = NULL;
    he_conf.passhash = NULL;
    he_conf.hostpairs = NULL;
    he_conf.tunlist = NULL;
}

static void modify_he_hostip_in_list(hostdata_t *t, char *host, char *ip)
{
    if (!t || !host)
        return;
    for (; t && strcmp(t->host, host); t = t->next);
    if (t) {
        free(t->ip);
        t->ip = NULL;
        if (ip) {
            size_t len = strlen(ip) + 1;
            char *buf = xmalloc(len);
            strnkcpy(buf, ip, len);
            t->ip = buf;
        }
    }
}

static void modify_he_hostip_in_conf(he_conf_t *conf, char *host, char *ip)
{
    if (conf)
        modify_he_hostip_in_list(conf->hostpairs, host, ip);
}

static void modify_he_hostdate_in_list(hostdata_t *t, char *host, time_t time)
{
    if (!t || !host)
        return;
    for (; t && strcmp(t->host, host); t = t->next);
    if (t)
        t->date = time;
}

static void modify_he_hostdate_in_conf(he_conf_t *conf, char *host, time_t time)
{
    if (conf)
        modify_he_hostdate_in_list(conf->hostpairs, host, time);
}

static void he_update_host(char *host, char *password, char *curip)
{
    char url[MAX_BUF];
    conn_data_t data;

    if (!host || !password || !curip)
        return;

    /* set up the authentication url */
    if (use_ssl)
        DDCB_CPY(url, "https://");
    else
        DDCB_CPY(url, "http://");

    DDCB_CAT(url, host);
    DDCB_CAT(url, ":");
    DDCB_CAT(url, password);

    DDCB_CAT(url, "@dyn.dns.he.net/nic/update?hostname=");
    DDCB_CAT(url, host);

    DDCB_CAT(url, "&myip=");
    DDCB_CAT(url, curip);

    data.buf = xmalloc(MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1);
    memset(data.buf, '\0', MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1);
    data.buflen = MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1;
    data.idx = 0;

    if (!dyndns_curl_send(url, &data, NULL)) {
        // "good x.x.x.x" is success
        log_line("response returned: [%s]", data.buf);
        if (strstr(data.buf, "good")) {
            log_line("%s: [good] - Update successful.", host);
            write_dnsip(host, curip);
            write_dnsdate(host, clock_time());
            modify_he_hostdate_in_conf(&he_conf, host, clock_time());
            modify_he_hostip_in_conf(&he_conf, host, curip);
        } else {
            log_line("%s: [fail] - Failed to update.", host);
        }
    }
    free(data.buf);
}

void he_dns_work(char *curip)
{
    char host[MAX_BUF], *pass, *p;
    for (hostdata_t *tp = he_conf.hostpairs; tp != NULL; tp = tp->next) {
        if (strcmp(curip, tp->ip)) {
            if (strnkcpy(host, tp->host, sizeof host))
                goto too_short;
            if (strnkcat(host, ":", sizeof host))
                goto too_short;
            if (strnkcat(host, tp->password, sizeof host)) {
too_short:
                log_line("he_dns_work: host+password is too long");
                continue;
            }
            p = strchr(host, ':');
            if (!p)
                continue;
            *p = '\0';
            pass = p + 1;
            log_line("adding for update [%s]", host);
            he_update_host(host, pass, curip);
        }
    }
}

static void he_update_tunid(char *tunid, char *curip)
{
    char url[MAX_BUF];
    conn_data_t data;

    if (!tunid || !curip)
        return;

    /* set up the authentication url */
    if (use_ssl)
        DDCB_CPY(url, "https");
    else
        DDCB_CPY(url, "http");
    DDCB_CAT(url, "://ipv4.tunnelbroker.net/ipv4_end.php?ip=");
    DDCB_CAT(url, curip);
    DDCB_CAT(url, "&pass=");
    DDCB_CAT(url, he_conf.passhash);
    DDCB_CAT(url, "&apikey=");
    DDCB_CAT(url, he_conf.userid);
    DDCB_CAT(url, "&tid=");
    DDCB_CAT(url, tunid);

    data.buf = xmalloc(MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1);
    memset(data.buf, '\0', MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1);
    data.buflen = MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1;
    data.idx = 0;

    if (!dyndns_curl_send(url, &data, NULL)) {
        // "+OK: Tunnel endpoint updated to: x.x.x.x" is success
        log_line("response returned: [%s]", data.buf);
        if (strstr(data.buf, "+OK")) {
            log_line("%s: [good] - Update successful.", tunid);
            write_dnsip(tunid, curip);
            write_dnsdate(tunid, clock_time());
            modify_he_hostdate_in_list(he_conf.tunlist, tunid, clock_time());
            modify_he_hostip_in_list(he_conf.tunlist, tunid, curip);
        } else if (strstr(data.buf, "-ERROR: This tunnel is already associated with this IP address.")) {
            log_line("%s: [nochg] - Unnecessary update; further updates will be considered abusive." , tunid);
            write_dnsip(tunid, curip);
            write_dnsdate(tunid, clock_time());
        } else if (strstr(data.buf, "abuse")) {
            log_line("[%s] has a configuration problem.  Refusing to update until %s-dnserr is removed.", tunid, tunid);
            write_dnserr(tunid, -2);
            remove_host_from_hostdata_list(&he_conf.tunlist, tunid);
        } else {
            log_line("%s: [fail] - Failed to update.", tunid);
        }
    }
    free(data.buf);
}

void he_tun_work(char *curip)
{
    for (hostdata_t *t = he_conf.tunlist; t != NULL; t = t->next) {
        if (strcmp(curip, t->ip)) {
            log_line("adding for update [%s]", t->host);
            he_update_tunid(t->host, curip);
        }
    }
}

