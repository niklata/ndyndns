/* (c) 2010-2012 Nicholas J. Kain <njkain at gmail dot com>
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

static void modify_he_hostip_in_list(he_conf_t *conf, char *host, char *ip)
{
    hostpairs_t *t;
    size_t len;
    char *buf;

    if (!conf || !host || !conf->hostpairs)
        return;

    for (t = conf->hostpairs; t && strcmp(t->host, host); t = t->next);

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

static void modify_he_hostdate_in_list(he_conf_t *conf, char *host, time_t time)
{
    hostpairs_t *t;

    if (!conf || !host || !conf->hostpairs)
        return;

    for (t = conf->hostpairs; t && strcmp(t->host, host); t = t->next);

    if (!t)
        return; /* not found */

    t->date = time;
}

static void he_update_host(char *host, char *password, char *curip)
{
    CURL *h;
    CURLcode ret;
    int len;
    char url[MAX_BUF];
    char useragent[64];
    char curlerror[CURL_ERROR_SIZE];
    conn_data_t data;

    if (!host || !password || !curip)
        return;

    /* set up the authentication url */
    if (use_ssl) {
        len = strlcpy(url, "https://", sizeof url);
        update_ip_buf_error(len, sizeof url);
    } else {
        len = strlcpy(url, "http://", sizeof url);
        update_ip_buf_error(len, sizeof url);
    }

    len = strlcat(url, host, sizeof url);
    update_ip_buf_error(len, sizeof url);
    len = strlcat(url, ":", sizeof url);
    update_ip_buf_error(len, sizeof url);
    len = strlcat(url, password, sizeof url);
    update_ip_buf_error(len, sizeof url);

    len = strlcat(url, "@dyn.dns.he.net/nic/update?hostname=", sizeof url);
    update_ip_buf_error(len, sizeof url);
    len = strlcat(url, host, sizeof url);
    update_ip_buf_error(len, sizeof url);

    len = strlcat(url, "&myip=", sizeof url);
    update_ip_buf_error(len, sizeof url);
    len = strlcat(url, curip, sizeof url);
    update_ip_buf_error(len, sizeof url);

    /* set up useragent */
    len = strlcpy(useragent, "ndyndns/", sizeof useragent);
    update_ip_buf_error(len, sizeof useragent);
    len = strlcat(useragent, PACKAGE_VERSION, sizeof useragent);
    update_ip_buf_error(len, sizeof useragent);

    data.buf = xmalloc(MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1);
    memset(data.buf, '\0', MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1);
    data.buflen = MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1;
    data.idx = 0;

    log_line("update url: [%s]", url);
    h = curl_easy_init();
    curl_easy_setopt(h, CURLOPT_URL, url);
    curl_easy_setopt(h, CURLOPT_USERAGENT, useragent);
    curl_easy_setopt(h, CURLOPT_ERRORBUFFER, curlerror);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_response);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &data);
    curl_easy_setopt(h, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_easy_setopt(h, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    if (use_ssl)
        curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, (long)0);
    ret = curl_easy_perform(h);
    curl_easy_cleanup(h);

    if (update_ip_curl_errcheck(ret, curlerror))
        goto out;

    // "good x.x.x.x" is success
    log_line("response returned: [%s]", data.buf);
    if (strstr(data.buf, "good")) {
        log_line("%s: [good] - Update successful.", host);
        write_dnsip(host, curip);
        write_dnsdate(host, clock_time());
        modify_he_hostdate_in_list(&he_conf, host, clock_time());
        modify_he_hostip_in_list(&he_conf, host, curip);
    } else {
        log_line("%s: [fail] - Failed to update.", host);
    }

  out:
    free(data.buf);
}

void he_dns_work(char *curip)
{
    for (hostpairs_t *tp = he_conf.hostpairs; tp != NULL; tp = tp->next) {
        if (strcmp(curip, tp->ip)) {
            size_t csiz = strlen(tp->host) + strlen(tp->password) + 2;
            char *host = alloca(csiz), *pass, *p;
            strlcpy(host, tp->host, csiz);
            strlcat(host, ":", csiz);
            strlcat(host, tp->password, csiz);
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
    CURL *h;
    CURLcode ret;
    int len;
    char url[MAX_BUF];
    char useragent[64];
    char curlerror[CURL_ERROR_SIZE];
    conn_data_t data;

    if (!tunid || !curip)
        return;

    /* set up the authentication url */
    if (use_ssl) {
        len = strlcpy(url, "https", sizeof url);
        update_ip_buf_error(len, sizeof url);
    } else {
        len = strlcpy(url, "http", sizeof url);
        update_ip_buf_error(len, sizeof url);
    }

    len = strlcat(url, "://ipv4.tunnelbroker.net/ipv4_end.php?ip=", sizeof url);
    update_ip_buf_error(len, sizeof url);
    len = strlcat(url, curip, sizeof url);
    update_ip_buf_error(len, sizeof url);

    len = strlcat(url, "&pass=", sizeof url);
    update_ip_buf_error(len, sizeof url);
    len = strlcat(url, he_conf.passhash, sizeof url);
    update_ip_buf_error(len, sizeof url);

    len = strlcat(url, "&apikey=", sizeof url);
    update_ip_buf_error(len, sizeof url);
    len = strlcat(url, he_conf.userid, sizeof url);
    update_ip_buf_error(len, sizeof url);

    len = strlcat(url, "&tid=", sizeof url);
    update_ip_buf_error(len, sizeof url);
    len = strlcat(url, tunid, sizeof url);
    update_ip_buf_error(len, sizeof url);

    /* set up useragent */
    len = strlcpy(useragent, "ndyndns/", sizeof useragent);
    update_ip_buf_error(len, sizeof useragent);
    len = strlcat(useragent, PACKAGE_VERSION, sizeof useragent);
    update_ip_buf_error(len, sizeof useragent);

    data.buf = xmalloc(MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1);
    memset(data.buf, '\0', MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1);
    data.buflen = MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1;
    data.idx = 0;

    log_line("update url: [%s]", url);
    h = curl_easy_init();
    curl_easy_setopt(h, CURLOPT_URL, url);
    curl_easy_setopt(h, CURLOPT_USERAGENT, useragent);
    curl_easy_setopt(h, CURLOPT_ERRORBUFFER, curlerror);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_response);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &data);
    curl_easy_setopt(h, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_easy_setopt(h, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    if (use_ssl)
        curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, (long)0);
    ret = curl_easy_perform(h);
    curl_easy_cleanup(h);

    if (update_ip_curl_errcheck(ret, curlerror) == 1)
        goto out;

    // "+OK: Tunnel endpoint updated to: x.x.x.x" is success
    log_line("response returned: [%s]", data.buf);
    if (strstr(data.buf, "+OK")) {
        log_line("%s: [good] - Update successful.", tunid);
        write_dnsip(tunid, curip);
        write_dnsdate(tunid, clock_time());
    } else if (strstr(data.buf, "-ERROR: This tunnel is already associated with this IP address.")) {
        log_line("%s: [nochg] - Unnecessary update; further updates will be considered abusive." , tunid);
        write_dnsip(tunid, curip);
        write_dnsdate(tunid, clock_time());
    } else if (strstr(data.buf, "abuse")) {
        log_line("[%s] has a configuration problem.  Refusing to update until %s-dnserr is removed.", tunid, tunid);
        write_dnserr(tunid, -2);
        remove_host_from_host_data_list(&he_conf.tunlist, tunid);
    } else {
        log_line("%s: [fail] - Failed to update.", tunid);
    }

  out:
    free(data.buf);
}

void he_tun_work(char *curip)
{
    for (host_data_t *t = he_conf.tunlist; t != NULL; t = t->next) {
        if (strcmp(curip, t->ip)) {
            log_line("adding for update [%s]", t->host);
            he_update_tunid(t->host, curip);
        }
    }
}

