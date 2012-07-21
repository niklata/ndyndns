/* (c) 2005-2012 Nicholas J. Kain <njkain at gmail dot com>
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
#include <ctype.h>
#include <curl/curl.h>

#include "config.h"
#include "defines.h"
#include "dns_dyn.h"
#include "dns_helpers.h"
#include "log.h"
#include "util.h"
#include "strl.h"
#include "strlist.h"
#include "malloc.h"

dyndns_conf_t dyndns_conf;

void init_dyndns_conf()
{
    dyndns_conf.username = NULL;
    dyndns_conf.password = NULL;
    dyndns_conf.hostlist = NULL;
    dyndns_conf.mx = NULL;
    dyndns_conf.wildcard = WC_NOCHANGE;
    dyndns_conf.backmx = BMX_NOCHANGE;
    dyndns_conf.offline = OFFLINE_NO;
    dyndns_conf.system = SYSTEM_DYNDNS;
}

static void modify_dyn_hostip_in_list(dyndns_conf_t *conf, char *host, char *ip)
{
    host_data_t *t;
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

static void modify_dyn_hostdate_in_list(dyndns_conf_t *conf, char *host,
                                        time_t time)
{
    host_data_t *t;

    if (!conf || !host || !conf->hostlist)
        return;

    for (t = conf->hostlist; t && strcmp(t->host, host); t = t->next);

    if (!t)
        return; /* not found */

    t->date = time;
}

typedef struct {
    return_codes code;
    void *next;
} return_code_list_t;

static return_code_list_t *dd_return_list = NULL;
static strlist_t *dd_update_list = NULL;

static void add_to_return_code_list(return_codes name,
                                    return_code_list_t **list)
{
    return_code_list_t *item, *t;

    if (!list)
        return;

    item = xmalloc(sizeof (return_code_list_t));
    item->code = name;
    item->next = NULL;

    if (!*list) {
        *list = item;
        return;
    }
    t = *list;
    while (t) {
        if (t->next == NULL) {
            t->next = item;
            return;
        }
        t = t->next;
    }

    log_line("%s: failed to add item", __func__);
    free(item);
}

static void free_return_code_list(return_code_list_t *head)
{
    return_code_list_t *p = head, *q = NULL;

    while (p != NULL) {
        q = p;
        p = q->next;
        free(q);
    }
}

int get_return_code_list_arity(return_code_list_t *list)
{
    int i;
    return_code_list_t *c;

    for (c = list, i = 0; c != NULL; c = c->next, ++i);
    return i;
}

/* not really well documented, so here:
 * return from the server will be stored in a buffer
 * buffer will look like:
 good 1.12.123.9
 nochg 1.12.123.9
 nochg 1.12.123.9
 nochg 1.12.123.9
*/
static void decompose_buf_to_list(char *buf)
{
    char tok[MAX_BUF], *point = buf;
    size_t i;

    free_return_code_list(dd_return_list);
    dd_return_list = NULL;

    while (*point != '\0') {
        while (*point != '\0' && isspace(*point))
            point++;
        memset(tok, '\0', sizeof tok);

        /* fetch one token */
        i = 0;
        while (i < sizeof tok && *point != '\0' && !isspace(*point))
            tok[i++] = *(point++);

        if (strstr(tok, "badsys")) {
            add_to_return_code_list(RET_BADSYS, &dd_return_list);
            continue;
        }
        if (strstr(tok, "badagent")) {
            add_to_return_code_list(RET_BADAGENT, &dd_return_list);
            continue;
        }
        if (strstr(tok, "badauth")) {
            add_to_return_code_list(RET_BADAUTH, &dd_return_list);
            continue;
        }
        if (strstr(tok, "!donator")) {
            add_to_return_code_list(RET_NOTDONATOR, &dd_return_list);
            continue;
        }
        if (strstr(tok, "good")) {
            add_to_return_code_list(RET_GOOD, &dd_return_list);
            continue;
        }
        if (strstr(tok, "nochg")) {
            add_to_return_code_list(RET_NOCHG, &dd_return_list);
            continue;
        }
        if (strstr(tok, "notfqdn")) {
            add_to_return_code_list(RET_NOTFQDN, &dd_return_list);
            continue;
        }
        if (strstr(tok, "nohost")) {
            add_to_return_code_list(RET_NOHOST, &dd_return_list);
            continue;
        }
        if (strstr(tok, "!yours")) {
            add_to_return_code_list(RET_NOTYOURS, &dd_return_list);
            continue;
        }
        if (strstr(tok, "abuse")) {
            add_to_return_code_list(RET_ABUSE, &dd_return_list);
            continue;
        }
        if (strstr(tok, "numhost")) {
            add_to_return_code_list(RET_NUMHOST, &dd_return_list);
            continue;
        }
        if (strstr(tok, "dnserr")) {
            add_to_return_code_list(RET_DNSERR, &dd_return_list);
            continue;
        }
        if (strstr(tok, "911")) {
            add_to_return_code_list(RET_911, &dd_return_list);
            continue;
        }
    }
}

/* -1 indicates hard error, -2 soft error on hostname, 0 success */
static int postprocess_update(char *host, char *curip, return_codes retcode)
{
    int ret = -2;

    switch (retcode) {
        default:
            log_line("%s: FATAL: %s has invalid state", host, __func__);
            ret = -1;
            break;
        case RET_BADSYS:
            log_line("%s: [badsys] - FATAL: Should never happen!", host);
            break;
        case RET_BADAGENT:
            log_line("%s: [badagent] - FATAL: Client program is banned!", host);
            break;
        case RET_BADAUTH:
            log_line("%s: [badauth] - FATAL: Invalid username or password.", host);
            break;
        case RET_NOTDONATOR:
            log_line("%s: [!donator] - FATAL: Option requested that is only allowed to donating users (such as 'offline').", host);
            break;
        case RET_NOTFQDN:
            log_line("%s: [notfqdn] - FATAL: Hostname isn't a fully-qualified domain name (such as 'hostname.dyndns.org')'.", host);
            break;
        case RET_NOHOST:
            log_line("%s: [nohost] - FATAL: Hostname doesn't exist or wrong service type specified (dyndns, static, custom).", host);
            break;
        case RET_NOTYOURS:
            log_line("%s: [!yours] - FATAL: Hostname exists, but doesn't belong to your account.", host);
            break;
        case RET_ABUSE:
            log_line("%s: [abuse] - FATAL: Hostname is banned for abuse.", host);
            break;
        case RET_NUMHOST:
            log_line("%s: [numhost] - FATAL: Too many or too few hosts found.", host);
            break;
        case RET_DNSERR:
            log_line("%s: [dnserr] - FATAL: DNS error encountered by server.", host);
            break;
        case RET_911:
            log_line("%s: [911] - FATAL: Critical error on dyndns.org's hardware.  Check http://www.dyndns.org/news/status/ for details.", host);
            break;
            /* Don't hardfail, 'success' */
        case RET_GOOD:
            log_line("%s: [good] - Update successful.", host);
            write_dnsip(host, curip);
            write_dnsdate(host, mono_time());
            ret = 0;
            break;
        case RET_NOCHG:
            log_line("%s: [nochg] - Unnecessary update; further updates will be considered abusive.", host);
            write_dnsip(host, curip);
            write_dnsdate(host, mono_time());
            ret = 0;
            break;
    }
    return ret;
}

static void dyndns_update_ip(char *curip)
{
    CURL *h;
    CURLcode ret;
    int len, runonce = 0;
    char url[MAX_BUF];
    char tbuf[32];
    char unpwd[256];
    char useragent[64];
    char curlerror[CURL_ERROR_SIZE];
    strlist_t *t;
    return_code_list_t *u;
    int ret2;
    conn_data_t data;

    if (!dd_update_list || !curip)
        return;

    /* set up the authentication url */
    if (use_ssl) {
        len = strlcpy(url,
                      "https://members.dyndns.org/nic/update?", sizeof url);
        update_ip_buf_error(len, sizeof url);
    } else {
        len = strlcpy(url,
                      "http://members.dyndns.org/nic/update?", sizeof url);
        update_ip_buf_error(len, sizeof url);
    }

    switch (dyndns_conf.system) {
        case SYSTEM_STATDNS:
            strlcpy(tbuf, "statdns", sizeof tbuf);
            break;
        case SYSTEM_CUSTOMDNS:
            strlcpy(tbuf, "custom", sizeof tbuf);
            break;
        default:
            strlcpy(tbuf, "dyndns", sizeof tbuf);
            break;
    }
    len = strlcat(url, "system=", sizeof url);
    update_ip_buf_error(len, sizeof url);
    len = strlcat(url, tbuf, sizeof url);
    update_ip_buf_error(len, sizeof url);

    len = strlcat(url, "&hostname=", sizeof url);
    update_ip_buf_error(len, sizeof url);
    for (t = dd_update_list, runonce = 0; t != NULL; t = t->next) {
        if (runonce) {
            len = strlcat(url, ",", sizeof url);
            update_ip_buf_error(len, sizeof url);
        }
        runonce = 1;
        len = strlcat(url, t->str, sizeof url);
        update_ip_buf_error(len, sizeof url);
    }

    len = strlcat(url, "&myip=", sizeof url);
    update_ip_buf_error(len, sizeof url);
    len = strlcat(url, curip, sizeof url);
    update_ip_buf_error(len, sizeof url);

    switch (dyndns_conf.wildcard) {
        case WC_YES:
            strlcpy(tbuf, "ON", sizeof tbuf);
            break;
        case WC_NO:
            strlcpy(tbuf, "OFF", sizeof tbuf);
            break;
        default:
            strlcpy(tbuf, "NOCHG", sizeof tbuf);
            break;
    }
    len = strlcat(url, "&wildcard=", sizeof url);
    update_ip_buf_error(len, sizeof url);
    len = strlcat(url, tbuf, sizeof url);
    update_ip_buf_error(len, sizeof url);

    len = strlcat(url, "&mx=", sizeof url);
    update_ip_buf_error(len, sizeof url);
    if (dyndns_conf.mx == NULL) {
        len = strlcat(url, "NOCHG", sizeof url);
        update_ip_buf_error(len, sizeof url);
    } else {
        len = strlcat(url, dyndns_conf.mx, sizeof url);
        update_ip_buf_error(len, sizeof url);
    }

    switch (dyndns_conf.backmx) {
        case BMX_YES:
            strlcpy(tbuf, "YES", sizeof tbuf);
            break;
        case BMX_NO:
            strlcpy(tbuf, "NO", sizeof tbuf);
            break;
        default:
            strlcpy(tbuf, "NOCHG", sizeof tbuf);
            break;
    }
    len = strlcat(url, "&backmx=", sizeof url);
    update_ip_buf_error(len, sizeof url);
    len = strlcat(url, tbuf, sizeof url);
    update_ip_buf_error(len, sizeof url);

    switch (dyndns_conf.offline) {
        case OFFLINE_YES:
            strlcpy(tbuf, "YES", sizeof tbuf);
            break;
        default:
            strlcpy(tbuf, "NO", sizeof tbuf);
            break;
    }
    len = strlcat(url, "&offline=", sizeof url);
    update_ip_buf_error(len, sizeof url);
    len = strlcat(url, tbuf, sizeof url);
    update_ip_buf_error(len, sizeof url);


    /* set up username:password pair */
    len = strlcpy(unpwd, dyndns_conf.username, sizeof unpwd);
    update_ip_buf_error(len, sizeof unpwd);
    len = strlcat(unpwd, ":", sizeof unpwd);
    update_ip_buf_error(len, sizeof unpwd);
    len = strlcat(unpwd, dyndns_conf.password, sizeof unpwd);
    update_ip_buf_error(len, sizeof unpwd);


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
    curl_easy_setopt(h, CURLOPT_USERPWD, unpwd);
    curl_easy_setopt(h, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(h, CURLOPT_USERAGENT, useragent);
    curl_easy_setopt(h, CURLOPT_ERRORBUFFER, curlerror);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_response);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &data);
    if (use_ssl)
        curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, (long)0);
    ret = curl_easy_perform(h);
    curl_easy_cleanup(h);

    if (update_ip_curl_errcheck(ret, curlerror) == 1)
        goto out;

    decompose_buf_to_list(data.buf);
    if (get_strlist_arity(dd_update_list) !=
        get_return_code_list_arity(dd_return_list)) {
        log_line("list arity doesn't match, updates may be suspect");
    }

    for (t = dd_update_list, u = dd_return_list;
         t != NULL && u != NULL; t = t->next, u = u->next) {

        ret2 = postprocess_update(t->str, curip, u->code);
        switch (ret2) {
            case -1:
            default:
                exit(EXIT_FAILURE);
                break;
            case -2:
                log_line("[%s] has a configuration problem.  Refusing to update until %s-dnserr is removed.", t->str, t->str);
                write_dnserr(t->str, ret2);
                remove_host_from_host_data_list(&dyndns_conf.hostlist, t->str);
                break;
            case 0:
                modify_dyn_hostdate_in_list(&dyndns_conf, t->str, mono_time());
                modify_dyn_hostip_in_list(&dyndns_conf, t->str, curip);
                break;
        }
    }
  out:
    free(data.buf);
}

#define DYN_REFRESH_INTERVAL (28*24*3600 + 60)
void dd_work(char *curip)
{
    free_strlist(dd_update_list);
    free_return_code_list(dd_return_list);
    dd_update_list = NULL;
    dd_return_list = NULL;

    for (host_data_t *t = dyndns_conf.hostlist; t != NULL; t = t->next) {
        if (strcmp(curip, t->ip)) {
            log_line("adding for update [%s]", t->host);
            add_to_strlist(&dd_update_list, t->host);
            continue;
        }
        if (dyndns_conf.system == SYSTEM_DYNDNS &&
            mono_time() - t->date > DYN_REFRESH_INTERVAL) {
            log_line("adding for refresh [%s]", t->host);
            add_to_strlist(&dd_update_list, t->host);
        }
    }
    if (dd_update_list)
        dyndns_update_ip(curip);
}

