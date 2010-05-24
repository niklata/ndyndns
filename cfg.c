/* cfg.c - configuration file functions
 *
 * (C) 2005-2010 Nicholas J. Kain <njkain at gmail dot com>
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "defines.h"
#include "cfg.h"
#include "util.h"
#include "log.h"
#include "nstrl.h"
#include "chroot.h"

void remove_host_from_host_data_list(dyndns_conf_t *conf, char *host)
{
    host_data_t *cur = conf->hostlist, *after = NULL, *p;

    if (!strcmp(cur->host, host)) {
        after = cur->next;
        free(cur->host);
        free(cur->ip);
        free(cur);
        conf->hostlist = after;
    }
    for (; cur->next != NULL; cur = cur->next) {
        p = cur->next;
        if(!strcmp(p->host, host)) {
            after = p->next;
            free(p->host);
            free(p->ip);
            free(p);
            p = after;
        }
    }
}

/* allocates memory for return or returns NULL; returns error string
 * or NULL if the host is OK to update. */
static char *get_dnserr(char *host)
{
    FILE *f;
    char buf[MAX_BUF], *file, *ret = NULL;
    int len;

    if (!host)
        suicide("FATAL - get_dnserr: host is NULL\n");

    memset(buf, '\0', MAX_BUF);

    len = strlen(get_chroot()) + strlen(host) + strlen("-dnserr") + 2;
    file = xmalloc(len);
    strlcpy(file, get_chroot(), len);
    strlcat(file, "/", len);
    strlcat(file, host, len);
    strlcat(file, "-dnserr", len);

    f = fopen(file, "r");
    free(file);

    if (!f)
        goto out;

    if (!fgets(buf, sizeof buf, f)) {
        log_line("%s-dnserr is empty.  Assuming error: [unknown].\n", host);
        ret = xmalloc(sizeof "unknown" + 1);
        strlcpy(ret, "unknown", sizeof "unknown" + 1);
        goto outfd;
    }

    len = strlen(buf) + 1;
    ret = xmalloc(len);
    strlcpy(ret, buf, len);
outfd:
    fclose(f);
out:
    return ret;
}


/* allocates memory.  ip may be NULL */
static void add_to_host_data_list(host_data_t **list, char *host, char *ip,
                    time_t time)
{
    host_data_t *item, *t;
    char *elem, *err = NULL;
    size_t len;

    if (!list || !host) return;

    err = get_dnserr(host);
    if (err) {
        log_line("host:[%s] is locked because of error:[%s].  Correct the problem and remove [%s-dnserr] to allow update.\n", host, err, host);
        free(err);
        return;
    }

    item = xmalloc(sizeof (host_data_t));
    item->date = time;
    item->next = NULL;
    item->ip = NULL;

    len = strlen(host) + 1;
    elem = xmalloc(len);
    strlcpy(elem, host, len);
    item->host = elem;

    if (!ip || !item->host) {
        if (item->host) {
            log_line("[%s] has no ip address.  No updates will be performed for [%s].", host, host);
        } else {
            log_line("[%s] has no host name.  Your configuration file has a problem.", ip, ip);
        }
        goto out;
    }

    len = strlen(ip) + 1;
    elem = xmalloc(len);
    strlcpy(elem, ip, len);
    item->ip = elem;

    if (!*list) {
        *list = item;
        return;
    }

    t = *list;
    while (t) {
        if (!t->next) {
            t->next = item;
            return;
        }
        t = t->next;
    }
    log_line("add_to_host_data_list: coding error\n");
out:
    free(item->host);
    free(item->ip);
    free(item);
}

void modify_hostip_in_list(dyndns_conf_t *conf, char *host, char *ip)
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

void modify_hostdate_in_list(dyndns_conf_t *conf, char *host, time_t time)
{
    host_data_t *t;

    if (!conf || !host || !conf->hostlist)
        return;

    for (t = conf->hostlist; t && strcmp(t->host, host); t = t->next);

    if (!t)
        return; /* not found */

    t->date = time;
}

void modify_nc_hostip_in_list(namecheap_conf_t *conf, char *host, char *ip)
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

void modify_nc_hostdate_in_list(namecheap_conf_t *conf, char *host, time_t time)
{
    host_data_t *t;

    if (!conf || !host || !conf->hostlist)
        return;

    for (t = conf->hostlist; t && strcmp(t->host, host); t = t->next);

    if (!t)
        return; /* not found */

    t->date = time;
}

static time_t get_dnsdate(char *host)
{
    FILE *f;
    char buf[MAX_BUF], *file;
    size_t len;
    time_t ret = 0;

    if (!host)
        suicide("FATAL - get_dnsdate: host is NULL\n");

    len = strlen(get_chroot()) + strlen(host) + strlen("-dnsdate") + 2;
    file = xmalloc(len);
    strlcpy(file, get_chroot(), len);
    strlcat(file, "/", len);
    strlcat(file, host, len);
    strlcat(file, "-dnsdate", len);

    f = fopen(file, "r");
    free(file);

    if (!f) {
        log_line("No existing %s-dnsdate.  Assuming date == 0.\n",
             host);
        goto out;
    }

    if (!fgets(buf, sizeof buf, f)) {
        log_line("%s-dnsdate is empty.  Assuming date == 0.\n", host);
        goto outfd;
    }

    ret = (time_t)atol(buf);
    if (ret < 0)
        ret = 0;
outfd:
    fclose(f);
out:
    return ret;
}

/* allocates memory for return or returns NULL */
static char *lookup_dns(char *name) {
    struct hostent *hent;
    char *ret = NULL, *t = NULL;
    int len;

    if (!name)
        suicide("FATAL - lookup_dns: host is NULL!\n");

    hent = gethostbyname(name);
    if (hent == NULL) {
        switch (h_errno) {
        case HOST_NOT_FOUND:
            log_line(
            "failed to resolve %s: host not found.\n", name);
            break;
        case NO_ADDRESS:
            log_line(
            "failed to resolve %s: no IP for host.\n", name);
            break;
        case NO_RECOVERY:
        default:
            log_line(
            "failed to resolve %s: non-recoverable error.\n", name);
            break;
        case TRY_AGAIN:
            log_line(
            "failed to resolve %s: temporary error on an authoritative nameserver.\n", name);
            break;
        }
        goto out;
    }

    t = inet_ntoa(*((struct in_addr *)hent->h_addr));
    log_line("lookup_dns: returned [%s]\n", t);

    len = strlen(t) + 1;
    ret = xmalloc(len);
    strlcpy(ret, t, len);
out:
    return ret;
}

/* allocates memory for return or returns NULL */
static char *get_dnsip(char *host)
{
    FILE *f;
    char buf[MAX_BUF], *file, *ret = NULL;
    int len;
    struct in_addr inr;

    if (!host)
        suicide("FATAL - get_dnsip: host is NULL\n");

    memset(buf, '\0', MAX_BUF);

    len = strlen(get_chroot()) + strlen(host) + strlen("-dnsip") + 2;
    file = xmalloc(len);
    strlcpy(file, get_chroot(), len);
    strlcat(file, "/", len);
    strlcat(file, host, len);
    strlcat(file, "-dnsip", len);

    f = fopen(file, "r");
    free(file);

    if (!f) {
        log_line("No existing %s-dnsip.  Querying DNS.\n", host);
        ret = lookup_dns(host);
        goto out;
    }

    if (!fgets(buf, sizeof buf, f)) {
        log_line("%s-dnsip is empty.  Querying DNS.\n", host);
        ret = lookup_dns(host);
        goto outfd;
    }

    if (inet_aton(buf, &inr) == 0) {
        log_line("%s-dnsip is corrupt.  Querying DNS.\n", host);
        ret = lookup_dns(host);
        goto outfd;
    }

    len = strlen(buf) + 1;
    ret = xmalloc(len);
    strlcpy(ret, buf, len);
outfd:
    fclose(f);
out:
    return ret;
}

static void do_populate(host_data_t **list, char *host)
{
    char *ip;

    if (strlen(host)) {
        ip = get_dnsip(host);
        if (ip) {
            log_line("adding: [%s] ip: [%s]\n", host, ip);
            add_to_host_data_list(list, host, ip, get_dnsdate(host));
        } else {
            log_line("No ip found for [%s].  No updates will be done.", host);
        }
        free(ip);
    }
}

static void populate_hostlist(host_data_t **list, char *hostname)
{
    char *left = hostname, *right = (char *)1, *t = NULL;
    size_t len;

    if (!list || !left)
        suicide("NULL passed to populate_hostlist()\n");
    if (strlen(left) == 0) {
        suicide("No hostnames were provided for updates.  Exiting.");
    }

    log_line("hostname: [%s]\n", left);

    do {
        right = strchr(left, ',');
        if (right != NULL && left < right) {
            len = right - left + 1;
            t = xmalloc(len);
            memset(t, '\0', len);
            memcpy(t, left, len - 1);
            do_populate(list, t);
            free(t);
            left = right + 1;
        } else {
            do_populate(list, left);
            break;
        }
    } while (1);
}

void init_dyndns_conf(dyndns_conf_t *t)
{
    t->username = NULL;
    t->password = NULL;
    t->hostlist = NULL;
    t->mx = NULL;
    t->wildcard = WC_NOCHANGE;
    t->backmx = BMX_NOCHANGE;
    t->offline = OFFLINE_NO;
    t->system = SYSTEM_DYNDNS;
}

void init_namecheap_conf(namecheap_conf_t *t)
{
    t->password = NULL;
    t->hostlist = NULL;
}

/* returns 1 for valid config, 0 for invalid */
static int validate_dyndns_conf(dyndns_conf_t *t)
{
    if ((!!t->username == !!t->password) != !!t->hostlist) {
        if (t->username == NULL) {
            log_line("config file invalid: no username provided\n");
            return 0;
        }
        if (t->password == NULL) {
            log_line("config file invalid: no password provided\n");
            return 0;
        }
        if (t->hostlist == NULL) {
            log_line("config file invalid: no hostnames provided\n");
            return 0;
        }
    }
    if (t->username)
        return 1;
    else
        return 0;
}

/* returns 1 for valid config, 0 for invalid */
static int validate_nc_conf(namecheap_conf_t *t)
{
    if (!!t->password != !!t->hostlist) {
        if (t->password == NULL) {
            log_line("config file invalid: no password provided\n");
            return 0;
        }
        if (t->hostlist == NULL) {
            log_line("config file invalid: no hostnames provided\n");
            return 0;
        }
    }
    if (t->password)
        return 1;
    else
        return 0;
}

static char *parse_line_string(char *line, char *key)
{
    char *point = NULL, *ret = NULL;
    int len;

    null_crlf(line);
    point = line;
    if (strncmp(point, key, strlen(key)))
        goto out;

    point += strlen(key);
    if (*point != '=')
        goto out;
    ++point;
    len = strlen(point) + 1;
    ret = xmalloc(len);
    strlcpy(ret, point, len);
out:
    return ret;
}

/* returns 1 if assignment made, 0 if not */
static int assign_string(char **to, char *from)
{
    int ret = 0;

    if (from) {
        if (*to)
            free(*to);
        *to = from;
        ret = 1;
    }

    return ret;
}

enum prs_state {
    PRS_NONE,
    PRS_CONFIG,
    PRS_DYNDNS,
    PRS_NAMECHEAP
};

#define PRS_CONFIG_STR "[config]"
#define PRS_DYNDNS_STR "[dyndns]"
#define PRS_NAMECHEAP_STR "[namecheap]"
#define NOWILDCARD_STR "nowildcard"
#define WILDCARD_STR "wildcard"
#define PRIMARYMX_STR "primarymx"
#define BACKUPMX_STR "backupmx"
#define OFFLINE_STR "offline"
#define DYNDNS_STR "dyndns"
#define CUSTOMDNS_STR "customdns"
#define STATICDNS_STR "staticdns"

void parse_warn(unsigned int lnum, char *name)
{
    log_line("WARNING: config line %d: %s statement not valid in section\n", lnum, name);
}

/* if file is NULL, then read stdin */
int parse_config(char *file, dyndns_conf_t *dc, namecheap_conf_t *nc)
{
    FILE *f;
    char buf[MAXLINE];
    int ret = -1;
    unsigned int lnum = 0;
    char *point, *tmp;
    enum prs_state prs = PRS_NONE;

    if (file) {
        f = fopen(file, "r");
        if (!f) {
            log_line("FATAL: parse_config: failed to open [%s] for \
                             read\n", file);
            exit(EXIT_FAILURE);
        }
    } else {
        f = fdopen(0, "r");
        if (!f) {
            log_line("FATAL: parse_config: failed to open stdin for \
                             read\n");
            exit(EXIT_FAILURE);
        }
    }

    while (!feof(f)) {
        if (!fgets(buf, sizeof buf, f))
            break;
        ++lnum;

        log_line("parse line: [%s]\n", buf);

        point = buf;
        while (*point == ' ' || *point == '\t')
            ++point;

        if (!strncmp(PRS_CONFIG_STR, point, sizeof PRS_CONFIG_STR - 1)) {
            prs = PRS_CONFIG;
            log_line("line %d: section is now CONFIG", lnum);
            continue;
        }
        if (!strncmp(PRS_DYNDNS_STR, point, sizeof PRS_DYNDNS_STR - 1)) {
            prs = PRS_DYNDNS;
            log_line("line %d: section is now DYNDNS", lnum);
            continue;
        }
        if (!strncmp(PRS_NAMECHEAP_STR, point, sizeof PRS_NAMECHEAP_STR - 1)) {
            prs = PRS_NAMECHEAP;
            log_line("line %d: section is now NAMECHEAP", lnum);
            continue;
        }

        tmp = parse_line_string(point, "password");
        if (tmp) {
            switch (prs) {
                default:
                    parse_warn(lnum, "password");
                    break;
                case PRS_DYNDNS:
                    assign_string(&dc->password, tmp);
                    log_line("config line %d: read dc password [%s]", lnum, tmp);
                    break;
                case PRS_NAMECHEAP:
                    assign_string(&nc->password, tmp);
                    log_line("config line %d: read nc password [%s]", lnum, tmp);
                    break;
            }
            free(tmp);
            continue;
        }

        tmp = parse_line_string(point, "hosts");
        if (tmp) {
            switch (prs) {
                default:
                    parse_warn(lnum, "hosts");
                    break;
                case PRS_DYNDNS:
                    populate_hostlist(&dc->hostlist, tmp);
                    log_line("config line %d: read dc hosts [%s]", lnum, tmp);
                    break;
                case PRS_NAMECHEAP:
                    populate_hostlist(&nc->hostlist, tmp);
                    log_line("config line %d: read nc hosts [%s]", lnum, tmp);
                    break;
            }
            free(tmp);
            continue;
        }

        tmp = parse_line_string(point, "username");
        if (tmp) {
            switch (prs) {
                default:
                    parse_warn(lnum, "username");
                    break;
                case PRS_DYNDNS:
                    assign_string(&dc->username, tmp);
                    log_line("config line %d: read dc username [%s]", lnum, tmp);
                    break;
            }
            free(tmp);
            continue;
        }

        tmp = parse_line_string(point, "mx");
        if (tmp) {
            switch (prs) {
                default:
                    parse_warn(lnum, "mx");
                    break;
                case PRS_DYNDNS:
                    assign_string(&dc->mx, tmp);
                    log_line("config line %d: read dc mx [%s]", lnum, tmp);
                    break;
            }
            free(tmp);
            continue;
        }

        if (!strncmp(NOWILDCARD_STR, point, sizeof NOWILDCARD_STR - 1)) {
            switch (prs) {
                default:
                    parse_warn(lnum, "nowildcard");
                    break;
                case PRS_DYNDNS:
                    log_line("config line %d: read dc nowildcard", lnum);
                    dc->wildcard = WC_NO;
                    break;
            }
            continue;
        }
        if (!strncmp(WILDCARD_STR, point, sizeof WILDCARD_STR - 1)) {
            switch (prs) {
                default:
                    parse_warn(lnum, "wildcard");
                    break;
                case PRS_DYNDNS:
                    log_line("config line %d: read dc wildcard", lnum);
                    dc->wildcard = WC_YES;
                    break;
            }
            continue;
        }
        if (!strncmp(PRIMARYMX_STR, point, sizeof PRIMARYMX_STR - 1)) {
            switch (prs) {
                default:
                    parse_warn(lnum, "primarymx");
                    break;
                case PRS_DYNDNS:
                    log_line("config line %d: read dc primarymx", lnum);
                    dc->backmx = BMX_NO;
                    break;
            }
            continue;
        }
        if (!strncmp(BACKUPMX_STR, point, sizeof BACKUPMX_STR - 1)) {
            switch (prs) {
                default:
                    parse_warn(lnum, "backupmx");
                    break;
                case PRS_DYNDNS:
                    log_line("config line %d: read dc backupmx", lnum);
                    dc->backmx = BMX_YES;
                    break;
            }
            continue;
        }
        if (!strncmp(OFFLINE_STR, point, sizeof OFFLINE_STR - 1)) {
            switch (prs) {
                default:
                    parse_warn(lnum, "offline");
                    break;
                case PRS_DYNDNS:
                    log_line("config line %d: read dc offline", lnum);
                    dc->offline = OFFLINE_YES;
                    break;
            }
            continue;
        }
        if (!strncmp(DYNDNS_STR, point, sizeof DYNDNS_STR - 1)) {
            switch (prs) {
                default:
                    parse_warn(lnum, "dyndns");
                    break;
                case PRS_DYNDNS:
                    log_line("config line %d: read dc dyndns", lnum);
                    dc->system = SYSTEM_DYNDNS;
                    break;
            }
            continue;
        }
        if (!strncmp(CUSTOMDNS_STR, point, sizeof CUSTOMDNS_STR - 1)) {
            switch (prs) {
                default:
                    parse_warn(lnum, "customdns");
                    break;
                case PRS_DYNDNS:
                    log_line("config line %d: read dc customdns", lnum);
                    dc->system = SYSTEM_CUSTOMDNS;
                    break;
            }
            continue;
        }
        if (!strncmp(STATICDNS_STR, point, sizeof STATICDNS_STR - 1)) {
            switch (prs) {
                default:
                    parse_warn(lnum, "staticdns");
                    break;
                case PRS_DYNDNS:
                    log_line("config line %d: read dc staticdns", lnum);
                    dc->system = SYSTEM_STATDNS;
                    break;
            }
            continue;
        }

    }

    if (fclose(f)) {
        log_line("parse_config: failed to close [%s]\n", file);
        exit(EXIT_FAILURE);
    }
    ret = validate_dyndns_conf(dc) | validate_nc_conf(nc);
    return ret;
}
