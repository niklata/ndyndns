/* cfg.c - configuration file functions
 *
 * (C) 2005-2011 Nicholas J. Kain <njkain at gmail dot com>
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
#include "strl.h"
#include "chroot.h"
#include "malloc.h"
#include "ndyndns.h"

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

    len = strlen(get_chroot()) + strlen(host) + strlen("-dnserr") + 6;
    file = xmalloc(len);
    strlcpy(file, get_chroot(), len);
    strlcat(file, "/var/", len);
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
            log_line("[%s] has no host name.  Your configuration file has a problem.", ip);
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

/* allocates memory.  ip may be NULL */
static void add_to_hostpair_list(hostpairs_t **list, char *host, char *passwd,
                                 char *ip, time_t time)
{
    hostpairs_t *item, *t;
    char *elem, *err = NULL;
    size_t len;

    if (!list || !host || !passwd) return;

    err = get_dnserr(host);
    if (err) {
        log_line("host:[%s] is locked because of error:[%s].  Correct the problem and remove [%s-dnserr] to allow update.\n", host, err, host);
        free(err);
        return;
    }

    item = xmalloc(sizeof (hostpairs_t));
    item->date = time;
    item->next = NULL;
    item->ip = NULL;

    len = strlen(host) + 1;
    elem = xmalloc(len);
    strlcpy(elem, host, len);
    item->host = elem;

    len = strlen(passwd) + 1;
    elem = xmalloc(len);
    strlcpy(elem, passwd, len);
    item->password = elem;

    len = strlen(ip) + 1;
    elem = xmalloc(len);
    strlcpy(elem, ip, len);
    item->ip = elem;

    if (!ip) {
        log_line("[%s] has no ip address.  No updates will be performed for [%s].", host, host);
        goto out;
    } else if (!item->host) {
        log_line("[%s] has no host name.  Your configuration file has a problem.", ip);
        goto out;
    } else if (!item->password) {
        log_line("[%s] has no password.  Your configuration file has a problem.", ip);
        goto out;
    }

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
    log_line("add_to_hostpair_list: coding error\n");
out:
    free(item->host);
    free(item->password);
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

void modify_he_hostip_in_list(he_conf_t *conf, char *host, char *ip)
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

void modify_he_hostdate_in_list(he_conf_t *conf, char *host, time_t time)
{
    hostpairs_t *t;

    if (!conf || !host || !conf->hostpairs)
        return;

    for (t = conf->hostpairs; t && strcmp(t->host, host); t = t->next);

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

    len = strlen(get_chroot()) + strlen(host) + strlen("-dnsdate") + 6;
    file = xmalloc(len);
    strlcpy(file, get_chroot(), len);
    strlcat(file, "/var/", len);
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

    len = strlen(get_chroot()) + strlen(host) + strlen("-dnsip") + 6;
    file = xmalloc(len);
    strlcpy(file, get_chroot(), len);
    strlcat(file, "/var/", len);
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

static void do_populate(host_data_t **list, char *host_in)
{
    char *ip, *host, *host_orig;

    host = strdup(host_in);
    host_orig = host;
    while (*host == ' ' || *host == '\t')
        ++host;

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
    free(host_orig);
}

static void do_populate_hp(hostpairs_t **list, char *pair_in)
{
    char *ip, *host, *host_orig, *passwd;

    host = strdup(pair_in);
    host_orig = host;
    while (*host == ' ' || *host == '\t')
        ++host;
    passwd = host;
    while (*passwd != ':' && *passwd != '\0')
        ++passwd;
    if (*passwd == ':') {
        *passwd = '\0';
        ++passwd;
    }

    if (strlen(host) && strlen(passwd)) {
        ip = get_dnsip(host);
        if (ip) {
            log_line("adding: [%s] ip: [%s]\n", host, ip);
            add_to_hostpair_list(list, host, passwd, ip, get_dnsdate(host));
        } else {
            log_line("No ip found for [%s].  No updates will be done.", host);
        }
        free(ip);
    }
    free(host_orig);
}

static void populate_hostlist(host_data_t **list, char *hostname)
{
    char *left = hostname, *right = (char *)1, *t = NULL, *p;
    size_t len;

    if (!list || !left)
        suicide("NULL passed to populate_hostlist()\n");
    if (strlen(left) == 0) {
        suicide("No hosts were provided for updates.  Exiting.");
    }

    log_line("hosts: [%s]\n", left);

    do {
        right = strchr(left, ',');
        if (right != NULL && left < right) {
            for (p = left; p < right; ++p) {
                if (*p == ' ' || *p == '\t')
                    break;
            }
            len = p - left + 1;
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

static void populate_hostpairs(hostpairs_t **list, char *hostpair)
{
    char *left = hostpair, *right = (char *)1, *t = NULL, *p;
    size_t len;

    if (!list || !left)
        suicide("NULL passed to populate_hostlist()\n");
    if (strlen(left) == 0) {
        suicide("No hostpairs were provided for updates.  Exiting.");
    }

    do {
        right = strchr(left, ',');
        if (right != NULL && left < right) {
            for (p = left; p < right; ++p) {
                if (*p == ' ' || *p == '\t')
                    break;
            }
            len = p - left + 1;
            t = xmalloc(len);
            memset(t, '\0', len);
            memcpy(t, left, len - 1);
            do_populate_hp(list, t);
            free(t);
            left = right + 1;
        } else {
            do_populate_hp(list, left);
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

void init_he_conf(he_conf_t *t)
{
    t->userid = NULL;
    t->passhash = NULL;
    t->hostpairs = NULL;
    t->tunlist = NULL;
}

/* returns 1 for valid config, 0 for invalid */
static int validate_dyndns_conf(dyndns_conf_t *t)
{
    int r = 1;
    if (t->username || t->password || t->hostlist) {
        if (t->username == NULL) {
            r = 0;
            log_line("dyndns config invalid: no username provided\n");
        }
        if (t->password == NULL) {
            r = 0;
            log_line("dyndns config invalid: no password provided\n");
        }
        if (t->hostlist == NULL) {
            r = 0;
            log_line("dyndns config invalid: no hostnames provided\n");
        }
    }
    return r;
}

/* returns 1 for valid config, 0 for invalid */
static int validate_nc_conf(namecheap_conf_t *t)
{
    int r = 1;
    if (t->password || t->hostlist) {
        if (t->password == NULL) {
            r = 0;
            log_line("namecheap config invalid: no password provided\n");
        }
        if (t->hostlist == NULL) {
            r = 0;
            log_line("namecheap config invalid: no hostnames provided\n");
        }
    }
    return r;
}

/* returns 1 for valid config, 0 for invalid */
static int validate_he_conf(he_conf_t *t)
{
    int r = 1;
    if (t->tunlist == NULL && t->hostpairs == NULL) {
        r = 0;
        log_line("he config invalid: no tunnelids or hostpairs provided\n");
    } else if (t->tunlist) {
        if (t->userid == NULL) {
            r = 0;
            log_line("he config invalid: no userid provided\n");
        }
        if (t->passhash == NULL) {
            r = 0;
            log_line("he config invalid: no passhash provided\n");
        }
    }
    return r;
}

static char *parse_line_string(char *line, char *key)
{
    char *point = NULL, *ret = NULL;
    int len, foundeq = 0;

    null_crlf(line);
    point = line;
    if (strncmp(point, key, strlen(key)))
        goto out;

    point += strlen(key);
    while (1) {
        if (*point == ' ' || *point == '\t') {
            ++point;
        } else if (*point == '=') {
            foundeq = 1;
            ++point;
        } else {
            break;
        }
    }
    if (!foundeq)
        goto out;
    len = strlen(point);
    while (1) {
        if (*(point+len-1) == ' ' || *(point+len-1) == '\t') {
            if (len - 1 >= 0)
                *(point+len-1) = '\0';
            if (len > 0)
                --len;
            else
                break;
        }
        else
            break;
    }
    ret = xmalloc(len + 1);
    strlcpy(ret, point, len + 1);
out:
    return ret;
}

/*
 * Returns 1 if assignment made, 0 if not.
 * Creates a new copy of @from on success.
 */
static int assign_string(char **to, char *from)
{
    int ret = 0;

    if (from) {
        if (*to)
            free(*to);
        *to = strdup(from);
        ret = 1;
    }

    return ret;
}

enum prs_state {
    PRS_NONE,
    PRS_CONFIG,
    PRS_DYNDNS,
    PRS_NAMECHEAP,
    PRS_HE,
};

#define PRS_CONFIG_STR "[config]"
#define PRS_DYNDNS_STR "[dyndns]"
#define PRS_NAMECHEAP_STR "[namecheap]"
#define PRS_HE_STR "[he]"
#define NOWILDCARD_STR "nowildcard"
#define WILDCARD_STR "wildcard"
#define PRIMARYMX_STR "primarymx"
#define BACKUPMX_STR "backupmx"
#define OFFLINE_STR "offline"
#define DYNDNS_STR "dyndns"
#define CUSTOMDNS_STR "customdns"
#define STATICDNS_STR "staticdns"
#define DETACH_STR "detach"
#define NODETACH_STR "nodetach"
#define QUIET_STR "quiet"
#define DISABLE_CHROOT_STR "disable-chroot"
#define REMOTE_STR "remote"

void parse_warn(unsigned int lnum, char *name)
{
    log_line("WARNING: config line %d: %s statement not valid in section\n", lnum, name);
}

/* if file is NULL, then read stdin */
int parse_config(char *file, dyndns_conf_t *dc, namecheap_conf_t *nc,
                 he_conf_t *hc)
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

        point = buf;
        while (*point == ' ' || *point == '\t')
            ++point;

        if (!strncmp(PRS_CONFIG_STR, point, sizeof PRS_CONFIG_STR - 1)) {
            prs = PRS_CONFIG;
            continue;
        }
        if (!strncmp(PRS_DYNDNS_STR, point, sizeof PRS_DYNDNS_STR - 1)) {
            prs = PRS_DYNDNS;
            continue;
        }
        if (!strncmp(PRS_NAMECHEAP_STR, point, sizeof PRS_NAMECHEAP_STR - 1)) {
            prs = PRS_NAMECHEAP;
            continue;
        }
        if (!strncmp(PRS_HE_STR, point, sizeof PRS_HE_STR - 1)) {
            prs = PRS_HE;
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
                    break;
                case PRS_NAMECHEAP:
                    assign_string(&nc->password, tmp);
                    break;
            }
            free(tmp);
            continue;
        }

        tmp = parse_line_string(point, "passhash");
        if (tmp) {
            switch (prs) {
                default:
                    parse_warn(lnum, "passhash");
                    break;
                case PRS_HE:
                    assign_string(&hc->passhash, tmp);
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
                    break;
                case PRS_NAMECHEAP:
                    populate_hostlist(&nc->hostlist, tmp);
                    break;
            }
            free(tmp);
            continue;
        }

        tmp = parse_line_string(point, "hostpairs");
        if (tmp) {
            switch (prs) {
                default:
                    parse_warn(lnum, "hostpairs");
                    break;
                case PRS_HE:
                    populate_hostpairs(&hc->hostpairs, tmp);
                    break;
            }
            free(tmp);
            continue;
        }

        tmp = parse_line_string(point, "tunnelids");
        if (tmp) {
            switch (prs) {
                default:
                    parse_warn(lnum, "tunnelids");
                    break;
                case PRS_HE:
                    populate_hostlist(&hc->tunlist, tmp);
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
                    break;
            }
            free(tmp);
            continue;
        }

        tmp = parse_line_string(point, "userid");
        if (tmp) {
            switch (prs) {
                default:
                    parse_warn(lnum, "userid");
                    break;
                case PRS_HE:
                    assign_string(&hc->userid, tmp);
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
                    dc->system = SYSTEM_STATDNS;
                    break;
            }
            continue;
        }

        tmp = parse_line_string(point, "chroot");
        if (tmp) {
            switch (prs) {
                default:
                    parse_warn(lnum, "chroot");
                    break;
                case PRS_CONFIG:
                    update_chroot(tmp);
                    break;
            }
            free(tmp);
            continue;
        }

        tmp = parse_line_string(point, "pidfile");
        if (tmp) {
            switch (prs) {
                default:
                    parse_warn(lnum, "pidfile");
                    break;
                case PRS_CONFIG:
                    cfg_set_pidfile(tmp);
                    break;
            }
            free(tmp);
            continue;
        }

        tmp = parse_line_string(point, "user");
        if (tmp) {
            switch (prs) {
                default:
                    parse_warn(lnum, "user");
                    break;
                case PRS_CONFIG:
                    cfg_set_user(tmp);
                    break;
            }
            free(tmp);
            continue;
        }

        tmp = parse_line_string(point, "group");
        if (tmp) {
            switch (prs) {
                default:
                    parse_warn(lnum, "group");
                    break;
                case PRS_CONFIG:
                    cfg_set_group(tmp);
                    break;
            }
            free(tmp);
            continue;
        }

        tmp = parse_line_string(point, "interface");
        if (tmp) {
            switch (prs) {
                default:
                    parse_warn(lnum, "interface");
                    break;
                case PRS_CONFIG:
                    cfg_set_interface(tmp);
                    break;
            }
            free(tmp);
            continue;
        }

        if (!strncmp(DETACH_STR, point, sizeof DETACH_STR - 1)) {
            switch (prs) {
                default:
                    parse_warn(lnum, "detach");
                    break;
                case PRS_CONFIG:
                    break;
            }
            continue;
        }
        if (!strncmp(NODETACH_STR, point, sizeof NODETACH_STR - 1)) {
            switch (prs) {
                default:
                    parse_warn(lnum, "nodetach");
                    break;
                case PRS_CONFIG:
                    break;
            }
            continue;
        }
        if (!strncmp(QUIET_STR, point, sizeof QUIET_STR - 1)) {
            switch (prs) {
                default:
                    parse_warn(lnum, "quiet");
                    break;
                case PRS_CONFIG:
                    break;
            }
            continue;
        }
        if (!strncmp(DISABLE_CHROOT_STR, point, sizeof DISABLE_CHROOT_STR - 1)) {
            switch (prs) {
                default:
                    parse_warn(lnum, "disable-chroot");
                    break;
                case PRS_CONFIG:
                    break;
            }
            continue;
        }
        if (!strncmp(REMOTE_STR, point, sizeof REMOTE_STR - 1)) {
            switch (prs) {
                default:
                    parse_warn(lnum, "remote");
                    break;
                case PRS_CONFIG:
                    break;
            }
            continue;
        }
    }

    if (fclose(f)) {
        log_line("parse_config: failed to close [%s]\n", file);
        exit(EXIT_FAILURE);
    }
    ret = validate_dyndns_conf(dc) | validate_nc_conf(nc) |
          validate_he_conf(hc);
    return ret;
}
