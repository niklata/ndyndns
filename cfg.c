/* cfg.c - configuration file functions
 *
 * Copyright (c) 2005-2014 Nicholas J. Kain <njkain at gmail dot com>
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include "nk/log.h"
#include "nk/privilege.h"
#include "nk/malloc.h"
#include "nk/copy_cmdarg.h"
#include "nk/xstrdup.h"

#include "defines.h"
#include "ndyndns.h"
#include "cfg.h"
#include "util.h"
#include "dns_nc.h"
#include "dns_he.h"
#include "dns_helpers.h"

struct dnsip_lookup_node
{
    char *host;
    char *ip;
    void *next;
};
static struct dnsip_lookup_node *dlq_pending;

void write_dnsip_lookups(void)
{
    struct dnsip_lookup_node *next;
    for (struct dnsip_lookup_node *p = dlq_pending; p; p = next) {
        next = p->next;
        write_dnsip(p->host, p->ip);
        free(p->host);
        free(p->ip);
        free(p);
    }
    dlq_pending = NULL;
}

static void queue_dnsip_lookup(char *host, char *ip)
{
    struct dnsip_lookup_node *p = xmalloc(sizeof(struct dnsip_lookup_node));
    p->host = xstrdup(host);
    p->ip = xstrdup(ip);
    p->next = dlq_pending;
    dlq_pending = p;
}

extern char chroot_dir[PATH_MAX];

void init_config(void)
{
    init_namecheap_conf();
    init_he_conf();
}

void remove_host_from_hostdata_list(hostdata_t **phl, char *host)
{
    hostdata_t *cur = *phl, *after = NULL, *p;

    if (!strcmp(cur->host, host)) {
        after = cur->next;
        free(cur->host);
        free(cur->ip);
        free(cur);
        *phl = after;
        return;
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
    size_t len;

    memset(buf, '\0', MAX_BUF);

    len = strlen(chroot_dir) + strlen(host) + strlen("/var/-dnserr") + 1;
    file = xmalloc(len);
    ssize_t snlen = snprintf(file, len, "%s/var/%s-dnserr", chroot_dir, host);
    if (snlen < 0 || (size_t)snlen >= len)
        suicide("%s: snprintf would truncate", __func__);

    f = fopen(file, "r");
    free(file);

    if (!f)
        goto out;

    if (!fgets(buf, sizeof buf, f)) {
        log_line("%s-dnserr is empty.  Assuming error: [unknown].", host);
        ret = xstrdup("unknown");
        goto outfd;
    }

    ret = xstrdup(buf);
outfd:
    fclose(f);
out:
    return ret;
}

/* allocates memory.  ip may be NULL */
static void add_to_hostdata_list(hostdata_t **list, char *host, char *ip,
                    time_t time)
{
    hostdata_t *item, *t;
    char *err = NULL;

    if (!list || !host) return;

    err = get_dnserr(host);
    if (err) {
        log_line("host:[%s] is locked because of error:[%s].  Correct the problem and remove [%s-dnserr] to allow update.", host, err, host);
        free(err);
        return;
    }

    item = xmalloc(sizeof (hostdata_t));
    item->date = time;
    item->next = NULL;
    item->ip = NULL;

    item->host = xstrdup(host);

    if (!ip || !item->host) {
        if (item->host) {
            log_line("[%s] has no ip address.  No updates will be performed for [%s].", host, host);
        } else {
            log_line("[%s] has no host name.  Your configuration file has a problem.", ip);
        }
        goto out;
    }

    item->ip = xstrdup(ip);

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
    log_error("%s: coding error", __func__);
out:
    free(item->host);
    free(item->ip);
    free(item);
}

/* allocates memory.  ip may be NULL */
static void add_to_hostpair_list(hostdata_t **list, char *host, char *passwd,
                                 char *ip, time_t time)
{
    hostdata_t *item, *t;
    char *err = NULL;

    if (!list || !host || !passwd) return;

    err = get_dnserr(host);
    if (err) {
        log_line("host:[%s] is locked because of error:[%s].  Correct the problem and remove [%s-dnserr] to allow update.", host, err, host);
        free(err);
        return;
    }

    item = xmalloc(sizeof (hostdata_t));
    item->date = time;
    item->next = NULL;
    item->ip = NULL;

    item->host = xstrdup(host);
    item->password = xstrdup(passwd);
    item->ip = xstrdup(ip);

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
    log_line("%s: coding error", __func__);
out:
    free(item->host);
    free(item->password);
    free(item->ip);
    free(item);
}

static time_t get_dnsdate(char *host)
{
    FILE *f;
    char buf[MAX_BUF], *file;
    size_t len;
    time_t ret = 0;

    len = strlen(chroot_dir) + strlen(host) + strlen("/var/-dnsdate") + 1;
    file = xmalloc(len);
    ssize_t snlen = snprintf(file, len, "%s/var/%s-dnsdate", chroot_dir, host);
    if (snlen < 0 || (size_t)snlen >= len)
        suicide("%s: snprintf would truncate", __func__);

    f = fopen(file, "r");
    free(file);

    if (!f) {
        log_line("No existing %s-dnsdate.  Assuming date == 0.", host);
        goto out;
    }

    if (!fgets(buf, sizeof buf, f)) {
        log_line("%s-dnsdate is empty.  Assuming date == 0.", host);
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

    if (!name)
        suicide("%s: host is NULL!", __func__);

    hent = gethostbyname(name);
    if (hent == NULL) {
        switch (h_errno) {
        case HOST_NOT_FOUND:
            log_line("failed to resolve %s: host not found.", name);
            break;
        case NO_ADDRESS:
            log_line("failed to resolve %s: no IP for host.", name);
            break;
        case NO_RECOVERY:
        default:
            log_line("failed to resolve %s: non-recoverable error.", name);
            break;
        case TRY_AGAIN:
            log_line("failed to resolve %s: temporary error on an authoritative nameserver.", name);
            break;
        }
        return NULL;
    }

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, (struct in_addr *)hent->h_addr, ip, sizeof ip);
    log_line("%s: returned [%s]", __func__, ip);
    queue_dnsip_lookup(name, ip);
    return xstrdup(ip);
}

/* allocates memory for return or returns NULL */
static char *get_dnsip(char *host)
{
    FILE *f;
    char buf[MAX_BUF], *file, *ret = NULL;
    size_t len;
    struct in_addr inr;

    memset(buf, '\0', MAX_BUF);

    len = strlen(chroot_dir) + strlen(host) + strlen("/var/-dnsip") + 1;
    file = xmalloc(len);
    ssize_t snlen = snprintf(file, len, "%s/var/%s-dnsip", chroot_dir, host);
    if (snlen < 0 || (size_t)snlen >= len)
        suicide("%s: snprintf would truncate", __func__);

    f = fopen(file, "r");
    free(file);

    if (!f) {
        log_line("No existing %s-dnsip.  Querying DNS.", host);
        ret = lookup_dns(host);
        goto out;
    }

    if (!fgets(buf, sizeof buf, f)) {
        log_line("%s-dnsip is empty.  Querying DNS.", host);
        ret = lookup_dns(host);
        goto outfd;
    }

    if (inet_pton(AF_INET, buf, &inr) != 1) {
        log_line("%s-dnsip is corrupt.  Querying DNS.", host);
        ret = lookup_dns(host);
        goto outfd;
    }

    ret = xstrdup(buf);
outfd:
    fclose(f);
out:
    return ret;
}

typedef void (*do_populate_fn)(hostdata_t **list, char *instr);

static void do_populate(hostdata_t **list, char *host_in)
{
    char *host, *host_orig;

    host = strdup(host_in);
    host_orig = host;
    while (*host == ' ' || *host == '\t')
        ++host;

    if (strlen(host)) {
        char *ip = get_dnsip(host);
        if (ip) {
            log_line("adding: [%s] ip: [%s]", host, ip);
            add_to_hostdata_list(list, host, ip, get_dnsdate(host));
        } else {
            log_line("No ip found for [%s].  No updates will be done.", host);
        }
        free(ip);
    }
    free(host_orig);
}

static void do_populate_hp(hostdata_t **list, char *pair_in)
{
    char *host, *host_orig, *passwd;

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
        char *ip = get_dnsip(host);
        if (ip) {
            log_line("adding: [%s] ip: [%s]", host, ip);
            add_to_hostpair_list(list, host, passwd, ip, get_dnsdate(host));
        } else {
            log_line("No ip found for [%s].  No updates will be done.", host);
        }
        free(ip);
    }
    free(host_orig);
}

static void populate_hostlist_generic(do_populate_fn fn, hostdata_t **list,
                                      char *left)
{
    char *right = (char *)1, *p;

    do {
        right = strchr(left, ',');
        if (right != NULL && left < right) {
            for (p = left; p < right; ++p) {
                if (*p == ' ' || *p == '\t')
                    break;
            }
            size_t len = p - left + 1;
            char *t = xmalloc(len);
            memcpy(t, left, len - 1);
            t[len-1] = '\0';
            fn(list, t);
            free(t);
            left = right + 1;
        } else {
            fn(list, left);
            break;
        }
    } while (1);
}

static void populate_hostlist(hostdata_t **list, char *hostname)
{
    if (!list || !hostname)
        suicide("%s: NULL passed as argument", __func__);
    if (strlen(hostname) == 0)
        suicide("No hosts were provided for updates.  Exiting.");

    log_line("hosts: [%s]", hostname);
    populate_hostlist_generic(do_populate, list, hostname);
}

static void populate_hostpairs(hostdata_t **list, char *hostpair)
{
    if (!list || !hostpair)
        suicide("%s: NULL passed as argument", __func__);
    if (strlen(hostpair) == 0)
        suicide("No hostpairs were provided for updates.  Exiting.");
    log_line("hostpairs: [%s]", hostpair);
    populate_hostlist_generic(do_populate_hp, list, hostpair);
}

/* returns 1 for valid config, 0 for invalid */
static int validate_nc_conf(namecheap_conf_t *t)
{
    int r = 1;
    if (t->password || t->hostlist) {
        if (t->password == NULL) {
            r = 0;
            log_line("namecheap config invalid: no password provided");
        }
        if (t->hostlist == NULL) {
            r = 0;
            log_line("namecheap config invalid: no hostnames provided");
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
        log_line("he config invalid: no tunnelids or hostpairs provided");
    } else if (t->tunlist) {
        if (t->userid == NULL) {
            r = 0;
            log_line("he config invalid: no userid provided");
        }
        if (t->passhash == NULL) {
            r = 0;
            log_line("he config invalid: no passhash provided");
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
    // Strip terminal whitespace.
    while (len) {
        if (*(point+len-1) == ' ' || *(point+len-1) == '\t') {
            if (len - 1 >= 0)
                *(point+len-1) = '\0';
            if (len > 0)
                --len;
            else
                break;
        } else
            break;
    }
    ret = xstrdup(point);
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
    PRS_NAMECHEAP,
    PRS_HE,
};

#define PRS_CONFIG_STR "[config]"
#define PRS_NAMECHEAP_STR "[namecheap]"
#define PRS_HE_STR "[he]"
#define BACKGROUND_STR "background"
#define QUIET_STR "quiet"
#define DISABLE_CHROOT_STR "disable-chroot"
#define REMOTE_STR "remote"

void parse_warn(unsigned int lnum, char *name)
{
    log_line("WARNING: config line %d: %s statement not valid in section", lnum, name);
}

/* if file is NULL, then read stdin */
int parse_config(char *file)
{
    FILE *f;
    char buf[MAX_BUF];
    int ret = -1;
    unsigned int lnum = 0;
    char *tmp;
    enum prs_state prs = PRS_NONE;

    if (file) {
        f = fopen(file, "r");
        if (!f)
            suicide("%s: failed to open [%s] for read", __func__, file);
    } else {
        f = fdopen(0, "r");
        if (!f)
            suicide("%s: failed to open stdin for read", __func__);
    }

    while (!feof(f)) {
        if (!fgets(buf, sizeof buf, f))
            break;
        ++lnum;

        char *point = buf;
        while (*point == ' ' || *point == '\t')
            ++point;

        if (!strncmp(PRS_CONFIG_STR, point, sizeof PRS_CONFIG_STR - 1)) {
            prs = PRS_CONFIG;
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
                case PRS_NAMECHEAP:
                    assign_string(&namecheap_conf.password, tmp);
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
                    assign_string(&he_conf.passhash, tmp);
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
                case PRS_NAMECHEAP:
                    populate_hostlist(&namecheap_conf.hostlist, tmp);
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
                    populate_hostpairs(&he_conf.hostpairs, tmp);
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
                    populate_hostlist(&he_conf.tunlist, tmp);
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
                    assign_string(&he_conf.userid, tmp);
                    break;
            }
            free(tmp);
            continue;
        }

        tmp = parse_line_string(point, "chroot");
        if (tmp) {
            switch (prs) {
                default:
                    parse_warn(lnum, "chroot");
                    break;
                case PRS_CONFIG:
                    cfg_set_chroot(tmp);
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

        if (!strncmp(BACKGROUND_STR, point, sizeof BACKGROUND_STR - 1)) {
            switch (prs) {
                default:
                    parse_warn(lnum, "background");
                    break;
                case PRS_CONFIG:
                    cfg_set_background();
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
                    cfg_set_quiet();
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
                    cfg_set_disable_chroot();
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
                    cfg_set_remote();
                    break;
            }
            continue;
        }
    }

    if (fclose(f))
        suicide("%s: failed to close [%s]", __func__, file);
    ret = validate_nc_conf(&namecheap_conf) | validate_he_conf(&he_conf);
    return ret;
}
