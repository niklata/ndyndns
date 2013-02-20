/* bsd.c - BSD-specific functions
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <errno.h>

#include "defines.h"
#include "log.h"
#include "strl.h"
#include "util.h"

/* allocates from heap for return */
char *get_interface_ip(char *ifname)
{
    struct ifaddrs *ifp = NULL, *p = NULL;
    char *ret = NULL, *ip;
    size_t len;
    int r, found = 0;

    if (ifname == NULL)
        goto out;

    r = getifaddrs(&ifp);
    if (r) {
        log_line("Failed to interface address info.");
        goto out;
    }

    /* find proper interface structure */
    p = ifp;
    while (p) {
        if (p->ifa_name && (strcmp(ifname, p->ifa_name) == 0) &&
            p->ifa_addr && (p->ifa_addr->sa_family == AF_INET)) {
            found = 1;
            break;
        }
        p = p->ifa_next;
    }

    /* No matching interface structure found.  Free and exit. */
    if (!found) {
        log_line("Could not find interface information for [%s].", ifname);
        goto out2;
    }

    /* Fail if the interface has no IP. */
    if (!p->ifa_addr) {
        log_line("Could not find an IP for interface [%s]\n", ifname);
        goto out2;
    }

    ip = inet_ntoa(((struct sockaddr_in *)p->ifa_addr)->sin_addr);
    len = strlen(ip) + 1;
    ret = xmalloc(len);
    strlcpy(ret, ip, len);

out2:
    freeifaddrs(ifp);
out:
    return ret;
}

