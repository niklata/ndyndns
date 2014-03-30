/* sun.c - Solaris-specific functions
 *
 * Copyright (c) 2007-2014 Nicholas J. Kain <njkain at gmail dot com>
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
#include <stropts.h>
#include <errno.h>
#include "nk/xstrdup.h"
#include "util.h"

/* allocates from heap for return */
char *get_interface_ip(char *ifname)
{
    struct lifreq lif;
    char *ret = NULL;
    size_t len;
    int r, s;

    if (ifname == NULL)
        goto out;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        log_line("Failed to open socket: unable to get NIC ip.");
        goto out;
    }

    ssize_t snlen = snprintf(lif.lfr_name, sizeof lif.lfr_name, "%s", ifname);
    if (snlen < 0 || (size_t)snlen >= sizeof lif.lif_name)
        suicide("%s: snprintf would truncate", __func__);
    r = ioctl(s, SIOCGLIFADDR, &lif);
    if (r) {
        log_line("Failed to get interface address info.");
        goto out2;
    }

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &((struct sockaddr_in *)lif.lifr_addr)->sin_addr,
              ip, sizeof ip);
    ret = xstrdup(ip);
out2:
    close(s);
out:
    return ret;
}

