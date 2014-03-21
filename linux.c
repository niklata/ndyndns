/* linux.c - Linux-specific functions
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>

#include "defines.h"
#include "config.h"
#include "log.h"
#include "util.h"
#include "xstrdup.h"

/* allocates from heap for return */
char *get_interface_ip(char *ifname)
{
    struct ifreq ifr;
    char *ret = NULL;
    int fd;

    if (ifname == NULL)
        goto out;

    fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        log_line("%s: (%s) failed to open interface socket: %s",
                 ifname, __func__, strerror(errno));
        goto out;
    }

    ssize_t snlen = snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", ifname);
    if (snlen < 0 || (size_t)snlen >= sizeof ifr.ifr_name)
        suicide("%s: snprintf would truncate", __func__);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        log_line("%s: (%s) SIOCGIFADDR failed: %s",
                 ifname, __func__, strerror(errno));
        goto outfd;
    }

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr,
              ip, sizeof ip);
    ret = xstrdup(ip);
outfd:
    close(fd);
out:
    return ret;
}

