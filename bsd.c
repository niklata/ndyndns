/* bsd.c - BSD-specific functions
 *
 * (C) 2005-2009 Nicholas J. Kain <njkain at gmail dot com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
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

int enforce_seccomp(void)
{
    return 0;
}

