/* bsd.c - BSD-specific functions
 *
 * (C) 2005-2007 Nicholas J. Kain <njk@aerifal.cx>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <errno.h>

#include "defines.h"
#include "log.h"
#include "nstrl.h"
#include "util.h"

/* allocates from heap for return */
char *get_interface_ip(char *ifname)
{
	struct ifaddrs *ifp = NULL, *p = NULL;
	char *ret = NULL;
	size_t len;
	int r, found = 0;

	if (ifname == NULL)
		goto out;

	r = getifaddrs(&ifp);
	if (r) {
		log_line("Failed to interface address info.\n", ifname);
		goto out;
	}

	/* find proper interface structure */
	p = ifp;
	while (p) {
		if (p->ifa_name && (strcmp(ifname, p->ifa_name) == 0)) {
			found = 1;
			break;
		}
		p = p->ifa_next;
	}

	if (found) {
		len = strlen(p->ifa_addr) + 1;
		ret = xmalloc(len);
		strlcpy(ret, p->ifa_addr, len);
	} else {
		log_line("Could not find an IP for interface [%s]\n", ifname);
	}

	freeifaddrs(ifp);
out:
	return ret;
}

