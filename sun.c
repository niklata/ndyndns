/* sun.c - Solaris-specific functions
 *
 * (C) 2007-2010 Nicholas J. Kain <njkain at gmail dot com>
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

#include "defines.h"
#include "log.h"
#include "strl.h"
#include "util.h"

/* allocates from heap for return */
char *get_interface_ip(char *ifname)
{
	struct lifreq lif;
	char *ret = NULL, *ip;
	size_t len;
	int r, s;

	if (ifname == NULL)
		goto out;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		log_line("Failed to open socket: unable to get NIC ip.\n");
		goto out;
	}

	strlcpy(lif.lfr_name, ifname, LIFNAMSIZ);
	r = ioctl(s, SIOCGLIFADDR, &lif);
	if (r) {
		log_line("Failed to get interface address info.\n");
		goto out2;
	}

	ip = inet_ntoa(((struct sockaddr_in *)lif.lifr_addr)->sin_addr);
	len = strlen(ip) + 1;
	ret = xmalloc(len);
	strlcpy(ret, ip, len);
out2:
	close(s);
out:
	return ret;
}

