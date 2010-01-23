/* linux.c - Linux-specific functions
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
#include "log.h"
#include "nstrl.h"
#include "util.h"

/* allocates from heap for return */
char *get_interface_ip(char *ifname)
{
	struct ifreq ifr;
	char *ip = NULL, *ret = NULL;
	int fd, len;

	if (ifname == NULL)
		goto out;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		log_line("%s: (get_interface_ip) failed to open interface \
			 socket: %s\n", ifname, strerror(errno));
		goto out;
	}

	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;
	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		log_line("%s: (get_interface_ip) SIOCGIFADDR failed: %s\n",
			ifname, strerror(errno));
		goto outfd;
	}

	ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
	len = strlen(ip) + 1;
	ret = xmalloc(len);
	strlcpy(ret, ip, len);
outfd:
	close(fd);
out:
	return ret;
}


