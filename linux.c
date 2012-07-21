/* linux.c - Linux-specific functions
 *
 * (C) 2005-2012 Nicholas J. Kain <njkain at gmail dot com>
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
#include "config.h"
#include "log.h"
#include "strl.h"
#include "util.h"
#include "malloc.h"
#include "seccomp-bpf.h"

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
        log_line("%s: (%s) failed to open interface socket: %s",
                 ifname, __func__, strerror(errno));
        goto out;
    }

    strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        log_line("%s: (%s) SIOCGIFADDR failed: %s",
                 ifname, __func__, strerror(errno));
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

#ifdef HAVE_LINUX_SECCOMP_H
int enforce_seccomp(void)
{
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        EXAMINE_SYSCALL,
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(sendto), // used for glibc syslog routines
        ALLOW_SYSCALL(nanosleep),
        ALLOW_SYSCALL(clock_gettime),
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(ioctl),
        ALLOW_SYSCALL(open),
        ALLOW_SYSCALL(socket),
        ALLOW_SYSCALL(connect),
        ALLOW_SYSCALL(poll),
        ALLOW_SYSCALL(recvfrom),
        ALLOW_SYSCALL(getsockopt),
        ALLOW_SYSCALL(getpeername),
        ALLOW_SYSCALL(getsockname),
        ALLOW_SYSCALL(stat),
        ALLOW_SYSCALL(getuid),
        ALLOW_SYSCALL(fsync),
        ALLOW_SYSCALL(fstat),
        ALLOW_SYSCALL(fcntl),
        ALLOW_SYSCALL(brk),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(munmap),

        ALLOW_SYSCALL(rt_sigreturn),
#ifdef __NR_sigreturn
        ALLOW_SYSCALL(sigreturn),
#endif
        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(exit),
        KILL_PROCESS,
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof filter / sizeof filter[0]),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return -1;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
        return -1;
    return 0;
}
#else
int enforce_seccomp(void)
{
    return 1;
}
#endif

