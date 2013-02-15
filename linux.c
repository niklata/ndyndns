/* linux.c - Linux-specific functions
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
#if 0
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
        ALLOW_SYSCALL(sendmmsg),

        ALLOW_SYSCALL(rt_sigreturn),
#ifdef __NR_sigreturn
        ALLOW_SYSCALL(sigreturn),
#endif
        ALLOW_SYSCALL(rt_sigaction),
        ALLOW_SYSCALL(alarm),
        ALLOW_SYSCALL(rt_sigprocmask),
        ALLOW_SYSCALL(futex),

        // Allowed by vDSO
        ALLOW_SYSCALL(getcpu),
        ALLOW_SYSCALL(time),
        ALLOW_SYSCALL(gettimeofday),

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
#endif

