/* (c) 2005-2012 Nicholas J. Kain <njkain at gmail dot com>
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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>

#include <signal.h>
#include <errno.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <curl/curl.h>

#include "defines.h"
#include "cfg.h"
#include "log.h"
#include "chroot.h"
#include "pidfile.h"
#include "signals.h"
#include "strl.h"
#include "linux.h"
#include "checkip.h"
#include "util.h"
#include "malloc.h"

#include "dns_dyn.h"
#include "dns_nc.h"
#include "dns_he.h"

int use_ssl = 1;

static char ifname[IFNAMSIZ] = "ppp0";
static char pidfile[MAX_PATH_LENGTH] = PID_FILE_DEFAULT;

static int update_interval = DEFAULT_UPDATE_INTERVAL;
static int update_from_remote = 0;
static int cfg_uid = 0, cfg_gid = 0;

static volatile sig_atomic_t pending_exit;

static void sighandler(int sig) {
    sig = sig; /* silence warning */
    pending_exit = 1;
}

static void fix_signals(void) {
    disable_signal(SIGPIPE);
    disable_signal(SIGUSR1);
    disable_signal(SIGUSR2);
    disable_signal(SIGTSTP);
    disable_signal(SIGTTIN);
    disable_signal(SIGCHLD);
    disable_signal(SIGHUP);

    hook_signal(SIGINT, sighandler, 0);
    hook_signal(SIGTERM, sighandler, 0);
}

static void do_sleep(void)
{
    struct timespec req = { update_interval, 0 }, rem;
retry:
    if (pending_exit)
        exit(EXIT_SUCCESS);

    if (nanosleep(&req, &rem)) {
        switch (errno) {
        case EINTR:
            req = rem;
            goto retry;
        default:
            suicide("nanosleep failed");
        }
    }
}

static void do_work(void)
{
    char *curip = NULL;
    struct in_addr inr;

    log_line("updating to interface: [%s]\n", ifname);

    while (1) {
        free(curip);

        if (update_from_remote == 0) {
            curip = get_interface_ip(ifname);
        } else {
            curip = query_curip();
        }

        if (!curip)
            goto sleep;
        if (inet_aton(curip, &inr) == 0) {
            log_line(
                "%s has ip: [%s], which is invalid.  Sleeping.\n",
                ifname, curip);
            goto sleep;
        }

        dd_work(curip);
        nc_work(curip);
        he_dns_work(curip);
        he_tun_work(curip);
sleep:
        do_sleep();
    }
}

static int check_ssl(void)
{
    int t;
    curl_version_info_data *data;

    data = curl_version_info(CURLVERSION_NOW);

    t = data->features & CURL_VERSION_SSL;
    if (t) {
        log_line("curl has SSL support, using https.\n");
    } else {
        log_line("curl lacks SSL support, using http.\n");
    }
    return t;
}

void cfg_set_remote(void)
{
    update_from_remote = 1;
    update_interval = 600;
}

void cfg_set_detach(void)
{
    gflags_detach = 1;
}

void cfg_set_nodetach(void)
{
    gflags_detach = 0;
}

void cfg_set_quiet(void)
{
    gflags_quiet = 1;
}

void cfg_set_pidfile(char *pidfname)
{
    strlcpy(pidfile, pidfname, sizeof pidfile);
}

void cfg_set_user(char *username)
{
    int t;
    char *p;
    struct passwd *pws;

    t = (unsigned int) strtol(username, &p, 10);
    if (*p != '\0') {
        pws = getpwnam(username);
        if (pws) {
            cfg_uid = (int)pws->pw_uid;
            if (!cfg_gid)
                cfg_gid = (int)pws->pw_gid;
        } else suicide("FATAL - Invalid uid specified.\n");
    } else
        cfg_uid = t;
}

void cfg_set_group(char *groupname)
{
    int t;
    char *p;
    struct group *grp;

    t = (unsigned int) strtol(groupname, &p, 10);
    if (*p != '\0') {
        grp = getgrnam(groupname);
        if (grp) {
            cfg_gid = (int)grp->gr_gid;
        } else suicide("FATAL - Invalid gid specified.\n");
    } else
        cfg_gid = t;
}

void cfg_set_interface(char *interface)
{
    strlcpy(ifname, interface, sizeof ifname);
}

int main(int argc, char** argv)
{
    int c, read_cfg = 0;

    init_config();

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"detach", 0, 0, 'd'},
            {"nodetach", 0, 0, 'n'},
            {"pidfile", 1, 0, 'p'},
            {"quiet", 0, 0, 'q'},
            {"chroot", 1, 0, 'c'},
            {"disable-chroot", 0, 0, 'x'},
            {"file", 1, 0, 'f'},
            {"cfg-stdin", 0, 0, 'F'},
            {"user", 1, 0, 'u'},
            {"group", 1, 0, 'g'},
            {"interface", 1, 0, 'i'},
            {"remote", 0, 0, 'r'},
            {"help", 0, 0, 'h'},
            {"version", 0, 0, 'v'},
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "rdnp:qc:xf:Fu:g:i:hv", long_options, &option_index);
        if (c == -1) break;

        switch (c) {

            case 'h':
                printf("ndyndns %s, dyndns update client.  Licensed under GNU GPL.\n", NDYNDNS_VERSION);
                printf(
                    "Copyright (C) 2005-2011 Nicholas J. Kain\n"
                    "Usage: ndyndns [OPTIONS]\n"
                    "  -d, --detach                detach from TTY and daemonize\n"
                    "  -n, --nodetach              stay attached to TTY\n"
                    "  -q, --quiet                 don't print to std(out|err) or log\n");
                printf(
                    "  -c, --chroot                path where ndyndns should chroot\n"
                    "  -x, --disable-chroot        do not actually chroot (not recommended)\n"
                    "  -f, --file                  configuration file\n"
                    "  -F, --cfg-stdin             read configuration file from standard input\n"
                    "  -p, --pidfile               pidfile path\n");
                printf(
                    "  -u, --user                  user name that ndyndns should run as\n"
                    "  -g, --group                 group name that ndyndns should run as\n"
                    "  -i, --interface             interface ip to check (default: ppp0)\n"
                    "  -r, --remote                get ip from remote dyndns host (overrides -i)\n"
                    "  -h, --help                  print this help and exit\n"
                    "  -v, --version               print version and license info and exit\n");
                exit(EXIT_FAILURE);
                break;

            case 'v':
                printf(
                    "ndyndns %s Copyright (C) 2005-2011 Nicholas J. Kain\n"
                    "This program is free software: you can redistribute it and/or modify\n"
                    "it under the terms of the GNU General Public License as published by\n"
                    "the Free Software Foundation, either version 3 of the License, or\n"
                    "(at your option) any later version.\n\n", NDYNDNS_VERSION);
                printf(
                    "This program is distributed in the hope that it will be useful,\n"
                    "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
                    "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
                    "GNU General Public License for more details.\n\n"

                    "You should have received a copy of the GNU General Public License\n"
                    "along with this program.  If not, see <http://www.gnu.org/licenses/>.\n");
                exit(EXIT_FAILURE);
                break;

            case 'r':
                cfg_set_remote();
                break;

            case 'd':
                cfg_set_detach();
                break;

            case 'n':
                cfg_set_nodetach();
                break;

            case 'q':
                cfg_set_quiet();
                break;

            case 'x':
                disable_chroot();
                break;

            case 'c':
                update_chroot(optarg);
                break;

            case 'f':
                if (read_cfg) {
                    log_line("FATAL: duplicate configuration file data specified");
                    exit(EXIT_FAILURE);
                } else {
                    read_cfg = 1;
                    if (parse_config(optarg) != 1)
                        suicide("FATAL: bad configuration data\n");
                }
                break;

            case 'F':
                if (read_cfg) {
                    log_line("ERROR: duplicate configuration file data specified");
                    exit(EXIT_FAILURE);
                } else {
                    read_cfg = 1;
                    if (parse_config(NULL) != 1)
                        suicide("FATAL: bad configuration data\n");
                }
                break;

            case 'p':
                cfg_set_pidfile(optarg);
                break;

            case 'u':
                cfg_set_user(optarg);
                break;

            case 'g':
                cfg_set_group(optarg);
                break;

            case 'i':
                cfg_set_interface(optarg);
                break;
        }
    }

    if (!read_cfg)
        suicide("FATAL - no configuration file, exiting.\n");

    if (chroot_enabled() && getuid())
        suicide("FATAL - I need root for chroot!\n");

    if (gflags_detach)
        if (daemon(0,0))
            suicide("FATAL - detaching fork failed\n");

    if (file_exists(pidfile, "w") == -1)
        exit(EXIT_FAILURE);
    write_pid(pidfile);

    umask(077);
    fix_signals();

    if (!chroot_exists())
        suicide("FATAL - No chroot path specified.  Refusing to run.\n");

    /* Note that failure cases are handled by called fns. */
    imprison(get_chroot());
    drop_root(cfg_uid, cfg_gid);

    /* Cover our tracks... */
    wipe_chroot();
    memset(pidfile, '\0', sizeof pidfile);

    curl_global_init(CURL_GLOBAL_ALL);
    use_ssl = check_ssl();

    do_work();

    exit(EXIT_SUCCESS);
}

