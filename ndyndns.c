/* ndyndns.c - dynamic dns update daemon
 *
 * (C) 2005-2009 Nicholas J. Kain <njkain at gmail dot com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * the Free Software Foundation.
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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ctype.h>
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
#include "nstrl.h"
#include "linux.h"
#include "checkip.h"
#include "util.h"
#include "strlist.h"

static dyndns_conf_t dyndns_conf;

static char ifname[IFNAMSIZ] = "ppp0";

static int update_interval = DEFAULT_UPDATE_INTERVAL;
static int use_ssl = 1;
static int update_from_remote = 0;

typedef enum {
	RET_DO_NOTHING,
	RET_BADSYS,
	RET_BADAGENT,
	RET_BADAUTH,
	RET_NOTDONATOR,
	RET_GOOD,
	RET_NOCHG,
	RET_NOTFQDN,
	RET_NOHOST,
	RET_NOTYOURS,
	RET_ABUSE,
	RET_NUMHOST,
	RET_DNSERR,
	RET_911
} return_codes;

typedef struct {
	return_codes code;
	void *next;
} return_code_list_t;

static strlist_t *update_list = NULL;
static return_code_list_t *return_list = NULL;

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

static void write_dnsfile(char *fn, char *cnts)
{
	int fd, written = 0, oldwritten, len;

	if (!fn || !cnts)
		suicide("FATAL - write_dnsfile: received NULL\n");

	fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);

	if (fd == -1)
		suicide("FATAL - failed to open %s for write\n", fn);

	len = strlen(cnts);

	while (written < len) {
		oldwritten = written;
		written = write(fd, cnts + written, len - written);
		if (written == -1) {
			if (errno == EINTR) {
				written = oldwritten;
				continue;
			}
			suicide("FATAL - write() failed on %s\n", fn);
		}
	}

	fsync(fd);
	if (close(fd) == -1)
		suicide("error closing %s; possible corruption\n", fn);
}

static void write_dnsdate(char *host, time_t date)
{
	int len;
	char *file, buf[MAX_BUF];

	if (!host)
		suicide("FATAL - write_dnsdate: host is NULL\n");

	len = strlen(host) + strlen("-dnsdate") + 1;
	file = xmalloc(len);
	strlcpy(file, host, len);
	strlcat(file, "-dnsdate", len);
	buf[MAX_BUF - 1] = '\0';
	snprintf(buf, sizeof buf - 1, "%u", (unsigned int)date);

	write_dnsfile(file, buf);
	free(file);
}

/* assumes that if ip is non-NULL, it is valid */
static void write_dnsip(char *host, char *ip)
{
	int len;
	char *file, buf[MAX_BUF];

	if (!host)
		suicide("FATAL - write_dnsip: host is NULL\n");
	if (!ip)
		suicide("FATAL - write_dnsip: ip is NULL\n");

	len = strlen(host) + strlen("-dnsip") + 1;
	file = xmalloc(len);
	strlcpy(file, host, len);
	strlcat(file, "-dnsip", len);
	strlcpy(buf, ip, sizeof buf);

	write_dnsfile(file, buf);
	free(file);
}

/* assumes that if ip is non-NULL, it is valid */
static void write_dnserr(char *host, return_codes code)
{
	int len;
	char *file, buf[MAX_BUF], *error;

	if (!host)
		suicide("FATAL - write_dnserr: host is NULL\n");

	len = strlen(host) + strlen("-dnserr") + 1;
	file = xmalloc(len);
	strlcpy(file, host, len);
	strlcat(file, "-dnserr", len);

	switch (code) {
	case RET_NOTFQDN:
		error = "notfqdn";
		break;
	case RET_NOHOST:
		error = "nohost";
		break;
	case RET_NOTYOURS:
		error = "!yours";
		break;
	case RET_ABUSE:
		error = "abuse";
		break;
	default:
		error = "unknown";
		break;
	}
	strlcpy(buf, error, sizeof buf);

	write_dnsfile(file, buf);
	free(file);
}

static void add_to_return_code_list(return_codes name,
					 return_code_list_t **list)
{
	return_code_list_t *item, *t;

	if (!list)
		return;

	item = xmalloc(sizeof (return_code_list_t));
	item->code = name;
	item->next = NULL;

	if (!*list) {
		*list = item;
		return;
	}
	t = *list;
	while (t) {
		if (t->next == NULL) {
			t->next = item;
			return;
		}
		t = t->next;
	}

	log_line("add_to_return_code_list: failed to add item\n");
	free(item);
}

static void free_return_code_list(return_code_list_t *head)
{
    return_code_list_t *p = head, *q = NULL;

    while (p != NULL) {
        q = p;
        p = q->next;
        free(q);
    }
}

int get_return_code_list_arity(return_code_list_t *list)
{
	int i;
	return_code_list_t *c;

	for (c = list, i = 0; c != NULL; c = c->next, ++i);
	return i;
}

/* not really well documented, so here:
 * return from the server will be stored in a buffer
 * buffer will look like:
	good 1.12.123.9
	nochg 1.12.123.9
	nochg 1.12.123.9
	nochg 1.12.123.9
 */
static void decompose_buf_to_list(char *buf)
{
	char tok[MAX_BUF], *point = buf;
	int i;

	free_return_code_list(return_list);
	return_list = NULL;


	while (*point != '\0') {
		while (*point != '\0' && isspace(*point))
			point++;
		memset(tok, '\0', sizeof tok);

		/* fetch one token */
		i = 0;
		while (*point != '\0' && !isspace(*point))
			tok[i++] = *(point++);

		if (strstr(tok, "badsys")) {
			add_to_return_code_list(RET_BADSYS, &return_list);
			continue;
		}
		if (strstr(tok, "badagent")) {
			add_to_return_code_list(RET_BADAGENT, &return_list);
			continue;
		}
		if (strstr(tok, "badauth")) {
			add_to_return_code_list(RET_BADAUTH, &return_list);
			continue;
		}
		if (strstr(tok, "!donator")) {
			add_to_return_code_list(RET_NOTDONATOR, &return_list);
			continue;
		}
		if (strstr(tok, "good")) {
			add_to_return_code_list(RET_GOOD, &return_list);
			continue;
		}
		if (strstr(tok, "nochg")) {
			add_to_return_code_list(RET_NOCHG, &return_list);
			continue;
		}
		if (strstr(tok, "notfqdn")) {
			add_to_return_code_list(RET_NOTFQDN, &return_list);
			continue;
		}
		if (strstr(tok, "nohost")) {
			add_to_return_code_list(RET_NOHOST, &return_list);
			continue;
		}
		if (strstr(tok, "!yours")) {
			add_to_return_code_list(RET_NOTYOURS, &return_list);
			continue;
		}
		if (strstr(tok, "abuse")) {
			add_to_return_code_list(RET_ABUSE, &return_list);
			continue;
		}
		if (strstr(tok, "numhost")) {
			add_to_return_code_list(RET_NUMHOST, &return_list);
			continue;
		}
		if (strstr(tok, "dnserr")) {
			add_to_return_code_list(RET_DNSERR, &return_list);
			continue;
		}
		if (strstr(tok, "911")) {
			add_to_return_code_list(RET_911, &return_list);
			continue;
		}
	}
}

/* -1 indicates hard error, -2 soft error on hostname, 0 success */
static int postprocess_update(char *host, char *curip, return_codes retcode)
{
	int ret = -1;

	switch (retcode) {
	default:
		log_line(
		"%s: FATAL: postprocess_update() has invalid state\n", host);
		break;
	case RET_BADSYS:
		log_line(
		"%s: [badsys] - FATAL: Should never happen!\n", host);
		break;
	case RET_BADAGENT:
		log_line(
		"%s: [badagent] - FATAL: Client program is banned!\n", host);
		break;
	case RET_BADAUTH:
		log_line(
		"%s: [badauth] - FATAL: Invalid username or password.\n", host);
		break;
	case RET_NOTDONATOR:
		log_line(
		"%s: [!donator] - FATAL: Option requested that is only allowed to donating users (such as 'offline').\n", host);
		break;
	case RET_NOTFQDN:
		log_line(
		"%s: [notfqdn] - FATAL: Hostname isn't a fully-qualified domain name (such as 'hostname.dyndns.org')'.\n", host);
		ret = -2;
		break;
	case RET_NOHOST:
		log_line(
		"%s: [nohost] - FATAL: Hostname doesn't exist or wrong service type specified (dyndns, static, custom).\n", host);
		ret = -2;
		break;
	case RET_NOTYOURS:
		log_line(
		"%s: [!yours] - FATAL: Hostname exists, but doesn't belong to your account.\n", host);
		ret = -2;
		break;
	case RET_ABUSE:
		log_line(
		"%s: [abuse] - FATAL: Hostname is banned for abuse.\n", host);
		ret = -2;
		break;
	case RET_NUMHOST:
		log_line(
		"%s: [numhost] - FATAL: Too many or too few hosts found.\n", host);
		break;
	case RET_DNSERR:
		log_line(
		"%s: [dnserr] - FATAL: DNS error encountered by server.\n", host);
		break;
	case RET_911:
		log_line(
		"%s: [911] - FATAL: Critical error on dyndns.org's hardware.  Check http://www.dyndns.org/news/status/ for details.\n", host);
		break;
	/* Don't hardfail, 'success' */
	case RET_GOOD:
		log_line(
		"%s: [good] - Update successful.\n", host);
		write_dnsip(host, curip);
		write_dnsdate(host, time(0));
		ret = 0;
		break;
	case RET_NOCHG:
		log_line(
		"%s: [nochg] - Unnecessary update; further updates will be considered abusive.\n", host);
		write_dnsip(host, curip);
		write_dnsdate(host, time(0));
		ret = 0;
		break;
	}
	return ret;
}

static void update_ip_buf_error(size_t len, size_t size)
{
	if (len > size)
		suicide("FATAL - config file would overflow a fixed buffer\n");
}

static void update_ip(char *curip)
{
	CURL *h;
	CURLcode ret;
	int len, runonce = 0;
	char url[MAX_BUF]; /* XXX: better to dynamically allocate here */
	char tbuf[32];
	char unpwd[256];
	char useragent[64];
	char curlerror[CURL_ERROR_SIZE];
	strlist_t *t;
	return_code_list_t *u;
	return_codes ret2;
	conn_data_t data;

	if (!update_list || !curip)
		return;

	/* set up the authentication url */
	if (use_ssl) {
		len = strlcpy(url,
			"https://members.dyndns.org/nic/update?", sizeof url);
		update_ip_buf_error(len, sizeof url);
	} else {
		len = strlcpy(url,
			"http://members.dyndns.org/nic/update?", sizeof url);
		update_ip_buf_error(len, sizeof url);
	}

	switch (dyndns_conf.system) {
		case SYSTEM_STATDNS:
			strlcpy(tbuf, "statdns", sizeof tbuf);
			break;
		case SYSTEM_CUSTOMDNS:
			strlcpy(tbuf, "custom", sizeof tbuf);
			break;
		default:
			strlcpy(tbuf, "dyndns", sizeof tbuf);
			break;
	}
	len = strlcat(url, "system=", sizeof url);
	update_ip_buf_error(len, sizeof url);
	len = strlcat(url, tbuf, sizeof url);
	update_ip_buf_error(len, sizeof url);

	len = strlcat(url, "&hostname=", sizeof url);
	update_ip_buf_error(len, sizeof url);
	for (t = update_list, runonce = 0; t != NULL; t = t->next) {
		if (runonce) {
			len = strlcat(url, ",", sizeof url);
			update_ip_buf_error(len, sizeof url);
		}
		runonce = 1;
		len = strlcat(url, t->str, sizeof url);
		update_ip_buf_error(len, sizeof url);
	}

	len = strlcat(url, "&myip=", sizeof url);
	update_ip_buf_error(len, sizeof url);
	len = strlcat(url, curip, sizeof url);
	update_ip_buf_error(len, sizeof url);

	switch (dyndns_conf.wildcard) {
		case WC_YES:
			strlcpy(tbuf, "ON", sizeof tbuf);
			break;
		case WC_NO:
			strlcpy(tbuf, "OFF", sizeof tbuf);
			break;
		default:
			strlcpy(tbuf, "NOCHG", sizeof tbuf);
			break;
	}
	len = strlcat(url, "&wildcard=", sizeof url);
	update_ip_buf_error(len, sizeof url);
	len = strlcat(url, tbuf, sizeof url);
	update_ip_buf_error(len, sizeof url);

	len = strlcat(url, "&mx=", sizeof url);
	update_ip_buf_error(len, sizeof url);
	if (dyndns_conf.mx == NULL) {
		len = strlcat(url, "NOCHG", sizeof url);
		update_ip_buf_error(len, sizeof url);
	} else {
		len = strlcat(url, dyndns_conf.mx, sizeof url);
		update_ip_buf_error(len, sizeof url);
	}

	switch (dyndns_conf.backmx) {
		case BMX_YES:
			strlcpy(tbuf, "YES", sizeof tbuf);
			break;
		case BMX_NO:
			strlcpy(tbuf, "NO", sizeof tbuf);
			break;
		default:
			strlcpy(tbuf, "NOCHG", sizeof tbuf);
			break;
	}
	len = strlcat(url, "&backmx=", sizeof url);
	update_ip_buf_error(len, sizeof url);
	len = strlcat(url, tbuf, sizeof url);
	update_ip_buf_error(len, sizeof url);

	switch (dyndns_conf.offline) {
		case OFFLINE_YES:
			strlcpy(tbuf, "YES", sizeof tbuf);
			break;
		default:
			strlcpy(tbuf, "NO", sizeof tbuf);
			break;
	}
	len = strlcat(url, "&offline=", sizeof url);
	update_ip_buf_error(len, sizeof url);
	len = strlcat(url, tbuf, sizeof url);
	update_ip_buf_error(len, sizeof url);


	/* set up username:password pair */
	len = strlcpy(unpwd, dyndns_conf.username, sizeof unpwd);
	update_ip_buf_error(len, sizeof unpwd);
	len = strlcat(unpwd, ":", sizeof unpwd);
	update_ip_buf_error(len, sizeof unpwd);
	len = strlcat(unpwd, dyndns_conf.password, sizeof unpwd);
	update_ip_buf_error(len, sizeof unpwd);


	/* set up useragent */
	len = strlcpy(useragent, "ndyndns/", sizeof useragent);
	update_ip_buf_error(len, sizeof useragent);
	len = strlcat(useragent, NDYNDNS_VERSION, sizeof useragent);
	update_ip_buf_error(len, sizeof useragent);

	data.buf = xmalloc(MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1);
	memset(data.buf, '\0', MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1);
	data.buflen = MAX_CHUNKS * CURL_MAX_WRITE_SIZE + 1;
	data.idx = 0;

	log_line("update url: [%s]\n", url);
	h = curl_easy_init();
	curl_easy_setopt(h, CURLOPT_URL, url);
	curl_easy_setopt(h, CURLOPT_USERPWD, unpwd);
	curl_easy_setopt(h, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	curl_easy_setopt(h, CURLOPT_USERAGENT, useragent);
	curl_easy_setopt(h, CURLOPT_ERRORBUFFER, curlerror);
	curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_response);
	curl_easy_setopt(h, CURLOPT_WRITEDATA, &data);
	if (use_ssl)
		 curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, (long)0);
	ret = curl_easy_perform(h);
	curl_easy_cleanup(h);

	switch (ret) {
	case CURLE_OK:
		break;
	case CURLE_UNSUPPORTED_PROTOCOL:
	case CURLE_FAILED_INIT:
	case CURLE_URL_MALFORMAT:
	case CURLE_URL_MALFORMAT_USER:
	case CURLE_SSL_CONNECT_ERROR:
	case CURLE_HTTP_RANGE_ERROR:
	case CURLE_HTTP_POST_ERROR:
	case CURLE_ABORTED_BY_CALLBACK:
	case CURLE_BAD_FUNCTION_ARGUMENT:
	case CURLE_BAD_CALLING_ORDER:
	case CURLE_BAD_PASSWORD_ENTERED:
	case CURLE_SSL_PEER_CERTIFICATE:
	case CURLE_SSL_ENGINE_NOTFOUND:
	case CURLE_SSL_ENGINE_SETFAILED:
	case CURLE_SSL_CERTPROBLEM:
	case CURLE_SSL_CIPHER:
	case CURLE_SSL_CACERT:
	case CURLE_BAD_CONTENT_ENCODING:
	case CURLE_SSL_ENGINE_INITFAILED:
	case CURLE_LOGIN_DENIED:
		suicide("Update failed.  cURL returned a fatal error: [%s].  Exiting.\n", curlerror);
		break;
	case CURLE_OUT_OF_MEMORY:
	case CURLE_READ_ERROR:
	case CURLE_TOO_MANY_REDIRECTS:
	case CURLE_RECV_ERROR:
		suicide("Update status unknown.  cURL returned a fatal error: [%s].  Exiting.\n", curlerror);
		break;
	case CURLE_COULDNT_RESOLVE_PROXY:
	case CURLE_COULDNT_RESOLVE_HOST:
	case CURLE_COULDNT_CONNECT:
	case CURLE_OPERATION_TIMEOUTED:
	case CURLE_HTTP_PORT_FAILED:
	case CURLE_GOT_NOTHING:
	case CURLE_SEND_ERROR:
		log_line("Temporary error connecting to host: [%s].  Queuing for retry.\n", curlerror);
		goto out;
		break;
	default:
		log_line("cURL returned nonfatal error: [%s]\n", curlerror);
		break;
	}

	decompose_buf_to_list(data.buf);
	if (get_strlist_arity(update_list) !=
		get_return_code_list_arity(return_list)) {
		log_line("list arity doesn't match, updates may be suspect\n");
	}

	for (t = update_list, u = return_list;
		t != NULL && u != NULL; t = t->next, u = u->next) {

		ret2 = postprocess_update(t->str, curip, u->code);
		switch (ret2) {
		case -1:
		default:
			exit(EXIT_FAILURE);
			break;
		case -2:
			log_line("[%s] has a configuration problem.  Refusing to update until %s-dnserr is removed.\n", t->str, t->str);
			write_dnserr(t->str, ret2);
			remove_host_from_host_data_list(&dyndns_conf, t->str);
			break;
		case 0:
			modify_hostdate_in_list(&dyndns_conf, t->str, time(0));
			modify_hostip_in_list(&dyndns_conf, t->str, curip);
			break;
		}
	}
out:
	free(data.buf);
}

static void do_work(void)
{
	char *curip = NULL;
	struct in_addr inr;
	host_data_t *t;

	log_line("updating to interface: [%s]\n", ifname);

	while (1) {
		free(curip);

		if (pending_exit)
			exit(EXIT_SUCCESS);

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

		free_strlist(update_list);
		free_return_code_list(return_list);
		update_list = NULL;
		return_list = NULL;

		for (t = dyndns_conf.hostlist; t != NULL; t = t->next) {
			if (strcmp(curip, t->ip)) {
				log_line("adding for update [%s]\n", t->host);
				add_to_strlist(t->host, &update_list);
				continue;
			}
			if (dyndns_conf.system == SYSTEM_DYNDNS &&
				time(0) - t->date > REFRESH_INTERVAL) {
				log_line("adding for refresh [%s]\n", t->host);
				add_to_strlist(t->host, &update_list);
			}
		}

		if (update_list)
			update_ip(curip);
sleep:
		sleep(update_interval);
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

int main(int argc, char** argv) {
  int c, t, uid = 0, gid = 0, cfgstdin = 0;
  char pidfile[MAX_PATH_LENGTH] = PID_FILE_DEFAULT;
  char conffile[MAX_PATH_LENGTH] = CONF_FILE_DEFAULT;
  char *p;
  struct passwd *pws;
  struct group *grp;


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
"Copyright (C) 2005-2010 Nicholas J. Kain\n"
"Usage: ndyndns [OPTIONS]\n"
"  -d, --detach                detach from TTY and daemonize\n"
"  -n, --nodetach              stay attached to TTY\n"
"  -q, --quiet                 don't print to std(out|err) or log\n"
"  -c, --chroot                path where ndyndns should chroot\n"
"  -x, --disable-chroot        do not actually chroot (not recomended)\n"
"  -f, --file                  configuration file\n"
"  -F, --cfg-stdin             read configuration file from standard input\n"
"  -p, --pidfile               pidfile path\n");
            printf(
"  -u, --user                  user name that ndyndns should run as\n"
"  -g, --group                 group name that ndyndns should run as\n"
"  -i, --interface             interface ip to check (default: ppp0)\n"
"  -r, --remote                get ip from remote dyndns host (overrides -i)\n"
"  -h, --help                  print this help and exit\n"
"  -v, --version               print version information and exit\n");
            exit(EXIT_FAILURE);
            break;

        case 'v':
            printf("ndyndns %s, dyndns update client.  Licensed under GNU GPL.\n", NDYNDNS_VERSION);
            printf(
"Copyright (C) 2005-2010 Nicholas J. Kain\n"
"This is free software; see the source for copying conditions.  There is NO\n"
"WARRANTY; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");
            exit(EXIT_FAILURE);
            break;

        case 'r':
            update_from_remote = 1;
            update_interval = 600;
            break;

        case 'd':
            gflags_detach = 1;
            break;

        case 'n':
            gflags_detach = 0;
            break;

        case 'q':
            gflags_quiet = 1;
            break;

        case 'x':
            disable_chroot();
            break;

        case 'c':
            update_chroot(optarg);
            break;

        case 'f':
            strlcpy(conffile, optarg, sizeof conffile);
            break;

        case 'F':
            cfgstdin = 1;
            break;

        case 'p':
            strlcpy(pidfile, optarg, sizeof pidfile);
            break;

        case 'u':
            t = (unsigned int) strtol(optarg, &p, 10);
            if (*p != '\0') {
                pws = getpwnam(optarg);
                if (pws) {
                    uid = (int)pws->pw_uid;
                    if (!gid)
                        gid = (int)pws->pw_gid;
                } else suicide("FATAL - Invalid uid specified.\n");
            } else
                uid = t;
            break;

        case 'g':
            t = (unsigned int) strtol(optarg, &p, 10);
            if (*p != '\0') {
                grp = getgrnam(optarg);
                if (grp) {
                    gid = (int)grp->gr_gid;
                } else suicide("FATAL - Invalid gid specified.\n");
            } else
                gid = t;
            break;

	case 'i':
		strlcpy(ifname, optarg, sizeof ifname);
		break;
    }
  }

  init_dyndns_conf(&dyndns_conf);
  t = parse_config(cfgstdin ? NULL : conffile, &dyndns_conf);
  if (t)
	suicide("FATAL - bad configuration file, exiting.\n");

  if (chroot_enabled() && getuid())
      suicide("FATAL - I need root for chroot!\n");

  if (gflags_detach)
	if (daemon(0,0))
		suicide("FATAL - detaching fork failed\n");

  fail_on_fdne(pidfile, "w");
  write_pid(pidfile);

  umask(077);
  fix_signals();

  if (!chroot_exists())
      suicide("FATAL - No chroot path specified.  Refusing to run.\n");

  /* Note that failure cases are handled by called fns. */
  imprison(get_chroot());
  drop_root(uid, gid);

  /* Cover our tracks... */
  wipe_chroot();
  memset(conffile, '\0', sizeof conffile);
  memset(pidfile, '\0', sizeof pidfile);

  curl_global_init(CURL_GLOBAL_ALL);
  use_ssl = check_ssl();

  do_work();

  exit(EXIT_SUCCESS);
}

