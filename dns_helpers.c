/* dns_helpers.c - common functions for dynamic dns service updates
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <curl/curl.h>

#include "dns_helpers.h"
#include "config.h"
#include "defines.h"
#include "log.h"
#include "strl.h"
#include "malloc.h"
#include "util.h"

static void write_dnsfile(char *fn, char *cnts)
{
    int fd, written = 0, oldwritten, len;

    if (!fn || !cnts)
        suicide("%s: received NULL", __func__);

    fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1)
        suicide("%s: failed to open %s for write", __func__, fn);

    len = strlen(cnts);

    while (written < len) {
        oldwritten = written;
        written = write(fd, cnts + written, len - written);
        if (written == -1) {
            if (errno == EINTR) {
                written = oldwritten;
                continue;
            }
            suicide("%s: write() failed on %s", __func__, fn);
        }
    }

    fsync(fd);
    if (close(fd) == -1)
        suicide("%s: error closing %s; possible corruption", __func__, fn);
}

void write_dnsdate(char *host, time_t date)
{
    int len;
    char *file, buf[MAX_BUF];

    if (!host)
        suicide("%s: host is NULL", __func__);

    len = strlen(host) + strlen("-dnsdate") + 5;
    file = xmalloc(len);
    strnkcpy(file, "var/", len);
    strnkcat(file, host, len);
    strnkcat(file, "-dnsdate", len);
    buf[MAX_BUF - 1] = '\0';
    snprintf(buf, sizeof buf - 1, "%u", (unsigned int)date);

    write_dnsfile(file, buf);
    free(file);
}

/* assumes that if ip is non-NULL, it is valid */
void write_dnsip(char *host, char *ip)
{
    int len;
    char *file, buf[MAX_BUF];

    if (!host)
        suicide("%s: host is NULL", __func__);
    if (!ip)
        suicide("%s: ip is NULL", __func__);

    len = strlen(host) + strlen("-dnsip") + 5;
    file = xmalloc(len);
    strnkcpy(file, "var/", len);
    strnkcat(file, host, len);
    strnkcat(file, "-dnsip", len);
    strnkcpy(buf, ip, sizeof buf);

    write_dnsfile(file, buf);
    free(file);
}

/* assumes that if ip is non-NULL, it is valid */
void write_dnserr(char *host, return_codes code)
{
    int len;
    char *file, buf[MAX_BUF], *error;

    if (!host)
        suicide("%s: host is NULL", __func__);

    len = strlen(host) + strlen("-dnserr") + 5;
    file = xmalloc(len);
    strnkcpy(file, "var/", len);
    strnkcat(file, host, len);
    strnkcat(file, "-dnserr", len);

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
    strnkcpy(buf, error, sizeof buf);

    write_dnsfile(file, buf);
    free(file);
}

/* Returns 0 on success, 1 on temporary error, 2 on permanent error */
static int update_ip_curl_errcheck(int val, char *cerr)
{
    switch (val) {
        case CURLE_OK:
            return 0;
        case CURLE_UNSUPPORTED_PROTOCOL:
        case CURLE_FAILED_INIT:
        case CURLE_URL_MALFORMAT:
        case CURLE_URL_MALFORMAT_USER:
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
        case CURLE_BAD_CONTENT_ENCODING:
        case CURLE_SSL_ENGINE_INITFAILED:
        case CURLE_LOGIN_DENIED:
        case CURLE_TOO_MANY_REDIRECTS:
            log_line("Update failed.  cURL returned a fatal error: [%s].", cerr);
            return 2;
        case CURLE_OUT_OF_MEMORY:
        case CURLE_READ_ERROR:
        case CURLE_RECV_ERROR:
            log_line("Update status unknown: [%s].  Queuing for retry.", cerr);
            return 1;
        case CURLE_SSL_CONNECT_ERROR:
        case CURLE_COULDNT_RESOLVE_PROXY:
        case CURLE_COULDNT_RESOLVE_HOST:
        case CURLE_COULDNT_CONNECT:
        case CURLE_OPERATION_TIMEOUTED:
        case CURLE_HTTP_PORT_FAILED:
        case CURLE_GOT_NOTHING:
        case CURLE_SEND_ERROR:
            log_line("Temporary error connecting to host: [%s].  Queuing for retry.", cerr);
            return 1;
        default:
            log_line("cURL returned nonfatal error: [%s]", cerr);
            return 0;
    }
    return 0;
}

void dyndns_curlbuf_cpy(char *dst, char *src, size_t size)
{
    if (strnkcpy(dst, src, size))
        suicide("%s: would overflow a fixed buffer", __func__);
}

void dyndns_curlbuf_cat(char *dst, char *src, size_t size)
{
    if (strnkcat(dst, src, size))
        suicide("%s: would overflow a fixed buffer", __func__);
}

int dyndns_curl_send(char *url, conn_data_t *data, char *unpwd)
{
    CURL *h;
    CURLcode ret;
    char useragent[64];
    char curlerror[CURL_ERROR_SIZE];

    /* set up useragent */
    dyndns_curlbuf_cpy(useragent, "ndyndns/", sizeof useragent);
    dyndns_curlbuf_cat(useragent, PACKAGE_VERSION, sizeof useragent);

    log_line("update url: [%s]", url);
    h = curl_easy_init();
    curl_easy_setopt(h, CURLOPT_URL, url);
    curl_easy_setopt(h, CURLOPT_USERAGENT, useragent);
    curl_easy_setopt(h, CURLOPT_ERRORBUFFER, curlerror);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_response);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, data);
    curl_easy_setopt(h, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_easy_setopt(h, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    if (unpwd) {
        curl_easy_setopt(h, CURLOPT_USERPWD, unpwd);
        curl_easy_setopt(h, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
    }
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, (long)0);
    ret = curl_easy_perform(h);
    curl_easy_cleanup(h);
    return update_ip_curl_errcheck(ret, curlerror);
}

