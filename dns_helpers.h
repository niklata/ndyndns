#ifndef NDYNDNS_DNS_HELPERS_H_
#define NDYNDNS_DNS_HELPERS_H_
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

extern int use_ssl;

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

void write_dnsdate(char *host, time_t date);
void write_dnsip(char *host, char *ip);
void write_dnserr(char *host, return_codes code);
int update_ip_curl_errcheck(int val, char *cerr);
void update_ip_buf_error(size_t len, size_t size);

#endif
