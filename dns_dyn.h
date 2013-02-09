#ifndef NDYNDNS_DNS_DYN_H_
#define NDYNDNS_DNS_DYN_H_
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

#include "cfg.h"

typedef enum {
    WC_NOCHANGE,
    WC_YES,
    WC_NO
} wc_state;

typedef enum {
    BMX_NOCHANGE,
    BMX_YES,
    BMX_NO
} backmx_state;

typedef enum {
    OFFLINE_NO,
    OFFLINE_YES
} offline_state;

typedef enum {
    SYSTEM_DYNDNS,
    SYSTEM_STATDNS,
    SYSTEM_CUSTOMDNS
} dyndns_system;

typedef struct {
    char *username;
    char *password;
    hostdata_t *hostlist;
    char *mx;
    wc_state wildcard;
    backmx_state backmx;
    offline_state offline;
    dyndns_system system;
} dyndns_conf_t;

extern dyndns_conf_t dyndns_conf;
void init_dyndns_conf();

void dd_work(char *curip);

#endif
