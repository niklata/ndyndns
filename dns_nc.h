#ifndef NNCDNS_DNS_NC_H_
#define NNCDNS_DNS_NC_H_
/* (c) 2010-2012 Nicholas J. Kain <njkain at gmail dot com>
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

typedef struct {
    char *password;
    hostdata_t *hostlist;
} namecheap_conf_t;

extern namecheap_conf_t namecheap_conf;
void init_namecheap_conf();

void nc_work(char *curip);

#endif

