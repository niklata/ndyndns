#ifndef NJK_CONFIG_H_
#define NJK_CONFIG_H_ 1
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

/*
ndyndns.conf
------------

username=
password=
hostname=<LIST: host1,host2,...,hostN>
mx=host (default: NOCHG)
wildcard|nowildcard (default: NOCHG)
backmx|nobackmx (default: NOCHG)
offline (default: NO)
*/
#include <time.h>

typedef struct {
    char *host;
    char *ip;
    time_t date;
    void *next;
} host_data_t;

typedef struct {
    char *host;
    char *password;
    char *ip;
    time_t date;
    void *next;
} hostpairs_t;

void init_config();
void remove_host_from_host_data_list(host_data_t **phl, char *host);
int parse_config(char *file);
#endif

