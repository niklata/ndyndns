/* bsd.h - BSD-specific functions include
 *
 * (C) 2004-2007 Nicholas J. Kain <njk@aerifal.cx>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef __NJK_IFCHD_BSD_H_
#define __NJK_IFCHD_BSD_H_ 1
char *get_interface_ip(char *ifname);
void drop_root(uid_t uid, gid_t gid);
#endif

