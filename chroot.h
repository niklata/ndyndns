/* chroot.h - include file for chroot.c
 *
 * (C) 2005-2009 Nicholas J. Kain <njkain at gmail dot com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __NJK_CHROOT_H_
#define __NJK_CHROOT_H_ 1
void disable_chroot(void);
int chroot_enabled(void);
void update_chroot(char *path);
char *get_chroot(void);
int chroot_exists(void);
void wipe_chroot(void);
void imprison(char *path);
void drop_root(uid_t uid, gid_t gid);
#endif

