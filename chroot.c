/* chroot.c - chroots ndyndns jobs
 *
 * (C) 2005-2007 Nicholas J. Kain <njkain at gmail dot com>
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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>

#include "defines.h"
#include "log.h"
#include "nstrl.h"

static char chrootd[MAX_PATH_LENGTH] = "\0";
static int chroot_modified;

void update_chroot(char *path)
{
	strlcpy(chrootd, path, sizeof chrootd);
	chroot_modified = 1;
}

int chroot_exists(void)
{
	return chroot_modified;
}

char *get_chroot(void)
{
	return chrootd;
}

void wipe_chroot(void)
{
	memset(chrootd, '\0', sizeof chrootd);
}

void imprison(char *path)
{
	int ret;

	if (path == NULL) return;

	ret = chdir(path);
	if (ret) {
		log_line("Failed to chdir(%s).  Not invoking job.", path);
		exit(EXIT_FAILURE);
	}

	ret = chroot(path);
	if (ret) {
		log_line("Failed to chroot(%s).  Not invoking job.", path);
		exit(EXIT_FAILURE);
	}
}

void drop_root(uid_t uid, gid_t gid)
{
    if (uid == 0 || gid == 0) {
        log_line("FATAL - drop_root: attempt to drop root to root?\n");
        exit(EXIT_FAILURE);
    }

    if (setregid(gid, gid) == -1 || setreuid(uid, uid) == -1) {
        log_line("FATAL - drop_root: failed to drop root!\n");
        exit(EXIT_FAILURE);
    }
}

