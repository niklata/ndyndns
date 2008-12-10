/* pidfile.h - process id file functions
 *
 * (C) 2003-2007 Nicholas J. Kain <njkain at gmail dot com>
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

#ifndef __NJK_PIDFILE_H_
#define __NJK_PIDFILE_H_ 1
void write_pid(char *file);
void fail_on_fdne(char *file, char *mode);
#endif

