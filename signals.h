/* signals.h - abstracts signal handling
 *
 * (C) 2004-2008 Nicholas J. Kain <njkain at gmail dot com>
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

#ifndef __NJK_SIGNALS_H_
#define __NJK_SIGNALS_H_ 1
void hook_signal(int signum, void (*fn)(int), int flags);
void disable_signal(int signum);
#endif

