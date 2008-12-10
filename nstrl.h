/* nstrl.h - header file for strlcpy/strlcat implementation
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

#ifndef _NJK_HAVE_STRL_
#define _NJK_HAVE_STRL_ 1
#include "config.h"
#ifndef HAVE_STRLCPY
size_t strlcpy (char *dest, char *src, size_t size);
#endif /* HAVE_STRLCPY */
#ifndef HAVE_STRLCAT
size_t strlcat (char *dest, char *src, size_t size);
#endif /* HAVE_STRLCAT */
#endif

