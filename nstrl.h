/* nstrl.h - header file for strlcpy/strlcat implementation

   (C) 2003-2007 Nicholas J. Kain <njk@aerifal.cx>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   version 2.1 as published by the Free Software Foundation.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA */

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

