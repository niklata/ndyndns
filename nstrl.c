/* nstrl.c - strlcpy/strlcat implementation
 *
 * (C) 2003-2010 Nicholas J. Kain <njkain at gmail dot com>
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

#include <unistd.h>

#ifndef HAVE_STRLCPY
size_t strlcpy (char *dest, char *src, size_t size)
{
	register unsigned int i = 0;

	if (size > 0) {
		size--;
		for (i=0; size > 0 && src[i] != '\0'; ++i, size--)
			dest[i] = src[i];

		dest[i] = '\0';
	}
	while (src[i++]);

	return i;
}
#endif /* HAVE_STRLCPY */

#ifndef HAVE_STRLCAT
size_t strlcat (char *dest, char *src, size_t size)
{
	register char *d = dest;

	for (; size > 0 && *d != '\0'; size--, d++);
	return (d - dest) + strlcpy(d, src, size);
}
#endif /* HAVE_STRLCAT */

