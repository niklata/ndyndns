/* strlist.c - string list functions
 *
 * (C) 2005-2010 Nicholas J. Kain <njkain at gmail dot com>
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
#include <stdlib.h>
#include <string.h>

#include "nstrl.h"
#include "util.h"
#include "strlist.h"

void add_to_strlist(char *name, strlist_t **list)
{
	strlist_t *item, *t;
	char *s;
	unsigned int len;

	if (!list || !name) return;

	len = strlen(name) + 1;
	if (len == 1) return;
	s = xmalloc(len);
	strlcpy(s, name, len);

	item = xmalloc(sizeof (strlist_t));
	item->str = s;
	item->next = NULL;

	if (!*list) {
		*list = item;
		return;
	}

	t = *list;
	while (t) {
		if (t->next == NULL) {
			t->next = item;
			return;
		}
		t = t->next;
	}

	free(item); /* should be impossible, but hey */
	free(s);
	return;
}

void free_strlist(strlist_t *head)
{
    strlist_t *p = head, *q = NULL;

    while (p != NULL) {
        free(p->str);
        q = p;
        p = q->next;
        free(q);
    }
}

void free_stritem(strlist_t **p)
{
    strlist_t *q;

    if (!p) return;
    if (!*p) return;

    q = (*p)->next;
    free((*p)->str);
    free(*p);
    *p = q;
}

int get_strlist_arity(strlist_t *list)
{
	int i;
	strlist_t *c;

	for (c = list, i = 0; c != NULL; c = c->next, ++i);
	return i;
}


