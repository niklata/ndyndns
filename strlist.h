/* strlist.h - string list functions
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

#ifndef __NJK_STRLIST_H_
#define __NJK_STRLIST_H_ 1

typedef struct {
    char *str;
    void *next;
} strlist_t;

void add_to_strlist(char *name, strlist_t **list);
void free_strlist(strlist_t *head);
void free_stritem(strlist_t **p);
int get_strlist_arity(strlist_t *list);

#endif
