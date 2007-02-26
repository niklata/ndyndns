#ifndef __NJK_STRLIST_H_
#define __NJK_STRLIST_H_ 1

typedef struct 
{
    char *str;
    void *next;
} strlist_t;

void add_to_strlist(char *name, strlist_t **list);
void free_strlist(strlist_t *head);
void free_stritem(strlist_t **p);
int get_strlist_arity(strlist_t *list);

#endif
