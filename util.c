#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>

#include "util.h"
#include "log.h"

void *xmalloc(size_t size) {
	void *ret;

	ret = malloc(size);
	if (ret == NULL)
		suicide("FATAL - malloc() failed\n");
	return ret;
}

void null_crlf(char *data) {
	char *p = data;

	while (*p != '\0') {
		if (isalnum(*p) || ispunct(*p)) {
			++p;
			continue;
		}
		*p = '\0';
		++p;
	}
}

