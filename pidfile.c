#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include "defines.h"
#include "log.h"

void write_pid(char *file) {
    FILE *f;
    char buf[MAXLINE];
    
    f = fopen(file, "w");
    if (f == NULL) {
        log_line("FATAL - failed to open pid file \"%s\"!\n", file);
        exit(EXIT_FAILURE);
    }

    snprintf(buf, sizeof buf - 1, "%i", (unsigned int)getpid());
    fwrite(buf, sizeof (char), strlen(buf), f);
    
    if (fclose(f) != 0) {
        log_line("FATAL - failed to close pid file \"%s\"!\n", file);
        exit(EXIT_FAILURE);
    }
}

void fail_on_fdne(char *file, char *mode) {
    FILE *f;

    if (file == NULL || mode == NULL) {
        log_line("fail_on_fdne: FATAL - coding bug: NULL passed\n");
        exit(EXIT_FAILURE);
    }

    f = fopen(file, mode);
    if (f == NULL) {
        log_line("FATAL - can't open file %s with mode %s!\n",
                 file, mode);
        exit(EXIT_FAILURE); 
    }
    fclose(f);
}

