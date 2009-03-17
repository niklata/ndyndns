/* log.c - simple logging support
 *
 * (C) 2005-2009 Nicholas J. Kain <njkain at gmail dot com>
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

#include <stdio.h>
#include <strings.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdlib.h>
#include "defines.h"

/* global logging flags */
int gflags_quiet = 0;
int gflags_detach = 1;

void log_line(char *format, ...) {
  va_list argp;

  if (format == NULL || gflags_quiet)
	return;

  if (gflags_detach) {
    openlog("ndyndns", LOG_PID, LOG_DAEMON);
    va_start(argp, format);
    vsyslog(LOG_ERR | LOG_DAEMON, format, argp);
    va_end(argp);
    closelog();
  } else {
    va_start(argp, format);
    vfprintf(stderr, format, argp);
    va_end(argp);
  }
  closelog();
}

void suicide(char *format, ...) {
  va_list argp;

  if (format == NULL || gflags_quiet)
	goto out;

  if (gflags_detach) {
    openlog("ndyndns", LOG_PID, LOG_DAEMON);
    va_start(argp, format);
    vsyslog(LOG_ERR | LOG_DAEMON, format, argp);
    va_end(argp);
    closelog();
  } else {
    va_start(argp, format);
    vfprintf(stderr, format, argp);
    va_end(argp);
    perror(NULL);
  }
  closelog();
out:
  exit(EXIT_FAILURE);
}

