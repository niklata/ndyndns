/* log.c - simple logging support
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

