/*
 * SPDX-License-Identifier: MIT
 */

#include "logging.h"

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

void do_log(FILE *stream, const char* level, const char* fmt, ...) {
    time_t now;
    time(&now);
    fprintf(stream, "%.19s [%s]: ", ctime(&now), level);
    va_list arg;
    va_start(arg, fmt);
    vfprintf(stream, fmt, arg);
    va_end(arg);
    fprintf(stream, "\n");
}
