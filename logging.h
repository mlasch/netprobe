/*
 * SPDX-License-Identifier: MIT
 */

#ifndef NETPROBE_LOGGING_H
#define NETPROBE_LOGGING_H

#include <stdio.h>

#define LOG_INF(...) do_log(stdout, "INFO", __VA_ARGS__)
#define LOG_ERR(...) do_log(stderr, "ERROR", __VA_ARGS__)

void do_log(__FILE *file, const char* level, const char* fmt, ...);

#endif // NETPROBE_LOGGING_H
