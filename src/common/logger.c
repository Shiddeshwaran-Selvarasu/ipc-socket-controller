/**
  ******************************************************************************
  * @file    logger.c
  * @author  Shiddeshwaran-S
  * @brief   Logger implementation file.
  ******************************************************************************
  */

#include "logger.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/* Tag strings aligned with logLevel_t enum indices */
static const char *LOG_TAGS[] = {
    "NONE",   /* LOG_LEVEL_NONE */
    "ERROR",  /* LOG_LEVEL_ERROR */
    "INFO",   /* LOG_LEVEL_INFO */
    "WARN",   /* LOG_LEVEL_WARN */
    "DEBUG"   /* LOG_LEVEL_DEBUG */
};

void logger(logLevel_t log_level, const char* file, int line, const char *format, ...) {
    /* Bounds check */
    if (log_level < LOG_LEVEL_ERROR || log_level > LOG_LEVEL_DEBUG) {
        return; /* Ignore NONE or invalid */
    }

    // /* Print date and time */
    // char time_buf[32];
    // time_t now = time(NULL);
    // struct tm *tm_info = localtime(&now);
    // strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    if (log_level == LOG_LEVEL_ERROR || log_level == LOG_LEVEL_WARN) {
        printf("[%s] %s:%d: ", LOG_TAGS[log_level], file, line);
    } else {
        printf("[%s] ", LOG_TAGS[log_level]);
    }

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    /* Auto-append newline if caller omitted */
    size_t len = strlen(format);
    if (len == 0 || format[len - 1] != '\n') {
        putchar('\n');
    }
    fflush(stdout);
}
