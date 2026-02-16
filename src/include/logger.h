/**
  ******************************************************************************
  * @file    logger.h
  * @author  Shiddeshwaran-S
  * @brief   Logger interface header file.
  ******************************************************************************
  */

#pragma once

typedef enum {
  LOG_LEVEL_NONE = 0,
  LOG_LEVEL_ERROR,
  LOG_LEVEL_INFO,
  LOG_LEVEL_WARN,
  LOG_LEVEL_DEBUG
} logLevel_t;

/* Compile-time selected maximum log level (default: DEBUG) */
#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_DEBUG
#endif

/* Internal logging function (implemented in logger.c) */
void logger(logLevel_t log_level, const char* file, int line, const char *format, ...);

#define LOG_WARN(...)  if (LOG_LEVEL >= LOG_LEVEL_WARN) logger(LOG_LEVEL_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(...) if (LOG_LEVEL >= LOG_LEVEL_ERROR) logger(LOG_LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO(...)  if (LOG_LEVEL >= LOG_LEVEL_INFO) logger(LOG_LEVEL_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_DEBUG(...) if (LOG_LEVEL >= LOG_LEVEL_DEBUG) logger(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
