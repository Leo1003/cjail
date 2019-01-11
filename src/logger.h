/**
 * @internal
 * @file logger.h
 * @brief logger functions header
 */
#ifndef LOGGER_H
#define LOGGER_H

#include <cjail/cjail.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

int swap_log_file();

#ifdef NDEBUG
int loggerf(enum logger_level level, const char *format, ...);
#define devf(fmt, ...) loggerf(LOG_DEBUG, "")
#define debugf(fmt, ...) loggerf(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define infof(fmt, ...) loggerf(LOG_INFO, fmt, ##__VA_ARGS__)
#define warnf(fmt, ...) loggerf(LOG_WARN, fmt, ##__VA_ARGS__)
#define errorf(fmt, ...) loggerf(LOG_ERROR, fmt, ##__VA_ARGS__)
#define fatalf(fmt, ...) loggerf(LOG_FATAL, fmt, ##__VA_ARGS__)
#define lprintf(fmt, ...) loggerf(LOG_NONE, fmt, ##__VA_ARGS__)
#else
int loggerf(enum logger_level level, const char *src, int line, const char *format, ...);
#define devf(fmt, ...) loggerf(LOG_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define debugf(fmt, ...) loggerf(LOG_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define infof(fmt, ...) loggerf(LOG_INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define warnf(fmt, ...) loggerf(LOG_WARN, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define errorf(fmt, ...) loggerf(LOG_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define fatalf(fmt, ...) loggerf(LOG_FATAL, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define lprintf(fmt, ...) loggerf(LOG_NONE, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#endif //NDEBUG

#define PWRN(name) warnf("Failed to %s: %s\n", name, strerror(errno))
#define PERR(name) errorf("Failed to %s: %s\n", name, strerror(errno))
#define PFTL(name) fatalf("Failed to %s: %s\n", name, strerror(errno))

#endif //LOGGER_H
