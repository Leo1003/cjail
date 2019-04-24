#ifndef TOOLS_UTILS_H
#define TOOLS_UTILS_H
#include <stdio.h>

#define perrf(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#ifdef NDEBUG
#define devf(fmt, ...)
#else
#define devf(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#endif

#endif
