#ifndef UTILS_H
#define UTILS_H

#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>

#define IFERR(x) if((x) < 0)
#define perrf(x, ...) do { fprintf(stderr, x, ##__VA_ARGS__); } while(0)
#define PRINTERR(name) do { fprintf(stderr, "Failed to %s: %s\n", name, strerror(errno)); } while(0)
#ifdef NDEBUG
#define pdebugf(x, ...)
#else
#define pdebugf(x, ...) do { fprintf(stderr, x, ##__VA_ARGS__); } while(0)
#endif

int closefrom(int minfd);
void parse_cpuset(const cpu_set_t *cpuset, char *cpumask);
int mkdir_r(const char *path);
char* combine_path(char *root, char *path) __nonnull((2));

#endif
