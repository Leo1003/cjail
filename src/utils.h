#ifndef UTILS_H
#define UTILS_H

#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>

#define UNUSED __attribute__((unused))
#define RETERR(x) do { errno = x; return -1; } while(0)

#define max(a,b) \
({ __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b; })
#define min(a,b) \
({ __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a < _b ? _a : _b; })

int cpuset_tostr(const cpu_set_t *cpuset, char *str, size_t len);
int cpuset_parse(const char *str, cpu_set_t *cpuset);
int mkdir_r(const char *path);
int combine_path(char *s, const char *root, const char *path);
int strrmchr(char* str, int index);
int setcloexec(int fd);
int pipe_c(int pipedes[2]);

#endif
