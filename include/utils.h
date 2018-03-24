#ifndef UTILS_H
#define UTILS_H

#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>

#define UNUSED __attribute__((unused))
#define IFERR(x) if((x) < 0)
#define perrf(x, ...) do { fprintf(stderr, x, ##__VA_ARGS__); } while(0)
#define PRINTERR(name) do { fprintf(stderr, "Failed to %s: %s\n", name, strerror(errno)); } while(0)
#define RETERR(x) do { errno = x; return -1; } while(0)
#ifdef NDEBUG
#define pdebugf(x, ...)
#else
#define pdebugf(x, ...) do { fprintf(stderr, x, ##__VA_ARGS__); } while(0)
#endif

int closefrom(int minfd);
int mkdir_r(const char *path);
int combine_path(char *s, const char *root, const char *path);
int strrmchr(char* str, int index);
int setcloexec(int fd);
int pipe_c(int pipedes[2]);

#endif
