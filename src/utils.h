#ifndef UTILS_H
#define UTILS_H

#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>

#define UNUSED __attribute__((unused))
#define RETERR(x) do { errno = x; return -1; } while(0)

int mkdir_r(const char *path);
int combine_path(char *s, const char *root, const char *path);
int strrmchr(char* str, int index);
int setcloexec(int fd);
int pipe_c(int pipedes[2]);

#endif
