/**
 * @internal
 * @file loop.h
 * @brief loopback device functions header
 */
#ifndef LOOP_H
#define LOOP_H

#include <linux/loop.h>

// clang-format off
#define LOOP_LOAD_READONLY  0x1
// clang-format on

int loop_load(const char *path, int flags, struct loop_info *info);
int loop_attach(int fd, struct loop_info *info);
int loop_detach(int loop);

#endif
