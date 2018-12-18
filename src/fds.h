/**
 * @internal
 * @file fds.h
 * @brief file descriptor related functions header
 */
#ifndef FDS_H
#define FDS_H

#include "cjail.h"

int setup_fd(const struct cjail_para para);
int is_valid_fd(int fd);
int closefrom(int minfd);

#endif
