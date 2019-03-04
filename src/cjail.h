/**
 * @dir src/
 * @brief internal sources directory
 */
/**
 * @internal
 * @file src/cjail.h
 * @brief cjail main library entry point header
 */
#ifndef CJAIL_H
#define CJAIL_H

#define _GNU_SOURCE

#include <cjail/cjail.h>

#include <linux/filter.h>

struct exec_meta {
    struct cjail_ctx ctx;
    int sockpair[2];
    int cgtasksfd;
    struct sock_fprog bpf;
};

#endif
