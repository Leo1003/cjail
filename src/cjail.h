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
#include "simple_seccomp.h"
#include "filesystem.h"

#include <linux/filter.h>

struct exec_para {
    struct cjail_para para;
    int resultpipe[2];
    int cgtasksfd;
    struct sock_fprog bpf;
};

#endif
