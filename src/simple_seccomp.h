/**
 * @internal
 * @file simple_seccomp.h
 * @brief basic seccomp rules header
 */
#ifndef SIMPLE_SECCOMP_H
#define SIMPLE_SECCOMP_H

#include <cjail/scconfig.h>
#include "trace.h"

#include <linux/filter.h>
#include <stddef.h>
#include <sys/types.h>

#define SC_ALLOC_BASE 10

//NOTE: This is a private struct
struct seccomp_config {
    enum config_type type;
    enum deny_method deny_action;
    size_t rules_alloc;
    size_t rules_count;
    struct seccomp_rule *rules;
    seccomp_cb callback;
};

#endif
