/**
 * @internal
 * @file simple_seccomp.h
 * @brief basic seccomp rules header
 */
#ifndef SIMPLE_SECCOMP_H
#define SIMPLE_SECCOMP_H

#include <linux/filter.h>
#include <sys/types.h>

#define SC_ALLOC_BASE 10
#define TRACE_MAGIC 28962
#define TRACE_KILL_MAGIC 3666

#ifndef _DOXYGEN
enum config_type {
    CFG_WHITELIST,
    CFG_BLACKLIST
};

enum deny_method {
    DENY_KILL,
    DENY_TRAP,
    DENY_ERRNO,
    DENY_TRACE,
    DENY_TRACE_KILL
};

enum rule_type {
    RULE_ALLOW,
    RULE_DENY
};

enum compare {
    CMP_NONE = 0,
    CMP_EQ,
    CMP_NE,
    CMP_GT,
    CMP_GE,
    CMP_LT,
    CMP_LE,
    CMP_MASK
};
#endif

struct args_rule {
    enum compare cmp;
    u_int64_t value;
    u_int64_t mask;
};

struct seccomp_rule {
    enum rule_type type;
    int syscall;
    struct args_rule args[6];
};

//NOTE: This is a private struct
struct seccomp_config {
    enum config_type type;
    enum deny_method deny_action;
    size_t rules_alloc;
    size_t rules_count;
    struct seccomp_rule *rules;
};

int scconfig_compile(const struct seccomp_config *cfg, struct sock_fprog *bpf);
struct seccomp_config * scconfig_init();
enum deny_method scconfig_get_deny(const struct seccomp_config *cfg);
void scconfig_set_deny(struct seccomp_config *cfg, enum deny_method deny);
enum config_type scconfig_get_type(const struct seccomp_config *cfg);
void scconfig_set_type(struct seccomp_config *cfg, enum config_type type);
int scconfig_clear(struct seccomp_config *cfg);
int scconfig_add(struct seccomp_config *cfg, const struct seccomp_rule *rules, size_t len);
int scconfig_remove(struct seccomp_config *cfg, size_t i, size_t len);
struct seccomp_rule * scconfig_get_rule(struct seccomp_config * cfg, size_t i);
size_t scconfig_len(const struct seccomp_config *cfg);
int scconfig_allocate(struct seccomp_config *cfg, size_t len);
void scconfig_free(struct seccomp_config *cfg);

#endif
