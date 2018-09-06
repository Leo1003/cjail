#ifndef SIMPLE_SECCOMP_H
#define SIMPLE_SECCOMP_H

enum config_type {
    CFG_WHITELIST,
    CFG_BLACKLIST
};

enum deny_method {
    DENY_KILL,
    DENY_TRAP,
    DENY_ERRNO
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

struct args_rule {
    enum compare cmp;
    unsigned long long value;
};

struct seccomp_rule {
    enum rule_type type;
    int syscall;
    struct args_rule args[6];
};

struct seccomp_config {
    enum deny_method deny_action;
    unsigned int debugmode;
    unsigned int rules_count;
    struct seccomp_rule *rules;
};

#endif
