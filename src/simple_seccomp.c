/**
 * @internal
 * @file simple_seccomp.c
 * @brief basic seccomp rules source
 */
#include "logger.h"
#include "simple_seccomp.h"
#include "utils.h"

#include <errno.h>
#include <linux/filter.h>
#include <linux/memfd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include <seccomp.h>

void default_cb(pid_t pid, unsigned long data, struct user_regs_struct *regs)
{
    if (data == TRACE_KILL_MAGIC) {
        infof("Killing process %d...\n", pid);
        kill(pid, SIGKILL);
    }
    infof("Process: %d, triggered systemcall: %llu\n", pid, regs->orig_rax);
}

static int rule_compile_add(scmp_filter_ctx ctx, uint32_t denycode, const struct seccomp_rule rule)
{
    struct scmp_arg_cmp args[6];
    int args_cnt = 0;
    uint32_t action = denycode;
    if (rule.type == RULE_ALLOW) {
        action = SCMP_ACT_ALLOW;
    }
    for (int i = 0; i < 6; i++) {
        if (rule.args[i].cmp == CMP_NONE) {
            continue;
        }
        switch (rule.args[i].cmp) {
            case CMP_NONE:
                continue;
            case CMP_EQ:
                args[args_cnt].op = SCMP_CMP_EQ;
                break;
            case CMP_NE:
                args[args_cnt].op = SCMP_CMP_NE;
                break;
            case CMP_GT:
                args[args_cnt].op = SCMP_CMP_GT;
                break;
            case CMP_GE:
                args[args_cnt].op = SCMP_CMP_GE;
                break;
            case CMP_LT:
                args[args_cnt].op = SCMP_CMP_LT;
                break;
            case CMP_LE:
                args[args_cnt].op = SCMP_CMP_LE;
                break;
            case CMP_MASK:
                args[args_cnt].op = SCMP_CMP_MASKED_EQ;
                break;
            default:
                errno = EINVAL;
                return -1;
        }
        args[args_cnt].arg = i;
        if (rule.args[i].cmp == CMP_MASK) {
            args[args_cnt].datum_a = rule.args[i].mask;
            args[args_cnt].datum_b = rule.args[i].value;
        } else {
            args[args_cnt].datum_a = rule.args[i].value;
        }
        args_cnt++;
    }
    devf("action: %x\n", action);
    devf("syscall: %d\n", rule.syscall);
    devf("args_cnt: %d\n", args_cnt);
    int ret = seccomp_rule_add_array(ctx, action, rule.syscall, args_cnt, args);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return 0;
}

int scconfig_compile(const struct seccomp_config *cfg, struct sock_fprog *bpf)
{
    if (!cfg) {
        errno = EINVAL;
        return -1;
    }
    scmp_filter_ctx ctx;
    uint32_t denycode = 0;
    switch (cfg->deny_action) {
        case DENY_KILL:
            denycode = SCMP_ACT_KILL;
            break;
        case DENY_TRAP:
            denycode = SCMP_ACT_TRAP;
            break;
        case DENY_ERRNO:
            denycode = SCMP_ACT_ERRNO(ENOSYS);
            break;
        case DENY_TRACE:
            warnf("DENY_TRACE is not implemented yet!\n");
            denycode = SCMP_ACT_TRACE(TRACE_MAGIC);
            break;
        case DENY_TRACE_KILL:
            warnf("DENY_TRACE_KILL is not implemented yet!\n");
            denycode = SCMP_ACT_TRACE(TRACE_KILL_MAGIC);
            break;
    }
    if (cfg->type == CFG_BLACKLIST) {
        ctx = seccomp_init(SCMP_ACT_ALLOW);
    } else {
        ctx = seccomp_init(denycode);
    }
    if (!ctx) {
        PFTL("init context");
        goto error;
    }

    for (unsigned i = 0; i < cfg->rules_count; i++) {
        if ((cfg->rules[i].type == RULE_DENY && cfg->type == CFG_WHITELIST) ||
            (cfg->rules[i].type == RULE_ALLOW && cfg->type == CFG_BLACKLIST)) {
            continue;
        }
        if (rule_compile_add(ctx, denycode, cfg->rules[i])) {
            PFTL("add rules");
            goto error;
        }
    }

    // compile libseccomp rule to bpf program
    // libseccomp only accept fd, so we use memfd to generate bpf program
    int memfd = syscall(__NR_memfd_create, "", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (memfd < 0) {
        PFTL("create memfd");
        goto error;
    }
    seccomp_export_bpf(ctx, memfd);
    size_t bpf_size = lseek(memfd, 0, SEEK_END);
    if (bpf_size < 0) {
        PFTL("get memory file size");
        goto error_memfd;
    }
    bpf->len = bpf_size / sizeof(struct sock_filter);
    bpf->filter = mmap(NULL, bpf_size, PROT_READ, MAP_PRIVATE, memfd, 0);
    if (bpf->filter == MAP_FAILED) {
        PFTL("mmap memfd");
        goto error_memfd;
    }

    seccomp_release(ctx);
    close(memfd);
    return 0;

error_memfd:
    close(memfd);
error:
    PFTL("compile seccomp config");
    seccomp_release(ctx);
    return -1;
}

struct seccomp_config * scconfig_init()
{
    struct seccomp_config *cfg = malloc(sizeof(struct seccomp_config));
    if (cfg == NULL) {
        PFTL("malloc memory");
        return NULL;
    }
    cfg->type = CFG_WHITELIST;
    cfg->deny_action = DENY_KILL;
    cfg->rules_count = 0;
    cfg->rules_alloc = SC_ALLOC_BASE;
    cfg->rules = malloc(SC_ALLOC_BASE * sizeof(struct seccomp_rule));
    if (cfg->rules == NULL) {
        PFTL("malloc memory");
        free(cfg);
        cfg = NULL; //return NULL
    }
    cfg->callback = NULL;
    return cfg;
}

enum deny_method scconfig_get_deny(const struct seccomp_config *cfg)
{
    if (!cfg) {
        errno = EINVAL;
        return 0;
    }
    return cfg->deny_action;
}

void scconfig_set_deny(struct seccomp_config* cfg, enum deny_method deny)
{
    if (!cfg) {
        errno = EINVAL;
        return;
    }
    cfg->deny_action = deny;
}

enum config_type scconfig_get_type(const struct seccomp_config *cfg)
{
    if (!cfg) {
        errno = EINVAL;
        return 0;
    }
    return cfg->type;
}

void scconfig_set_type(struct seccomp_config* cfg, enum config_type type)
{
    if (!cfg) {
        errno = EINVAL;
        return;
    }
    cfg->type = type;
}

seccomp_cb scconfig_get_callback(const struct seccomp_config* cfg)
{
    if (!cfg) {
        errno = EINVAL;
        return NULL;
    }
    return (cfg->callback ? cfg->callback : default_cb);
}

void scconfig_set_callback(struct seccomp_config* cfg, seccomp_cb callback)
{
    if (!cfg) {
        errno = EINVAL;
        return;
    }
    cfg->callback = callback;
}

void scconfig_reset_callback(struct seccomp_config* cfg)
{
    if (!cfg) {
        errno = EINVAL;
        return;
    }
    cfg->callback = NULL;
}

int scconfig_clear(struct seccomp_config* cfg)
{
    if (!cfg) {
        errno = EINVAL;
        return -1;
    }
    memset(cfg->rules, 0, sizeof(struct seccomp_rule) * cfg->rules_count);
    cfg->rules_count = 0;
    return 0;
}

int scconfig_add(struct seccomp_config* cfg, const struct seccomp_rule* rules, size_t len)
{
    if (!cfg) {
        errno = EINVAL;
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    while (cfg->rules_alloc < cfg->rules_count + len) {
        size_t new_alloc = max(cfg->rules_alloc * 2, cfg->rules_count + len + SC_ALLOC_BASE);
        if (scconfig_allocate(cfg, new_alloc))
            return -1;
    }
    memcpy(cfg->rules + cfg->rules_count, rules, len * sizeof(struct seccomp_rule));
    cfg->rules_count += len;
    return 0;
}

int scconfig_remove(struct seccomp_config* cfg, size_t i, size_t len)
{
    if (!cfg) {
        errno = EINVAL;
        return -1;
    }
    if (i + len > cfg->rules_count) {
        errno = EFAULT;
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    memmove(cfg->rules + i, cfg->rules + (i + len), (cfg->rules_count - (i + len)) * sizeof(struct seccomp_rule));
    cfg->rules_count -= len;
    return 0;
}

struct seccomp_rule * scconfig_get_rule(struct seccomp_config * cfg, size_t i)
{
    if (!cfg) {
        errno = EINVAL;
        return NULL;
    }
    if (i >= cfg->rules_count) {
        return NULL;
    }
    return &cfg->rules[i];
}

size_t scconfig_len(const struct seccomp_config* cfg)
{
    if (!cfg) {
        errno = EINVAL;
        return 0;
    }
    return cfg->rules_count;
}

int scconfig_allocate(struct seccomp_config* cfg, size_t len)
{
    if (!cfg) {
        errno = EINVAL;
        return -1;
    }
    if (len <= cfg->rules_alloc) {
        return 0;
    }
    struct seccomp_rule *tmp = (struct seccomp_rule *)realloc(cfg->rules, len * sizeof(struct seccomp_rule));
    if (tmp == NULL) {
        PFTL("realloc memory");
        return -1;
    }
    cfg->rules_alloc = len;
    cfg->rules = tmp;
    return 0;
}

void scconfig_free(struct seccomp_config* cfg)
{
    if (!cfg) {
        return;
    }
    if (cfg->rules) {
        free(cfg->rules);
        cfg->rules = NULL;
    }
    free(cfg);
}
