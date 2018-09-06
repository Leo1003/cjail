#include "logger.h"
#include "simple_seccomp.h"

#include <errno.h>
#include <linux/filter.h>
#include <linux/memfd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include <seccomp.h>

static int rule_add(scmp_filter_ctx ctx, uint32_t denycode, const struct seccomp_rule rule)
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
    return seccomp_rule_add_array(ctx, action, rule.syscall, args_cnt, args);
}

int seccomp_config_compile(const struct seccomp_config *cfg, struct sock_fprog *bpf)
{
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
    }
    if (cfg->type == CFG_WHITELIST) {
        ctx = seccomp_init(SCMP_ACT_ALLOW);
    } else {
        ctx = seccomp_init(denycode);
    }
    if (!ctx) {
        goto error;
    }

    for (unsigned i = 0; i < cfg->rules_count; i++) {
        if (rule_add(ctx, denycode, cfg->rules[i])) {
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
