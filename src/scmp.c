#include "cjail.h"
#include "logger.h"
#include "scmp.h"
#include "utils.h"

#include <linux/filter.h>
#include <linux/memfd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include <seccomp.h>

int compile_seccomp(const struct cjail_para para, struct sock_fprog *bpf)
{
    if (!para.seccomplist) {
        return 0;
    }
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRAP);
    if (!ctx) {
        goto error;
    }

    for (int i = 0; para.seccomplist[i] >= 0; i++) {
#ifndef NDEBUG
        char *scname = seccomp_syscall_resolve_num_arch(seccomp_arch_native(),
                                                        para.seccomplist[i]);
        devf("seccomp_rule_add: %d %s\n", para.seccomplist[i], scname);
        free(scname);
        /* In the case of seccomp_syscall_resolve_num_arch() the associated
         * syscall name is returned and it remains the callers responsibility to
         * free the returned string via free(3).
         */
#endif
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, para.seccomplist[i], 0)) {
            goto error;
        }
    }
    if (para.argv) {
        //we have to prevent seccomp from blocking our execve()
        //only allow the certain argv pointer
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
                SCMP_SYS(execve), 1,
                SCMP_A1(SCMP_CMP_EQ, (scmp_datum_t)para.argv))) {
            goto error;
        }
    }

    // compile libseccomp rule to bpf program
    // libseccomp only accept fd, so we use memfd to generate bpf program
    size_t bpf_size;
    int memfd = syscall( __NR_memfd_create, "", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (memfd < 0) {
        PFTL("create memfd");
        goto error;
    }
    seccomp_export_bpf(ctx, memfd);
    bpf_size = lseek(memfd, 0, SEEK_END);
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
    PFTL("setup_seccomp");
    seccomp_release(ctx);
    return -1;
}
