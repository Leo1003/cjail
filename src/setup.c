#include "cjail.h"
#include "cgroup.h"
#include "fds.h"
#include "filesystem.h"
#include "setup.h"
#include "taskstats.h"
#include "utils.h"

#include <linux/limits.h>
#include <linux/memfd.h>
#include <linux/seccomp.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <seccomp.h>

typedef void * scmp_filter_ctx;

int setup_fs(const struct cjail_para para)
{
    if (privatize_fs()) {
        goto error;
    }
    if (jail_mount("", para.chroot, "/proc", FS_PROC, "")) {
        PRINTERR("mount procfs");
        goto error;
    }
    if (jail_mount("", para.chroot, "/dev", FS_UDEV, "")) {
        PRINTERR("mount devfs");
        goto error;
    }
    if (jail_chroot(para.chroot, para.workingDir)) {
        goto error;
    }
    return 0;

    error:
    PRINTERR("setup_fs");
    return -1;
}

int setup_cpumask(const struct cjail_para para)
{
    if (para.cpuset) {
        if (sched_setaffinity(getpid(), sizeof(*para.cpuset), para.cpuset)) {
            PRINTERR("setup_cpumask");
            return -1;
        }
    }
    return 0;
}

inline static int set_rlimit(int res, long long val)
{
    struct rlimit rl;
    rl.rlim_cur = rl.rlim_max = val;
    return setrlimit(res, &rl);
}
int setup_rlimit(const struct cjail_para para)
{
    if (para.rlim_as > 0) {
        if (set_rlimit(RLIMIT_AS, para.rlim_as * 1024))
            goto error;
        pdebugf("setup_rlimit: RLIMIT_AS set to %lld KB\n", para.rlim_as);
    }
    if (para.rlim_core >= 0) {
        if (set_rlimit(RLIMIT_CORE, para.rlim_core * 1024))
            goto error;
        pdebugf("setup_rlimit: RLIMIT_CORE set to %lld KB\n", para.rlim_core);
    }
    if (para.rlim_nofile > 0) {
        if (set_rlimit(RLIMIT_NOFILE, para.rlim_nofile))
        goto error;
        pdebugf("setup_rlimit: RLIMIT_NOFILE set to %lld\n", para.rlim_nofile);
    }
    if (para.rlim_fsize > 0) {
        if (set_rlimit(RLIMIT_FSIZE, para.rlim_fsize * 1024))
            goto error;
        pdebugf("setup_rlimit: RLIMIT_FSIZE set to %lld KB\n", para.rlim_fsize);
    }
    if (para.rlim_proc > 0) {
        if (set_rlimit(RLIMIT_NPROC, para.rlim_proc))
            goto error;
        pdebugf("setup_rlimit: RLIMIT_NPROC set to %lld\n", para.rlim_proc);
    }
    if (para.rlim_stack > 0) {
        if (set_rlimit(RLIMIT_STACK, para.rlim_stack * 1024))
            goto error;
        pdebugf("setup_rlimit: RLIMIT_STACK set to %lld KB\n", para.rlim_stack);
    }
    return 0;

    error:
    PRINTERR("setup_rlimit");
    return -1;
}

int setup_taskstats(struct ts_socket *s)
{
    if (taskstats_create(s)) {
        goto error;
    }

    cpu_set_t cur;
    CPU_ZERO(&cur);
    for (int i = 0; i < get_nprocs(); i++) {
        CPU_SET(i, &cur);
    }
    if (taskstats_setcpuset(s, &cur)) {
        goto error;
    }
    return 0;

    error:
    PRINTERR("setup taskstats");
    return -1;
}

int setup_cgroup(const struct cjail_para para, int *pidfd)
{
    if (para.cgroup_root) {
        if (cgroup_set_root(para.cgroup_root)) {
            return -1;
        }
    }

    if (cgroup_create("pids")) {
        return -1;
    }
    if ((*pidfd = cgroup_open_tasks("pids")) < 0) {
        return -1;
    }

    if (para.cg_rss > 0) {
        if (cgroup_create("memory")) {
            return -1;
        }
        if (cgroup_write("memory", "memory.limit_in_bytes", "%lld",
            para.cg_rss * 1024) < 0) {
            return -1;
        }
        if (cgroup_write("memory", "memory.swappiness", "%u", 0) < 0) {
            return -1;
        }
    }
    return 0;
}

int setup_seccomp_compile(const struct cjail_para para, struct sock_fprog *bpf)
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
        pdebugf("seccomp_rule_add: %d %s\n", para.seccomplist[i], scname);
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
        PRINTERR("create memfd");
        goto error;
    }
    seccomp_export_bpf(ctx, memfd);
    bpf_size = lseek(memfd, 0, SEEK_END);
    if (bpf_size < 0) {
        PRINTERR("get memfd size");
        goto error_memfd;
    }
    bpf->len = bpf_size / sizeof(struct sock_filter);
    bpf->filter = mmap(NULL, bpf_size, PROT_READ, MAP_PRIVATE, memfd, 0);
    if (bpf->filter == MAP_FAILED) {
        PRINTERR("mmap memfd");
        goto error_memfd;
    }

    seccomp_release(ctx);
    close(memfd);
    return 0;

error_memfd:
    close(memfd);
error:
    PRINTERR("setup_seccomp");
    seccomp_release(ctx);
    return -1;
}

int setup_seccomp_load(const struct cjail_para para, struct sock_fprog* bpf)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        PRINTERR("set no new privs");
        return -1;
    }
    if (!para.seccomplist)
        return 0;

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, bpf, 0, 0)) {
        PRINTERR("load seccomp filter");
        return -1;
    }
    return 0;
}
