#include "cjail.h"
#include "cgroup.h"
#include "fds.h"
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

int setup_fs()
{
    IFERR(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
        goto error;
    int rmflag = 0;
    if(!exec_para.para.chroot)
        rmflag |= MS_REMOUNT;

    char procpath[PATH_MAX];
    combine_path(procpath, exec_para.para.chroot, "/proc");
    IFERR(mkdir_r(procpath))
        goto procerror;
    IFERR(mount("proc", procpath, "proc", MS_NODEV | MS_NOEXEC | MS_NOSUID, ""))
        goto procerror;

    if(exec_para.para.chroot)
    {
        char devpath[PATH_MAX];
        combine_path(devpath, exec_para.para.chroot, "/dev");
        IFERR(mkdir_r(devpath))
            goto deverror;
        IFERR(mount("dev", devpath, "devtmpfs", MS_NOEXEC | MS_NOSUID, ""))
        {
            PRINTERR("mount devtmpfs");
            goto deverror;
        }
    }
    if(exec_para.para.chroot)
    {
        IFERR(chroot(exec_para.para.chroot))
            goto error;
        IFERR(chdir("/"))
            goto error;
    }
    if(exec_para.para.workingDir)
    {
        IFERR(chdir(exec_para.para.workingDir))
            goto error;
    }
    return 0;

    procerror:
    PRINTERR("mount procfs");
    return -1;

    deverror:
    PRINTERR("mount devfs");
    return -1;

    error:
    PRINTERR("setup_fs");
    return -1;
}

int setup_cpumask()
{
    if(exec_para.para.cpuset)
    {
        IFERR(sched_setaffinity(getpid(), sizeof(*exec_para.para.cpuset), exec_para.para.cpuset))
        {
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
int setup_rlimit()
{
    if(exec_para.para.rlim_as > 0)
    {
        IFERR(set_rlimit(RLIMIT_AS, exec_para.para.rlim_as * 1024))
            goto error;
        pdebugf("setup_rlimit: RLIMIT_AS set to %lld KB\n", exec_para.para.rlim_as);
    }
    if(exec_para.para.rlim_core >= 0)
    {
        IFERR(set_rlimit(RLIMIT_CORE, exec_para.para.rlim_core * 1024))
            goto error;
        pdebugf("setup_rlimit: RLIMIT_CORE set to %lld KB\n", exec_para.para.rlim_core);
    }
    if(exec_para.para.rlim_nofile > 0)
    {
        IFERR(set_rlimit(RLIMIT_NOFILE, exec_para.para.rlim_nofile))
        goto error;
        pdebugf("setup_rlimit: RLIMIT_NOFILE set to %lld\n", exec_para.para.rlim_nofile);
    }
    if(exec_para.para.rlim_fsize > 0)
    {
        IFERR(set_rlimit(RLIMIT_FSIZE, exec_para.para.rlim_fsize * 1024))
            goto error;
        pdebugf("setup_rlimit: RLIMIT_FSIZE set to %lld KB\n", exec_para.para.rlim_fsize);
    }
    if(exec_para.para.rlim_proc > 0)
    {
        IFERR(set_rlimit(RLIMIT_NPROC, exec_para.para.rlim_proc))
            goto error;
        pdebugf("setup_rlimit: RLIMIT_NPROC set to %lld\n", exec_para.para.rlim_proc);
    }
    if(exec_para.para.rlim_stack > 0)
    {
        IFERR(set_rlimit(RLIMIT_STACK, exec_para.para.rlim_stack * 1024))
            goto error;
        pdebugf("setup_rlimit: RLIMIT_STACK set to %lld KB\n", exec_para.para.rlim_stack);
    }
    return 0;

    error:
    PRINTERR("setup_rlimit");
    return -1;
}

int setup_taskstats(struct ts_socket *s)
{
    IFERR(taskstats_create(s))
        goto error;

    cpu_set_t cur;
    CPU_ZERO(&cur);
    for(int i = 0; i < get_nprocs(); i++)
        CPU_SET(i, &cur);
    IFERR(taskstats_setcpuset(s, &cur))
        goto error;

    return 0;

    error:
    PRINTERR("setup taskstats");
    return -1;
}

int setup_cgroup(int *pidfd)
{
    if(exec_para.para.cgroup_root)
        IFERR(cgroup_set_root(exec_para.para.cgroup_root))
            return -1;

    IFERR(cgroup_create("pids"))
        return -1;
    *pidfd = cgroup_open_tasks("pids");
        if(*pidfd < 0)
            return -1;

    if(exec_para.para.cg_rss > 0)
    {
        IFERR(cgroup_create("memory"))
            return -1;
        IFERR(cgroup_write("memory", "memory.limit_in_bytes", "%lld", exec_para.para.cg_rss * 1024))
            return -1;
        IFERR(cgroup_write("memory", "memory.swappiness", "%u", 0))
            return -1;
    }
    return 0;
}

int setup_seccomp_compile(struct sock_fprog *bpf, void* exec_argv)
{
    if(!exec_para.para.seccomplist)
        return 0;
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRAP);
    if(!ctx)
        goto error;

    for (int i = 0; exec_para.para.seccomplist[i] >= 0; i++)
    {
#ifndef NDEBUG
        char *scname = seccomp_syscall_resolve_num_arch(seccomp_arch_native(), exec_para.para.seccomplist[i]);
        pdebugf("seccomp_rule_add: %d %s\n", exec_para.para.seccomplist[i], scname);
        free(scname);
        /* In the case of seccomp_syscall_resolve_num_arch() the associated syscall name is
         * returned and it remains the callers responsibility to free the returned string
         * via free(3).
         */
#endif
        IFERR(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, exec_para.para.seccomplist[i], 0))
            goto error;
    }
    if(exec_argv)
    {
        //we have to prevent seccomp from blocking our execve()
        //only allow the certain argv pointer
        IFERR(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 1, SCMP_A1(SCMP_CMP_EQ, (scmp_datum_t)exec_argv)))
            goto error;
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
    IFERR (bpf_size) {
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
    return 0;

error_memfd:
    close(memfd);
error:
    PRINTERR("setup_seccomp");
    seccomp_release(ctx);
    return -1;
}

int setup_seccomp_load(struct sock_fprog* bpf)
{
    IFERR (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        PRINTERR("set no new privs");
        return -1;
    }
    if(!exec_para.para.seccomplist)
        return 0;

    IFERR (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, bpf, 0, 0)) {
        PRINTERR("load seccomp filter");
        return -1;
    }
    return 0;
}
