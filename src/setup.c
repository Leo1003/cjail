#include "cjail.h"
#include "setup.h"
#include "taskstats.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <seccomp.h>

typedef void * scmp_filter_ctx;

int setup_fs()
{
    struct stat st;
    IFERR(mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL))
        goto error;
    if(exec_para->chroot)
    {
        IFERR(chroot(exec_para->chroot))
            goto error;
    }
    //TODO: Custom mkdir util
    IFERR(stat("/proc", &st))
    {
        IFERR(mkdir("/proc", 0755))
            goto error;
    }
    IFERR(mount("proc", "/proc", "proc", 0, ""))
        goto error;
    //TODO: Mount devfs
    if(exec_para->workingDir)
    {
        IFERR(chdir(exec_para->workingDir))
            goto error;
    }
    return 0;

    error:
    PRINTERR("setup_fs");
    return -1;
}

int setup_fd()
{
    if (exec_para->fd_input)
    {
        close(STDIN_FILENO);
        IFERR(open(exec_para->fd_input, O_RDONLY))
            goto error;
    }
    if (exec_para->fd_output)
    {
        close(STDOUT_FILENO);
        IFERR(open(exec_para->fd_output, O_WRONLY | O_CREAT | O_TRUNC, 0666))
            goto error;
    }
    if (exec_para->fd_err)
    {
        close(STDERR_FILENO);
        IFERR(open(exec_para->fd_err, O_WRONLY | O_CREAT | O_TRUNC, 0666))
            goto error;
    }
    else
    {
        IFERR(dup2(STDOUT_FILENO, STDERR_FILENO))
            goto error;
    }
    IFERR(closefrom(STDERR_FILENO))
        return -1;
    return 0;

    error:
    PRINTERR("setup_fd");
    return -1;
}

int setup_signals()
{
    for(int s = SIGHUP; s < SIGRTMAX; s++)
    {
        IFERR(signal(s, SIG_DFL))
        {
            PRINTERR("setup_signals");
            return -1;
        }
    }
    return 0;
}

int setup_cpumask()
{
    if(exec_para->cpuset)
    {
        IFERR(sched_setaffinity(getpid(), sizeof(*exec_para->cpuset), exec_para->cpuset))
        {
            PRINTERR("setup_cpumask");
            return -1;
        }
    }
    return 0;
}

static int set_rlimit(int res, long long val)
{
    struct rlimit rl;
    rl.rlim_cur = rl.rlim_max = val;
    return setrlimit(res, &rl);
}
int setup_rlimit()
{
    if(exec_para->lim_vss > 0)
    {
        IFERR(set_rlimit(RLIMIT_AS, exec_para->lim_vss * 1024))
            goto error;
    }
    if(exec_para->lim_fsize > 0)
    {
        IFERR(set_rlimit(RLIMIT_FSIZE, exec_para->lim_fsize * 1024))
        goto error;
    }
    if(exec_para->lim_proc > 0)
    {
        IFERR(set_rlimit(RLIMIT_NPROC, exec_para->lim_proc))
        goto error;
    }

    error:
    PRINTERR("setup_rlimit");
    return -1;
}

int setup_taskstats(struct ts_socket *s)
{
    IFERR(taskstats_create(s))
        goto error;
    if(exec_para->cpuset)
    {
        IFERR(taskstats_setcpuset(s, exec_para->cpuset))
            goto error;
    }
    return 0;

    error:
    PRINTERR("setup_taskstats");
    return -1;
}

int setup_seccomp(void* exec_argv)
{
    prctl(PR_SET_NO_NEW_PRIVS, 1);
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRAP);
    if(!ctx)
        goto error;
    int i = 0;
    while(exec_para->seccomplist[i])
    {
#ifndef NDEBUG
        char *scname = seccomp_syscall_resolve_num_arch(exec_para->seccomplist[i], seccomp_arch_native());
        pdebugf("seccomp_rule_add: %d %s", exec_para->seccomplist[i], scname);
        free(scname);
        /* In the case of seccomp_syscall_resolve_num_arch() the associated syscall name is
         * returned and it remains the callers responsibility to free the returned string
         * via free(3).
         */
#endif
        IFERR(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, exec_para->seccomplist[i], 0))
            goto error;
    }
    if(exec_argv)
    {
        //we have to prevent seccomp from blocking our execve()
        //only allow the certain argv pointer
        IFERR(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 1, SCMP_A1(SCMP_CMP_EQ, (scmp_datum_t)exec_argv)))
            goto error;
    }
    IFERR(seccomp_load(ctx))
        goto error;
    seccomp_release(ctx);
    return 0;

    error:
    PRINTERR("setup_seccomp");
    seccomp_release(ctx);
    return -1;
}
