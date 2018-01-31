#include "cjail.h"
#include "setup.h"
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
#include <sys/resource.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>

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
    if(exec_para->cpumask)
    {
        IFERR(sched_setaffinity(getpid(), sizeof(*exec_para->cpumask), exec_para->cpumask))
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
