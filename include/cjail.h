#ifndef CJAIL_H
#define CJAIL_H

#define _GNU_SOURCE
#include <linux/taskstats.h>
#include <sched.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#define STACKSIZE 1024 * 1024

struct cjail_para
{
    int fd_input, fd_output, fd_err;
    char **argv, **environ, *chroot, *workingDir, *redir_input, *redir_output, *redir_err, *cgroup_root;
    cpu_set_t *cpuset;
    uid_t uid;
    gid_t gid;
    long long rlim_as, rlim_core, rlim_fsize, rlim_proc, rlim_stack;
    long long cg_rss;
    struct timeval *lim_time;
    int *seccomplist;
};

struct cjail_result
{
    struct taskstats stats;
    siginfo_t info;
    struct timeval time;
};


struct __exec_para
{
    struct cjail_para para;
    int resultpipe[2];
    int memcgtasksfd;
};

extern struct __exec_para *exec_para;
int cjail_exec(struct cjail_para *para, struct cjail_result *result);

#endif
