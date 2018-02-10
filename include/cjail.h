#ifndef CJAIL_H
#define CJAIL_H

#define _GNU_SOURCE
#include <linux/taskstats.h>
#include <sched.h>
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
    struct itimerval lim_time;
    int *seccomplist;
};

extern int tspipe[2];
extern struct cjail_para *exec_para;
int cjail_exec(struct cjail_para *para, struct taskstats *result);

#endif
