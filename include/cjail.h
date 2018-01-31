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
    char **argv, **environ, *chroot, *workingDir, *fd_input, *fd_output, *fd_err;
    cpu_set_t *cpumask;
    uid_t uid;
    long long lim_vss, lim_rss, lim_fsize, lim_proc;
    struct itimerval *lim_time;
    int *seccomplist;
};

extern int tspipe[2];
extern struct cjail_para *exec_para;
int cjail_exec(struct cjail_para *para, struct taskstats *result);

#endif
