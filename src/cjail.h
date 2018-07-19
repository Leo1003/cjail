#ifndef CJAIL_H
#define CJAIL_H

#define _GNU_SOURCE
#include <linux/filter.h>
#include <linux/taskstats.h>
#include <sched.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#define CGROUP_DEFAULT_ROOT "/sys/fs/cgroup"
#define CGROUP_NAME "cjail.%d"
#define UTSNAME "cjail"
#define INITNAME "/sbin/init"
#define PROCNAME "init"

struct cjail_para {
    unsigned int preservefd, sharenet;
    int fd_input, fd_output, fd_err;
    char **argv, **environ, *chroot, *workingDir, *redir_input, *redir_output, *redir_err, *cgroup_root;
    cpu_set_t *cpuset;
    uid_t uid;
    gid_t gid;
    long long rlim_as, rlim_core, rlim_nofile, rlim_fsize, rlim_proc, rlim_stack;
    long long cg_rss;
    struct timeval lim_time;
    int *seccomplist;
};

struct cjail_result {
    struct taskstats stats;
    struct rusage rus;
    siginfo_t info;
    struct timeval time;
    int timekill;
    int oomkill;
};

struct exec_para {
    struct cjail_para para;
    int resultpipe[2];
    int cgtasksfd;
    struct sock_fprog bpf;
};

void cjail_para_init(struct cjail_para *para);
int cjail_exec(const struct cjail_para *para, struct cjail_result *result);

#endif
