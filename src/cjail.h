/**
 * @dir src/
 * @brief internal sources directory
 */
/**
 * @internal
 * @file src/cjail.h
 * @brief cjail main library entry point header
 */
#ifndef CJAIL_H
#define CJAIL_H

#define _GNU_SOURCE
#include "simple_seccomp.h"

#include <linux/filter.h>
#include <linux/taskstats.h>
#include <sched.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

struct cjail_para {
    unsigned int preservefd, sharenet;
    int fd_input, fd_output, fd_error;
    char *redir_input, *redir_output, *redir_error, **argv, **environ, *chroot, *workingDir, *cgroup_root;
    cpu_set_t *cpuset;
    uid_t uid;
    gid_t gid;
    long long rlim_as, rlim_core, rlim_nofile, rlim_fsize, rlim_proc, rlim_stack;
    long long cg_rss;
    struct timeval lim_time;
    struct seccomp_config *seccompcfg;
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
