#ifndef CJAIL_H
#define CJAIL_H

#define _GNU_SOURCE
#include <linux/taskstats.h>
#include <sched.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

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
};

/**
* @brief Initialize cjail_para struct
*
* @param[in,out] para cjail_para struct to be initialized
*/
void cjail_para_init(struct cjail_para *para);

/**
* @brief Execute a process in the jail
*
* @param[in] para Executing parameters to the jail
* @param[out] result Executing results to be filled
* @return int
*/
int cjail_exec(const struct cjail_para *para, struct cjail_result *result);

/**
* @brief Convert cpu_set_t to human readable format
*
* @param[in] cpuset cpu_set_t to be converted
* @param[out] str Output string
* @param[in] len The buffer size of str
* @return int
*/
int cpuset_tostr(const cpu_set_t *cpuset, char *str, size_t len);

/**
* @brief Convert human readable format to cpu_set_t
*
* @param[in] str string to be converted
* @param[out] cpuset Output
* @return int
*/
int cpuset_parse(const char *str, cpu_set_t *cpuset);

#endif
