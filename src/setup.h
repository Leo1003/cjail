#ifndef SETUP_H
#define SETUP_H

#include "cjail.h"
#include "taskstats.h"

#include <linux/filter.h>

int setup_fs(const struct cjail_para para);
int setup_cpumask(const struct cjail_para para);
int setup_rlimit(const struct cjail_para para);
int setup_taskstats(struct ts_socket* s);
int setup_cgroup(const struct cjail_para para, int* pidfd);
int setup_seccomp_compile(const struct cjail_para para, struct sock_fprog *bpf);
int setup_seccomp_load(const struct cjail_para para, struct sock_fprog *bpf);

#endif
