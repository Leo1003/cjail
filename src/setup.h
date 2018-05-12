#ifndef SETUP_H
#define SETUP_H

#include "cjail.h"
#include "taskstats.h"

#include <linux/filter.h>

int setup_fs();
int setup_fd();
int setup_cpumask();
int setup_rlimit();
int setup_taskstats(struct ts_socket* s);
int setup_cgroup(int* pidfd);
int setup_seccomp_compile(struct sock_fprog *bpf, void* exec_argv);
int setup_seccomp_load(struct sock_fprog *bpf);

#endif
