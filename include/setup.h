#ifndef SETUP_H
#define SETUP_H

#include "cjail.h"
#include "taskstats.h"

int setup_fs();
int setup_fd();
int reset_signals();
int setup_cpumask();
int setup_rlimit();
int setup_taskstats(struct ts_socket* s);
int setup_cgroup(int* pidfd);
int setup_seccomp(void* exec_argv);

#endif
