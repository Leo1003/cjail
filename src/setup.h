#ifndef SETUP_H
#define SETUP_H

#include "cjail.h"

int setup_fs();
int setup_fd();
int setup_signals();
int setup_cpumask();
int setup_rlimit();
int setup_taskstats();
int setup_cgroup();
int enter_cgroup();
int setup_seccomp();

#endif
