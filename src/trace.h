#ifndef TRACE_H
#define TRACE_H

#include <signal.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/user.h>

typedef void(*seccomp_cb)(pid_t, unsigned long, struct user_regs_struct *);

struct trace_ops {
    seccomp_cb seccomp_event;
};

int trace_seize(pid_t pid);
int trace_handle(const siginfo_t *sinfo, const struct trace_ops *ops);

#endif
