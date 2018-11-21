#include "logger.h"
#include "simple_seccomp.h"
#include "trace.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ptrace.h>

int trace_seize(pid_t pid)
{
    return ptrace(PTRACE_SEIZE, pid, NULL, PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACESECCOMP);
}

static int trace_getsig(pid_t pid, siginfo_t *info) {
    if (ptrace(PTRACE_GETSIGINFO, pid, NULL, info)) {
        if (errno == ESRCH) {
            // Tracee die
            return 1;
        }
        return -1;
    }
    return 0;
}

static int trace_cont(pid_t pid, int sig) {
    return ptrace(PTRACE_CONT, pid, NULL, sig);
}

inline static int isstopsig(int sig) {
    switch (sig) {
        case SIGSTOP:
        case SIGTSTP:
        case SIGTTIN:
        case SIGTTOU:
            return 1;
    }
    return 0;
}

int trace_handle(const siginfo_t* sinfo, const struct trace_ops* ops)
{
    switch (sinfo->si_code) {
        case CLD_EXITED:
        case CLD_KILLED:
        case CLD_DUMPED:
            return 1;
    }
    siginfo_t real_sig;
    pid_t current = sinfo->si_pid;
    int sig = sinfo->si_status & 0x000000ff;
    int event = sinfo->si_status >> 8;
    devf("Current tracee: %d\n", current);
    if (sig == SIGTRAP && event) {
        // ptrace event stop
        devf("ptrace event stop\n");
        unsigned long message;
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETEVENTMSG, current, NULL, &message)) {
            return -1;
        }
        switch (event) {
            case PTRACE_EVENT_FORK:
            case PTRACE_EVENT_VFORK:
            case PTRACE_EVENT_CLONE:
                devf("new process event\n");
                break;
            case PTRACE_EVENT_EXEC:
                devf("exec event\n");
                break;
            case PTRACE_EVENT_VFORK_DONE:
                devf("vfork done event\n");
                break;
            case PTRACE_EVENT_EXIT:
                devf("exit event\n");
                break;
            case PTRACE_EVENT_SECCOMP:
                devf("seccomp event\n");
                ptrace(PTRACE_GETREGS, current, NULL, &regs);
                if (ops->seccomp_event) {
                    ops->seccomp_event(current, message, &regs);
                }
                if (message == TRACE_KILL_MAGIC) {
                    kill(current, SIGKILL);
                    return 0;
                }
                ptrace(PTRACE_POKEUSER, current, sizeof(long) * ORIG_RAX, -1);
                break;
            case PTRACE_EVENT_STOP:
                devf("stop event\n");
                break;
        }
        devf("event end!\n");
        return trace_cont(current, 0);
    }
    if (sig == SIGTRAP && !event) {
        if (ptrace(PTRACE_GETSIGINFO, current, NULL, &real_sig)) {
            return -1;
        }
        if (real_sig.si_code == SIGTRAP ||
            real_sig.si_code == (SIGTRAP | 0x80)) {
            //ptrace system call stop
            //but we don't care it
            devf("ptrace system call stop\n");
            return trace_cont(current, 0);
        }
    }
    if (isstopsig(sig)) {
        if (trace_getsig(current, &real_sig) < 0 && errno == EINVAL) {
            //group stop
            //we can't make the tracee stop because it isn't seized
            //only can continue it
            devf("group stop\n");
            devf("stop continue...\n");
            return trace_cont(current, 0);
        }
        if (event == PTRACE_EVENT_STOP) {
            //group stop (seized)
            devf("group stop (seized)\n");
            //stop child until someone continue it
            devf("ptrace listen...\n");
            return ptrace(PTRACE_LISTEN, current, NULL, NULL);
        }
    }
    //signal delivery stop
    //reinject the signal
    devf("signal delivery stop\n");
    return trace_cont(current, sig);
}
