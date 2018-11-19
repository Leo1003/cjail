#include "trace.h"

#include <errno.h>
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

int trace_handle(const siginfo_t* sinfo, const struct trace_ctx* ctx)
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
    if (sig == SIGTRAP && event) {
        // ptrace event stop
        unsigned long message;
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETEVENTMSG, current, NULL, &message)) {
            return -1;
        }
        switch (event) {
            case PTRACE_EVENT_FORK:
            case PTRACE_EVENT_VFORK:
            case PTRACE_EVENT_CLONE:
                break;
            case PTRACE_EVENT_EXEC:
                break;
            case PTRACE_EVENT_VFORK_DONE:
                break;
            case PTRACE_EVENT_EXIT:
                break;
            case PTRACE_EVENT_SECCOMP:
                ptrace(PTRACE_GETREGSET, current, NULL, &regs);
                if (ctx->seccomp_event) {
                    ctx->seccomp_event(current, message, &regs);
                }
                ptrace(PTRACE_POKEUSER, current, sizeof(long) * ORIG_RAX, -1);
                break;
        }
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
            return trace_cont(current, 0);
        }
    }
    if (isstopsig(sig)) {
        if (trace_getsig(current, &real_sig) < 0 && errno == EINVAL) {
            //group stop
            if (sinfo->si_status >> 16 == PTRACE_EVENT_STOP) {
                //stop child until someone continue it
                return ptrace(PTRACE_LISTEN, current, NULL, NULL);
            }
            //we can't make the tracee stop because it isn't seized
            //only can continue it
            return trace_cont(current, 0);
        }
    }
    //signal delivery stop
    //reinject the signal
    return trace_cont(current, sig);
}
