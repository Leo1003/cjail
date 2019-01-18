/**
 * @internal
 * @file cleanup.c
 * @brief cleanup stack source
 */
#include "cleanup.h"
#include "cgroup.h"
#include "logger.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <unistd.h>

static void push_free(struct cleanupstack *stack, void **ptr)
{
    struct cleanuptask task;
    task.type = CLN_FREE;
    task.arg.ptr = ptr;
    push_task(stack, &task);
    return;
}
static void clean_free(void **ptr)
{
    if (*ptr) {
        free(*ptr);
        *ptr = NULL;
    }
}

static void push_close(struct cleanupstack *stack, int fd)
{
    struct cleanuptask task;
    task.type = CLN_CLOSE;
    task.arg.fd = fd;
    push_task(stack, &task);
    return;
}
static void clean_close(int fd)
{
    if (close(fd)) {
        PFTL("cleanup fd");
    }
}

static void push_kill(struct cleanupstack *stack, pid_t pid, int sig)
{
    struct cleanuptask task;
    task.type = CLN_KILL;
    task.arg.kill.pid = pid;
    task.arg.kill.sig = sig;
    push_task(stack, &task);
    return;
}
static void clean_kill(pid_t pid, int sig)
{
    if (kill(pid, sig)) {
        PFTL("cleanup process");
    }
}

static void push_cgroup(struct cleanupstack *stack, const char *subsystem)
{
    struct cleanuptask task;
    task.type = CLN_CGROUP;
    task.arg.subsystem = subsystem;
    push_task(stack, &task);
    return;
}
static void clean_cgroup(const char *subsystem)
{
    if (cgroup_destory(subsystem)) {
        PFTL("cleanup cgroup");
    }
}
static void push_taskstat(struct cleanupstack *stack, tsproc_t *tsproc)
{
    struct cleanuptask task;
    task.type = CLN_TASKSTAT;
    task.arg.tsproc = tsproc;
    push_task(stack, &task);
    return;
}
static void clean_taskstat(tsproc_t *tsproc)
{
    if (taskstats_stop(tsproc)) {
        PFTL("cleanup taskstats");
    }
}

static void push_sigset(struct cleanupstack *stack, struct sig_rule *rules)
{
    struct cleanuptask task;
    task.type = CLN_SIGSET;
    task.arg.rules = rules;
    push_task(stack, &task);
    return;
}
static void clean_sigset(struct sig_rule *rules)
{
    restoresigs(rules);
}


void stack_push(struct cleanupstack *stack, int type, ...)
{
    va_list args;
    va_start(args, type);
    switch (type) {
        case CLN_FREE:
            push_free(stack, va_arg(args, void **));
            break;
        case CLN_CLOSE:
            push_close(stack, va_arg(args, int));
            break;
        case CLN_KILL:
            push_kill(stack, va_arg(args, pid_t), va_arg(args, int));
            break;
        case CLN_CGROUP:
            push_cgroup(stack, va_arg(args, const char *));
            break;
        case CLN_TASKSTAT:
            push_taskstat(stack, va_arg(args, tsproc_t *));
            break;
        case CLN_SIGSET:
            push_sigset(stack, va_arg(args, struct sig_rule *));
            break;
        default:
            break;
    }
    va_end(args);
}

void push_task(struct cleanupstack *stack, struct cleanuptask *task)
{
    if (stack->count >= MAX_CLNSTACK) {
        return;
    }
    stack->stack[stack->count] = *task;
    stack->count++;
    return;
}

struct cleanuptask *stack_top(struct cleanupstack *stack)
{
    if (stack->count) {
        return &stack->stack[stack->count - 1];
    }
    return NULL;
}

int stack_pop(struct cleanupstack *stack, struct cleanuptask *task)
{
    if (stack->count) {
        stack->count--;
        *task = stack->stack[stack->count];
        return 1;
    }
    return 0;
}

void do_cleanup(struct cleanupstack *stack)
{
    struct cleanuptask task;
    while (stack_pop(stack, &task)) {
        switch (task.type) {
            case CLN_FREE:
                clean_free(task.arg.ptr);
                break;
            case CLN_CLOSE:
                clean_close(task.arg.fd);
                break;
            case CLN_KILL:
                clean_kill(task.arg.kill.pid, task.arg.kill.sig);
                break;
            case CLN_CGROUP:
                clean_cgroup(task.arg.subsystem);
                break;
            case CLN_TASKSTAT:
                clean_taskstat(task.arg.tsproc);
                break;
            case CLN_SIGSET:
                clean_sigset(task.arg.rules);
                break;
            default:
                errorf("Unknown cleanuptask type\n");
                break;
        }
    }
    return;
}
