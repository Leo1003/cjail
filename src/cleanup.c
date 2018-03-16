#include "cgroup.h"
#include "cleanup.h"
#include "taskstats.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <sys/types.h>

static void stack_push_free(struct cleanupstack *stack, void **ptr)
{
    struct cleanuptask task;
    task.type = CLN_FREE;
    task.arg.ptr = ptr;
    stack_push_task(stack, &task);
    return;
}

static void clean_free(void **ptr)
{
    if(*ptr)
    {
        free(*ptr);
        *ptr = NULL;
    }
}

static void stack_push_close(struct cleanupstack *stack, int fd)
{
    struct cleanuptask task;
    task.type = CLN_CLOSE;
    task.arg.fd = fd;
    stack_push_task(stack, &task);
    return;
}

static void clean_close(int fd)
{
    IFERR(close(fd))
    {
        PRINTERR("cleanup fd");
    }
}

static void stack_push_kill(struct cleanupstack *stack, pid_t pid, int sig)
{
    struct cleanuptask task;
    task.type = CLN_KILL;
    task.arg.kill.pid = pid;
    task.arg.kill.sig = sig;
    stack_push_task(stack, &task);
    return;
}

static void clean_kill(pid_t pid, int sig)
{
    IFERR(kill(pid, sig))
    {
        PRINTERR("cleanup process");
    }
}

static void stack_push_cgroup(struct cleanupstack *stack, const char *subsystem)
{
    struct cleanuptask task;
    task.type = CLN_CGROUP;
    task.arg.subsystem = subsystem;
    stack_push_task(stack, &task);
    return;
}

static void clean_cgroup(const char *subsystem)
{
    IFERR(cgroup_destory(subsystem))
    {
        PRINTERR("cleanup cgroup");
    }
}

static void stack_push_taskstat(struct cleanupstack *stack, struct ts_socket *tssock)
{
    struct cleanuptask task;
    task.type = CLN_TASKSTAT;
    task.arg.tssock = tssock;
    stack_push_task(stack, &task);
    return;
}

static void clean_taskstat(struct ts_socket *tssock)
{
    IFERR(taskstats_destory(tssock))
    {
        PRINTERR("cleanup taskstats");
    }
}

void stack_push(struct cleanupstack *stack, int type, ...)
{
    va_list args;
    va_start(args, type);
    switch(type)
    {
        case CLN_FREE:
            stack_push_free(stack, va_arg(args, void *));
            break;
        case CLN_CLOSE:
            stack_push_close(stack, va_arg(args, int));
            break;
        case CLN_KILL:
            stack_push_kill(stack, va_arg(args, pid_t), va_arg(args, int));
            break;
        case CLN_CGROUP:
            stack_push_cgroup(stack, va_arg(args, const char *));
            break;
        case CLN_TASKSTAT:
            stack_push_taskstat(stack, va_arg(args, struct ts_socket *));
            break;
        default:
            break;
    }
    va_end(args);
}

void stack_push_task(struct cleanupstack* stack, struct cleanuptask* task)
{
    if(stack->count >= MAX_CLNSTACK)
        return;
    stack->stack[stack->count] = *task;
    stack->count++;
    return;
}

struct cleanuptask * stack_top(struct cleanupstack *stack)
{
    if(stack->count)
        return &stack->stack[stack->count - 1];
    return NULL;
}

int stack_pop(struct cleanupstack *stack, struct cleanuptask *task)
{
    if(stack->count)
    {
        stack->count--;
        *task = stack->stack[stack->count];
        return 1;
    }
    return 0;
}

void do_cleanup(struct cleanupstack* stack)
{
    struct cleanuptask task;
    while(stack_pop(stack, &task))
    {
        switch(task.type)
        {
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
                clean_taskstat(task.arg.tssock);
                break;
            default:
                perrf("Unknown cleanuptask type\n");
                break;
        }
    }
    return;
}
