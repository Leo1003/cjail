#ifndef CLEANUP_H
#define CLEANUP_H

#include "sigset.h"
#include "taskstats.h"
#include "utils.h"

#define MAX_CLNSTACK 64

enum tasktype
{
    CLN_NONE,
    CLN_FREE,
    CLN_CLOSE,
    CLN_KILL,
    CLN_CGROUP,
    CLN_TASKSTAT,
    CLN_SIGSET
};

struct cleanuptask
{
    int type;
    union
    {
        void **ptr;                 //CLN_FREE
        int fd;                     //CLN_CLOSE
        struct
        {
            pid_t pid;
            int sig;
        } kill;                     //CLN_KILL
        const char *subsystem;      //CLN_CGROUP
        struct ts_socket *tssock;   //CLN_TASKSTAT
        struct sig_rule *rules;     //CLN_SIGSET
    } arg;
};

struct cleanupstack
{
    size_t count;
    struct cleanuptask stack[MAX_CLNSTACK]; //TODO: Maybe a dynamic array
};

void stack_push(struct cleanupstack *stack, int type, ...);
void push_task(struct cleanupstack *stack, struct cleanuptask *task);
struct cleanuptask * stack_top(struct cleanupstack *stack);
int stack_pop(struct cleanupstack *stack, struct cleanuptask *task);
void do_cleanup(struct cleanupstack *stack);

#endif
