#ifndef CLEANUP_H
#define CLEANUP_H

#include "taskstats.h"
#include "utils.h"

#define MAX_CLNSTACK 1024

enum tasktype
{
    CLN_NONE,
    CLN_FREE,
    CLN_CLOSE,
    CLN_KILL,
    CLN_CGROUP,
    CLN_TASKSTAT
};

struct cleanuptask
{
    int type;
    union
    {
        void **ptr;                  //CLN_FREE
        int fd;                     //CLN_CLOSE
        struct
        {
            pid_t pid;
            int sig;
        } kill;                     //CLN_KILL
        const char *subsystem;            //CLN_CGROUP
        struct ts_socket *tssock;   //CLN_TASKSTAT
    } arg;
};

struct cleanupstack
{
    size_t count;
    struct cleanuptask stack[MAX_CLNSTACK]; //TODO: Maybe a dynamic array
};

void stack_push(struct cleanupstack *stack, int type, ...);
void stack_push_task(struct cleanupstack *stack, struct cleanuptask *task);
struct cleanuptask * stack_top(struct cleanupstack *stack);
int stack_pop(struct cleanupstack *stack, struct cleanuptask *task);
void do_cleanup(struct cleanupstack *stack);

#endif
