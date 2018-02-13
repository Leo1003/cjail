#include "cjail.h"
#include "child_init.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/signal.h>
#include <sys/wait.h>

struct __exec_para *exec_para;

int cjail_exec(struct cjail_para* para, struct cjail_result* result)
{
    void *child_stack;
    int wstatus;
    if(geteuid())
        return -EPERM;
    if(!para)
        return -EINVAL;

    IFERR(pipe(exec_para->resultpipe))
    {
        PRINTERR("create pipe");
        return -errno;
    }
    exec_para->para = *para;

    child_stack = malloc(STACKSIZE);
    if(!child_stack)
    {
        PRINTERR("malloc stack");
        return -errno;
    }
    pid_t initpid = clone(child_init, child_stack + STACKSIZE,
                          SIGCHLD | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWPID, NULL);
    IFERR(initpid)
    {
        PRINTERR("clone child namespace init process");
        return -errno;
    }
    close(exec_para->resultpipe[1]);

    size_t n = read(exec_para->resultpipe[0], result, sizeof(*result));
    IFERR(n)
        PRINTERR("get result");

    IFERR(waitpid(initpid, &wstatus, 0))
    {
        if(errno == ECHILD)
        {
            perrf("Lost control of child namespace init process\n");
            return -ECHILD;
        }
    }

    if(WIFSIGNALED(wstatus) && WTERMSIG(wstatus) == SIGABRT)
    {
        perrf("child namespace init process abnormal terminated\n");
        return EXIT_FAILURE;
    }
    return 0;
}
