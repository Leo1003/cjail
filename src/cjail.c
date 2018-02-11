#include "cjail.h"
#include "child_init.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/signal.h>
#include <sys/wait.h>

int tspipe[2];
struct cjail_para *exec_para;

int cjail_exec(struct cjail_para *para, struct taskstats *result)
{
    void *child_stack;
    int wstatus;
    if(geteuid())
        return EPERM;
    if(!para)
        return EINVAL;
    exec_para = para;
    pipe(tspipe);
    close(tspipe[1]);
    child_stack = malloc(STACKSIZE);
    pid_t initpid = clone(child_init, child_stack + STACKSIZE,
                          SIGCHLD | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWPID, NULL);
    //FIXME: Rewrite and add error handling
    size_t n = read(tspipe[0], result, sizeof(result));
    waitpid(initpid, &wstatus, 0);
    if(WIFEXITED(wstatus))
        return WEXITSTATUS(wstatus);
    else if(WIFSIGNALED(wstatus))
        return 127;
    else
        return 255;
}
