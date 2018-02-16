#include "cjail.h"
#include "child_init.h"
#include "cgroup.h"
#include "setup.h"
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

struct __exec_para exec_para;

int cjail_exec(struct cjail_para* para, struct cjail_result* result)
{
    void *child_stack;
    int wstatus;
    struct ts_socket tssock;
    if(geteuid())
        return -EPERM;
    if(!para)
        return -EINVAL;
    exec_para.para = *para;

    //setup pipe
    IFERR(pipe(exec_para.resultpipe))
    {
        PRINTERR("create pipe");
        return -errno;
    }

    //setup cgroup stage I
    IFERR(setup_cgroup(&exec_para.cgtasksfd))
        return -1;

    //setup taskstats
    IFERR(setup_taskstats(&tssock))
        return -1;

    //clone
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
    close(exec_para.resultpipe[1]);
    pdebugf("Init PID: %d", initpid);

    //setup cgroup stage II
    pid_t childpid;
    while(cgroup_read("pids", "tasks", "%d", &childpid) == EOF)
    {
        usleep(100000);
    }
    pdebugf("Got childpid: %d\n", childpid);
    if(exec_para.para.cg_rss)
    {
        cgroup_write("memory", "tasks", "%d", childpid);
    }
    kill(childpid, SIGRTMIN);
    kill(initpid, SIGRTMIN);

    //get result from pipe
    size_t n = read(exec_para.resultpipe[0], result, sizeof(*result));
    IFERR(n)
        PRINTERR("get result");

    //wait for init process return
    IFERR(waitpid(initpid, &wstatus, 0))
    {
        if(errno == ECHILD)
        {
            perrf("Lost control of child namespace init process\n");
            return -ECHILD;
        }
    }
    if(WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 1)
    {
        perrf("child namespace init process abnormal terminated\n");
        return EXIT_FAILURE;
    }

    //taskstats get stats
    //FIXME: socket buffer may overflow while the child process are executing
    int tsret = 0;
    struct taskstats ts;
    while((tsret = taskstats_getstats(&tssock, &ts)) != -1)
    {
        pdebugf("taskstats got stats PID: %d\n", ts.ac_pid);
        if(tsret == -2)
            continue;
        if(ts.ac_pid == childpid)
        {
            result->stats = ts;
            break;
        }
    }
    if(tsret == -1)
        return EXIT_FAILURE;

    return 0;
}
