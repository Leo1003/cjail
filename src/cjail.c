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
    int wstatus, ret = 0;
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
    {
        ret = -1;
        goto out_cgroup;
    }

    //clone
    child_stack = malloc(STACKSIZE);
    if(!child_stack)
    {
        PRINTERR("malloc stack");
        ret = -errno;
        goto out_taskstats;
    }
    int optionflag = 0;
    optionflag |= exec_para.para.sharenet ? 0 : CLONE_NEWNET;
    pid_t initpid = clone(child_init, child_stack + STACKSIZE,
                          SIGCHLD | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWPID | optionflag, NULL);
    IFERR(initpid)
    {
        PRINTERR("clone child namespace init process");
        ret = -errno;
        goto out_taskstats;
    }
    close(exec_para.resultpipe[1]);
    pdebugf("Init PID: %d\n", initpid);

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

    //socket buffer may overflow while the child process are executing
    int tsret = 0, waited = 0, tsgot = 0;
    struct taskstats ts;
    while(!waited && !tsgot)
    {
        //wait for init process return
        if(!waited)
        {
            pid_t retp = waitpid(initpid, &wstatus, (tsgot ? 0 : WNOHANG));
            IFERR(retp)
            {
                if(errno == ECHILD)
                {
                    perrf("Lost control of child namespace init process\n");
                    ret = -errno;
                    goto out_kill;
                }
            }
            if(retp > 0)
            {
                if(WIFEXITED(wstatus) && WEXITSTATUS(wstatus) != 0)
                {
                    perrf("child namespace init process abnormal terminated\n");
                    ret = -WEXITSTATUS(wstatus);
                    goto out_kill;
                }
                waited = 1;
            }
        }
        //taskstats get stats
        if(!tsgot)
        {
            tsret = taskstats_getstats(&tssock, &ts);
            if(tsret == 0 && ts.ac_pid == childpid)
            {
                tsgot = 1;
            }
            if(tsret == -1)
                tsgot = 1;
        }
    }
    if(tsret == -1)
    {
        perrf("Failed to receive from taskstats.\n");
        ret = -EXIT_FAILURE;
        goto out_kill;
    }

    //get result from pipe
    size_t n = read(exec_para.resultpipe[0], result, sizeof(*result));
    IFERR(n)
        PRINTERR("get result");
    result->stats = ts;

    out_kill:
    kill(childpid, SIGKILL);
    kill(initpid, SIGKILL);
    usleep(200000);

    out_taskstats:
    IFERR(taskstats_destory(&tssock))
        perrf("Failed to destory taskstats\n");

    out_cgroup:
    IFERR(cgroup_destory("pids"))
        perrf("Failed to destory pids cgroup\n");
    if(exec_para.para.cg_rss > 0)
    {
        IFERR(cgroup_destory("memory"))
            perrf("Failed to destory memory cgroup\n");
    }
    return ret;
}

void cjail_para_init(struct cjail_para* para)
{
    memset(para, 0, sizeof(struct cjail_para));
    para->rlim_core = -1;
    para->uid = 65534;
    para->gid = 65534;
}
