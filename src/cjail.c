#include "cjail.h"
#include "child_init.h"
#include "cgroup.h"
#include "setup.h"
#include "sigset.h"
#include "utils.h"
#include "cleanup.h"

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

static volatile sig_atomic_t child = 0, interrupted = 0;
static void sighandler(int sig)
{
    switch(sig)
    {
        case SIGHUP:
        case SIGINT:
        case SIGQUIT:
        case SIGTERM:
            interrupted = 1;
            break;
        case SIGCHLD:
            child = 1;
            break;
    }
}

static struct sig_rule lib_sigrules[] =
{
    { SIGHUP  , sighandler, NULL, {{0}}, 0 },
    { SIGINT  , sighandler, NULL, {{0}}, 0 },
    { SIGQUIT , sighandler, NULL, {{0}}, 0 },
    { SIGTERM , sighandler, NULL, {{0}}, 0 },
    { SIGCHLD , sighandler, NULL, {{0}}, 0 },
    { SIGTTIN , SIG_IGN   , NULL, {{0}}, 0 },
    { SIGTTOU , SIG_IGN   , NULL, {{0}}, 0 },
    { 0       , NULL      , NULL, {{0}}, 0 },
};

static int cjail_kill(pid_t pid)
{
    IFERR(kill(pid, SIGKILL))
    {
        if(errno != ESRCH)
            return -1;
    }
    usleep(100000);
    return 0;
}

static int cjail_wait(pid_t initpid, int *wstatus)
{
    pid_t retp;
    retry:
    retp = waitpid(initpid, wstatus, 0);
    IFERR(retp)
    {
        if(errno == ECHILD)
        {
            perrf("Lost control of child namespace init process\n");
            goto error;
        }
        if(errno == EINTR)
        {
            if(interrupted && !child)
                cjail_kill(initpid);
            goto retry;
        }
    }
    if(retp == initpid)
    {
        if((WIFEXITED(*wstatus) && WEXITSTATUS(*wstatus) != 0) || WIFSIGNALED(*wstatus))
        {
            perrf("child namespace init process abnormal terminated\n");
            errno = WIFEXITED(*wstatus) ? WEXITSTATUS(*wstatus) : (interrupted ? EINTR : EFAULT);
            PRINTERR("setup child");
            goto error;
        }
    }
    return retp;

    error:
    return -1;
}

int cjail_exec(struct cjail_para* para, struct cjail_result* result)
{
    void *child_stack = NULL;
    int wstatus, ret = 0, tsgot = 0;
    pid_t initpid, childpid;
    struct ts_socket tssock;
    struct taskstats ts;
    struct cleanupstack cstack = { 0 };
    child = 0;
    interrupted = 0;

    if(geteuid())
        RETERR(EPERM);
    if(!para)
        RETERR(EINVAL);
    exec_para.para = *para;

    installsigs(lib_sigrules, 0);
    stack_push(&cstack, CLN_SIGSET, lib_sigrules);

    //setup pipe
    IFERR(pipe_c(exec_para.resultpipe))
    {
        PRINTERR("create pipe");
        ret = -1;
        goto out_cleanup;
    }
    stack_push(&cstack, CLN_CLOSE, exec_para.resultpipe[0]);

    //setup cgroup stage I
    IFERR(setup_cgroup(&exec_para.cgtasksfd))
    {
        ret = -1;
        goto out_cleanup;
    }
    stack_push(&cstack, CLN_CLOSE, exec_para.cgtasksfd);
    stack_push(&cstack, CLN_CGROUP, "pids");
    if(exec_para.para.cg_rss > 0)
        stack_push(&cstack, CLN_CGROUP, "memory");

    //setup taskstats
    IFERR(setup_taskstats(&tssock))
    {
        ret = -1;
        goto out_cleanup;
    }
    stack_push(&cstack, CLN_TASKSTAT, &tssock);

    //clone
    child_stack = malloc(STACKSIZE);
    if(!child_stack)
    {
        PRINTERR("malloc stack");
        ret = -1;
        goto out_cleanup;
    }
    stack_push(&cstack, CLN_FREE, &child_stack);
    int optionflag = 0;
    optionflag |= exec_para.para.sharenet ? 0 : CLONE_NEWNET;
    initpid = clone(child_init, child_stack + STACKSIZE,
                          SIGCHLD | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWPID | optionflag, NULL);
    IFERR(initpid)
    {
        PRINTERR("clone child namespace init process");
        ret = -1;
        goto out_cleanup;
    }
    close(exec_para.resultpipe[1]);
    pdebugf("Init PID: %d\n", initpid);

    //setup cgroup stage II
    while(cgroup_read("pids", "tasks", "%d", &childpid) == EOF)
    {
        if(child || interrupted)
            goto out_kill;
        usleep(100000);
    }
    pdebugf("Got childpid: %d\n", childpid);
    if(exec_para.para.cg_rss)
    {
        cgroup_write("memory", "tasks", "%d", childpid);
    }
    kill(initpid, SIGREADY);

    //socket buffer may overflow while the child process are executing
    while(!tsgot)
    {
        if(interrupted && !child)
        {
            IFERR(kill(initpid, SIGTERM))
            {
                if(errno != ESRCH)
                {
                    PRINTERR("terminate init process");
                    goto out_kill;
                }
            }
        }
        int tsret = taskstats_getstats(&tssock, &ts);
        if(tsret == 0 && ts.ac_pid == childpid)
            tsgot = 1;
        else if(tsret < 0)
        {
            switch(errno)
            {
                case EAGAIN:
                case ETIMEDOUT:
                case EINTR:
                case EBUSY:
                    if(child)
                        tsgot = -1;
                    break;
                default:
                    tsgot = -1;
                    break;
            }
        }
    }
    if(tsgot == -1)
    {
        perrf("Failed to receive from taskstats.\n");
        ret = -1;
        goto out_kill;
    }

    if(result)
    {
        //get result from pipe
        size_t n = read(exec_para.resultpipe[0], result, sizeof(*result));
        IFERR(n)
            PRINTERR("get result");
        result->stats = ts;
    }

    out_kill:
    if(interrupted && !child)
        IFERR(cjail_kill(initpid))
            ret = -1;
    IFERR(cjail_wait(initpid, &wstatus))
        ret = -1;

    if(isatty(STDIN_FILENO))
        IFERR(tcsetpgrp(STDIN_FILENO, getpgrp()))
            PRINTERR("set back control terminal");

    out_cleanup:
    do_cleanup(&cstack);

    return ret;
}

void cjail_para_init(struct cjail_para* para)
{
    memset(para, 0, sizeof(struct cjail_para));
    para->rlim_core = -1;
    para->uid = 65534;
    para->gid = 65534;
}
