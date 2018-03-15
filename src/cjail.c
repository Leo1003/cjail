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

#define RETRYTIMES 3

struct __exec_para exec_para;

static struct sigaction sa_save[32];
static volatile sig_atomic_t child = 0, interrupted = 0, error = 0;
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

#define SIGSAV(x) sigaction(x , &sa, &sa_save[x])
#define SIGRES(x) sigaction(x , &sa_save[x], NULL)
inline static void installsig()
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigaddset(&sa.sa_mask, SIGHUP);
    sigaddset(&sa.sa_mask, SIGINT);
    sigaddset(&sa.sa_mask, SIGQUIT);
    sigaddset(&sa.sa_mask, SIGTERM);
    sigaddset(&sa.sa_mask, SIGCHLD);
    sigaddset(&sa.sa_mask, SIGRTMIN);
    sa.sa_handler = sighandler;
    SIGSAV(SIGHUP);
    SIGSAV(SIGINT);
    SIGSAV(SIGQUIT);
    SIGSAV(SIGTERM);
    SIGSAV(SIGCHLD);
}

inline static void restoresig()
{
    SIGRES(SIGHUP);
    SIGRES(SIGINT);
    SIGRES(SIGQUIT);
    SIGRES(SIGTERM);
    SIGRES(SIGCHLD);
}

int cjail_exec(struct cjail_para* para, struct cjail_result* result)
{
    void *child_stack;
    int wstatus, ret = 0;
    pid_t initpid, childpid;
    struct ts_socket tssock;
    struct taskstats ts;

    if(geteuid())
        RETERR(EPERM);
    if(!para)
        RETERR(EINVAL);
    exec_para.para = *para;

    installsig();

    //setup pipe
    IFERR(pipe(exec_para.resultpipe))
    {
        PRINTERR("create pipe");
        ret = -1;
        goto out_sig;
    }

    //setup cgroup stage I
    IFERR(setup_cgroup(&exec_para.cgtasksfd))
    {
        ret = -1;
        goto out_pipe;
    }

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
        ret = -1;
        goto out_taskstats;
    }
    int optionflag = 0;
    optionflag |= exec_para.para.sharenet ? 0 : CLONE_NEWNET;
    initpid = clone(child_init, child_stack + STACKSIZE,
                          SIGCHLD | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWPID | optionflag, NULL);
    IFERR(initpid)
    {
        PRINTERR("clone child namespace init process");
        ret = -errno;
        goto out_free;
    }
    close(exec_para.resultpipe[1]);
    pdebugf("Init PID: %d\n", initpid);

    //setup cgroup stage II
    while(cgroup_read("pids", "tasks", "%d", &childpid) == EOF)
    {
        if(child || interrupted)
        {
            error = 1;
            break;
        }
        usleep(100000);
    }
    if(!error)
    {
        pdebugf("Got childpid: %d\n", childpid);
        if(exec_para.para.cg_rss)
        {
            cgroup_write("memory", "tasks", "%d", childpid);
        }
        kill(childpid, SIGRTMIN);
        kill(initpid, SIGRTMIN);
    }

    //socket buffer may overflow while the child process are executing
    int tsret = 0, waited = 0, tsgot = 0, retry = RETRYTIMES;
    if(error)
        tsgot = -1;
    while(!waited || !tsgot)
    {
        //wait for init process return
        if(interrupted)
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
            if(retp == initpid)
            {
                if((WIFEXITED(wstatus) && WEXITSTATUS(wstatus) != 0) || WIFSIGNALED(wstatus))
                {
                    perrf("child namespace init process abnormal terminated\n");
                    errno = WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : EFAULT;
                    ret = -1;
                    waited = 1;
                    goto out_kill;
                }
                waited = 1;
            }
        }
        //taskstats get stats
        if(!tsgot)
        {
            tsret = taskstats_getstats(&tssock, &ts);
            if(tsret == 0)
            {
                if(ts.ac_pid == childpid)
                    tsgot = 1;
                retry = RETRYTIMES;
            }
            if(tsret < 0)
            {
                switch(errno)
                {
                    case EAGAIN:
                    case ETIMEDOUT:
                    case EBUSY:
                        if(waited && !retry--)
                            tsgot = -1;
                        break;
                    default:
                        tsgot = -1;
                        break;
                }
            }
        }
    }
    if(tsgot == -1)
    {
        perrf("Failed to receive from taskstats.\n");
        ret = -1;
        goto out_kill;
    }

    if(!error && result)
    {
        //get result from pipe
        size_t n = read(exec_para.resultpipe[0], result, sizeof(*result));
        IFERR(n)
            PRINTERR("get result");
        result->stats = ts;
    }

    out_kill:
    if(!waited)
    {
        kill(childpid, SIGKILL);
        kill(initpid, SIGKILL);
        usleep(200000);
    }

    out_free:
    free(child_stack);

    out_taskstats:
    IFERR(taskstats_destory(&tssock))
        perrf("Failed to destory taskstats\n");

    out_cgroup:
    IFERR(close(exec_para.cgtasksfd))
        PRINTERR("close cgroup tasks file");
    IFERR(cgroup_destory("pids"))
        perrf("Failed to destory pids cgroup\n");
    if(exec_para.para.cg_rss > 0)
    {
        IFERR(cgroup_destory("memory"))
            perrf("Failed to destory memory cgroup\n");
    }

    out_pipe:
    IFERR(close(exec_para.resultpipe[0]))
        PRINTERR("close pipe");
    close(exec_para.resultpipe[1]);

    out_sig:
    restoresig();
    return ret;
}

void cjail_para_init(struct cjail_para* para)
{
    memset(para, 0, sizeof(struct cjail_para));
    para->rlim_core = -1;
    para->uid = 65534;
    para->gid = 65534;
}
