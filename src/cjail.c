#include "cjail.h"
#include "cgroup.h"
#include "cleanup.h"
#include "init.h"
#include "logger.h"
#include "sigset.h"
//#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/signal.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>

#define STACKSIZE 16

static volatile sig_atomic_t child = 0, interrupted = 0;
static void sighandler(int sig)
{
    switch (sig) {
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

static struct sig_rule lib_sigrules[] = {
    { SIGHUP  , sighandler, NULL, 0, {{0}}, 0 },
    { SIGINT  , sighandler, NULL, 0, {{0}}, 0 },
    { SIGQUIT , sighandler, NULL, 0, {{0}}, 0 },
    { SIGTERM , sighandler, NULL, 0, {{0}}, 0 },
    { SIGCHLD , sighandler, NULL, 0, {{0}}, 0 },
    { SIGTTIN , SIG_IGN   , NULL, 0, {{0}}, 0 },
    { SIGTTOU , SIG_IGN   , NULL, 0, {{0}}, 0 },
    { 0       , NULL      , NULL, 0, {{0}}, 0 },
};

static int init_taskstats(struct ts_socket *s)
{
    if (taskstats_create(s)) {
        goto error;
    }
    cpu_set_t cur;
    CPU_ZERO(&cur);
    for (int i = 0; i < get_nprocs(); i++) {
        CPU_SET(i, &cur);
    }
    if (taskstats_setcpuset(s, &cur)) {
        goto error;
    }
    return 0;

error:
    PFTL("init taskstats");
    return -1;
}

static int init_cgroup(const struct cjail_para para, int *pidfd)
{
    if (para.cgroup_root) {
        if (cgroup_set_root(para.cgroup_root)) {
            return -1;
        }
    }

    if (cgroup_create("pids")) {
        return -1;
    }
    if ((*pidfd = cgroup_open_tasks("pids")) < 0) {
        return -1;
    }

    if (para.cg_rss > 0) {
        if (cgroup_create("memory")) {
            return -1;
        }
        if (cgroup_write("memory", "memory.limit_in_bytes", "%lld",
                para.cg_rss * 1024) < 0) {
            return -1;
        }
        if (cgroup_write("memory", "memory.swappiness", "%u", 0) < 0) {
            return -1;
        }
    }
    return 0;
}

static int cjail_kill(pid_t pid)
{
    if (kill(pid, SIGKILL)) {
        if (errno != ESRCH)
            return -1;
    }
    usleep(100000);
    return 0;
}

static pid_t cjail_wait(pid_t initpid, int *wstatus, int *initerrno)
{
    pid_t retp;
    retry:
    retp = waitpid(initpid, wstatus, 0);
    if (retp < 0) {
        if (errno == ECHILD) {
            fatalf("Lost control of child namespace init process\n");
            goto error;
        } else if(errno == EINTR) {
            if (interrupted && !child)
                cjail_kill(initpid);
            goto retry;
        } else {
            PFTL("waitpid");
            goto error;
        }
    }

    if ((WIFEXITED(*wstatus) && WEXITSTATUS(*wstatus) != 0)
        || WIFSIGNALED(*wstatus)) {
        errorf("child namespace init process abnormal terminated\n");
        *initerrno = WIFEXITED(*wstatus) ? WEXITSTATUS(*wstatus) : (interrupted ? EINTR : EFAULT);
        errorf("Failed to setup child: %s\n", strerror(*initerrno));
        if (WIFSIGNALED(*wstatus)) {
            errorf("Received signal: %d\n", WTERMSIG(*wstatus));
        }
        goto error;
    }

    return retp;

    error:
    return -1;
}

int cjail_exec(const struct cjail_para* para, struct cjail_result* result)
{
    char child_stack[STACKSIZE + 1] __attribute__((aligned(16)));
    int wstatus, ret = 0, tsgot = 0, initerr = 0;
    pid_t initpid, childpid;
    struct ts_socket tssock = { 0 };
    struct taskstats ts = { 0 };
    struct cleanupstack cstack = { 0 }, pipestack = { 0 };
    struct exec_para *ep = (struct exec_para *) malloc(sizeof(struct exec_para));
    stack_push(&cstack, CLN_FREE, &ep);
    child = 0;
    interrupted = 0;

    if (geteuid())
        RETERR(EPERM);
    if (!para)
        RETERR(EINVAL);
    ep->para = *para;

    installsigs(lib_sigrules);
    stack_push(&cstack, CLN_SIGSET, lib_sigrules);

    //setup pipe
    if (pipe_c(ep->resultpipe)) {
        PFTL("create pipe");
        ret = -1;
        goto out_cleanup;
    }
    stack_push(&cstack, CLN_CLOSE, ep->resultpipe[0]);
    stack_push(&pipestack, CLN_CLOSE, ep->resultpipe[1]);

    //setup cgroup stage I
    if (init_cgroup(ep->para, &ep->cgtasksfd)) {
        ret = -1;
        goto out_cleanup;
    }
    stack_push(&cstack, CLN_CLOSE, ep->cgtasksfd);
    stack_push(&cstack, CLN_CGROUP, "pids");
    if (ep->para.cg_rss > 0)
        stack_push(&cstack, CLN_CGROUP, "memory");

    //setup taskstats
    if (init_taskstats(&tssock)) {
        ret = -1;
        goto out_cleanup;
    }
    stack_push(&cstack, CLN_TASKSTAT, &tssock);

    //clone
    int optionflag = 0;
    optionflag |= ep->para.sharenet ? 0 : CLONE_NEWNET;
    initpid = clone(child_init, child_stack + STACKSIZE,
                      SIGCHLD | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS |
                      CLONE_NEWPID | optionflag, (void *) ep);
    if (initpid < 0) {
        PFTL("clone child namespace init process");
        ret = -1;
        goto out_cleanup;
    }
    //use cleanupstack to close the write side
    do_cleanup(&pipestack);
    debugf("Init PID: %d\n", initpid);

    //setup cgroup stage II
    while (cgroup_read("pids", "tasks", "%d", &childpid) == EOF) {
        if (child || interrupted)
            goto out_kill;
        usleep(100000);
    }
    debugf("Got childpid: %d\n", childpid);
    if (ep->para.cg_rss) {
        cgroup_write("memory", "tasks", "%d", childpid);
    }
    kill(initpid, SIGREADY);

    //socket buffer may overflow while the child process are executing
    while (!tsgot) {
        if (interrupted && !child) {
            if (kill(initpid, SIGTERM)) {
                if (errno != ESRCH) {
                    PFTL("terminate init process");
                    goto out_kill;
                }
            }
        }
        if (taskstats_getstats(&tssock, &ts)) {
            switch (errno) {
                case EAGAIN:
                case ETIMEDOUT:
                case EINTR:
                case EBUSY:
                    if (child)
                        tsgot = -1;
                    break;
                default:
                    tsgot = -1;
                    break;
            }
        } else if (ts.ac_pid == childpid) {
            tsgot = 1;
        }
    }
    if (tsgot == -1) {
        errorf("Failed to receive from taskstats.\n");
        ret = -1;
        goto out_kill;
    }

    if (result) {
        //get result from pipe
        memset(result, 0, sizeof(*result));
        size_t n = read(ep->resultpipe[0], result, sizeof(*result));
        if (n < 0)
            PFTL("get result");
        result->stats = ts;
        if (ep->para.cg_rss) {
            if (cgroup_read("memory", "memory.oom_control",
                              "oom_kill_disable %*d\n"
                              "under_oom %*d\n"
                              "oom_kill %d", &result->oomkill) < 0) {
                errorf("Can't read memory.oom_control\n");
                warnf("oomkill value invalid!\n");
                result->oomkill = -1;
            }
        }
    }

    out_kill:
    if ((interrupted && !child) || tsgot != 1)
        if (cjail_kill(initpid))
            ret = -1;
    if (cjail_wait(initpid, &wstatus, &initerr) < 0)
        ret = -1;

    if (isatty(STDIN_FILENO))
        if (tcsetpgrp(STDIN_FILENO, getpgrp()))
            PWRN("set back control terminal");

    out_cleanup:
    do_cleanup(&pipestack);
    do_cleanup(&cstack);

    errno = (initerr ? initerr : errno);
    return ret;
}

void cjail_para_init(struct cjail_para* para)
{
    memset(para, 0, sizeof(struct cjail_para));
    para->rlim_core = -1;
    para->uid = 65534;
    para->gid = 65534;
    para->fd_input = STDIN_FILENO;
    para->fd_output = STDOUT_FILENO;
    para->fd_error = STDERR_FILENO;
}
