/**
 * @internal
 * @file cjail.c
 * @brief cjail main library entry point source
 */
#include "cjail.h"
#include "cgroup.h"
#include "cleanup.h"
#include "init.h"
#include "logger.h"
#include "sigset.h"

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

// clang-format off
static struct sig_rule lib_sigrules[] = {
    { SIGHUP  , sighandler, NULL, 0, {{0}}, 0 },
    { SIGINT  , sighandler, NULL, 0, {{0}}, 0 },
    { SIGQUIT , sighandler, NULL, 0, {{0}}, 0 },
    { SIGPIPE , SIG_IGN   , NULL, 0, {{0}}, 0 },
    { SIGTERM , sighandler, NULL, 0, {{0}}, 0 },
    { SIGCHLD , sighandler, NULL, 0, {{0}}, 0 },
    { SIGTTIN , SIG_IGN   , NULL, 0, {{0}}, 0 },
    { SIGTTOU , SIG_IGN   , NULL, 0, {{0}}, 0 },
    { 0       , NULL      , NULL, 0, {{0}}, 0 },
};
// clang-format on

static int init_cgroup(const struct cjail_ctx ctx, int *pidfd)
{
    if (ctx.cgroup_root) {
        if (cgroup_set_root(ctx.cgroup_root)) {
            return -1;
        }
    }

    if (cgroup_create("pids")) {
        return -1;
    }
    if ((*pidfd = cgroup_open_tasks("pids")) < 0) {
        return -1;
    }

    if (ctx.cg_rss > 0) {
        if (cgroup_create("memory")) {
            return -1;
        }
        if (cgroup_write("memory", "memory.limit_in_bytes", "%lld",
                         ctx.cg_rss * 1024) < 0) {
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

static pid_t cjail_wait(pid_t initpid, int *initerrno)
{
    int wstatus;
    pid_t retp;
retry:
    retp = waitpid(initpid, &wstatus, 0);
    if (retp < 0) {
        if (errno == ECHILD) {
            fatalf("Lost control of child namespace init process\n");
            goto error;
        } else if (errno == EINTR) {
            if (interrupted && !child)
                cjail_kill(initpid);
            goto retry;
        } else {
            PFTL("waitpid");
            goto error;
        }
    }

    if ((WIFEXITED(wstatus) && WEXITSTATUS(wstatus) != 0) || WIFSIGNALED(wstatus)) {
        errorf("child namespace init process abnormal terminated\n");
        if (WIFEXITED(wstatus)) {
            *initerrno = WEXITSTATUS(wstatus);
        } else if (WIFSIGNALED(wstatus)) {
            errorf("Received signal: %d\n", WTERMSIG(wstatus));
            switch (WTERMSIG(wstatus)) {
                case SIGSEGV:
                case SIGFPE:
                case SIGILL:
                case SIGIOT:
                case SIGBUS:
                    *initerrno = EFAULT;
                case SIGKILL:
                    *initerrno = ECANCELED;
                default:
                    *initerrno = EINTR;
            }
        }
        errorf("setup process failed with error: %s\n", strerror(*initerrno));

        goto error;
    }

    return retp;

error:
    return -1;
}

int cjail_exec(const struct cjail_ctx *ctx, struct cjail_result *result)
{
    char child_stack[STACKSIZE + 1] __attribute__((aligned(16)));
    int ret = 0, initerr = 0;
    unsigned int flag = SIGCHLD | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWPID;
    pid_t initpid, childpid;
    tsproc_t tsproc = { 0 };
    struct taskstats ts = { 0 };
    struct cleanupstack cstack = { 0 }, pipestack = { 0 };
    struct exec_meta *meta;
    child = 0;
    interrupted = 0;

    if (geteuid())
        RETERR(EPERM);
    if (!ctx)
        RETERR(EINVAL);

    meta = (struct exec_meta *)malloc(sizeof(struct exec_meta));
    stack_push(&cstack, CLN_FREE, &meta);
    meta->ctx = *ctx;

    installsigs(lib_sigrules);
    stack_push(&cstack, CLN_SIGSET, lib_sigrules);

    //setup pipe
    if (pipe_c(meta->resultpipe)) {
        PFTL("create pipe");
        ret = -1;
        goto out_cleanup;
    }
    stack_push(&cstack, CLN_CLOSE, meta->resultpipe[0]);
    stack_push(&pipestack, CLN_CLOSE, meta->resultpipe[1]);

    //setup cgroup stage I
    if (init_cgroup(meta->ctx, &meta->cgtasksfd)) {
        ret = -1;
        goto out_cleanup;
    }
    stack_push(&cstack, CLN_CLOSE, meta->cgtasksfd);
    stack_push(&cstack, CLN_CGROUP, "pids");
    if (meta->ctx.cg_rss > 0)
        stack_push(&cstack, CLN_CGROUP, "memory");

    //setup taskstats
    if (taskstats_run(&tsproc)) {
        ret = -1;
        goto out_cleanup;
    }
    stack_push(&cstack, CLN_TASKSTAT, &tsproc);

    //clone
    if (!meta->ctx.sharenet) flag |= CLONE_NEWNET;
    initpid = clone(jail_init, child_stack + STACKSIZE, flag, (void *)meta);
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
        if (child || interrupted) {
            ret = -1;
            cjail_kill(initpid);
            goto out_wait;
        }
        usleep(100000);
    }
    debugf("Got childpid: %d\n", childpid);
    if (meta->ctx.cg_rss) {
        cgroup_write("memory", "tasks", "%d", childpid);
    }
    if (taskstats_listen(&tsproc, childpid)) {
        PFTL("listen on child process");
        ret = -1;
        cjail_kill(initpid);
        goto out_wait;
    }
    kill(initpid, SIGREADY);

out_wait:
    if (cjail_wait(initpid, &initerr) < 0) {
        ret = -1;
    }

    if (taskstats_result(&tsproc, childpid, &ts)) {
        errorf("Failed to receive from taskstats.\n");
        ret = -1;
    }

    if (ret == 0 && result) {
        //get result from pipe
        memset(result, 0, sizeof(*result));
        size_t n = read(meta->resultpipe[0], result, sizeof(*result));
        if (n < 0)
            PERR("get result");
        result->stats = ts;
        if (meta->ctx.cg_rss) {
            if (cgroup_read("memory", "memory.oom_control",
                            "oom_kill_disable %*d\n"
                            "under_oom %*d\n"
                            "oom_kill %d",
                            &result->oomkill) < 0) {
                errorf("Can't read memory.oom_control\n");
                warnf("oomkill value invalid!\n");
                result->oomkill = -1;
            }
        }
    }

    if ((interrupted && !child))
        if (cjail_kill(initpid))
            ret = -1;

    if (isatty(STDIN_FILENO))
        if (tcsetpgrp(STDIN_FILENO, getpgrp()))
            PWRN("set back control terminal");

out_cleanup:
    do_cleanup(&pipestack);
    do_cleanup(&cstack);

    if (!errno && initerr) {
        errno = initerr;
    }
    return ret;
}

void cjail_ctx_init(struct cjail_ctx *ctx)
{
    memset(ctx, 0, sizeof(struct cjail_ctx));
    ctx->rlim_core = -1;
    ctx->uid = 65534;
    ctx->gid = 65534;
    ctx->fd_input = STDIN_FILENO;
    ctx->fd_output = STDOUT_FILENO;
    ctx->fd_error = STDERR_FILENO;
}
