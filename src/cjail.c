/**
 * @internal
 * @file cjail.c
 * @brief cjail main library entry point source
 */
#define _GNU_SOURCE
#include "cjail.h"
#include "cgroup.h"
#include "cleanup.h"
#include "init.h"
#include "logger.h"
#include "sigset.h"
#include "protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/epoll.h>
#include <sys/signal.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>

#define STACKSIZE 16
#define EPOLL_EVENT_CNT 4

// clang-format off
static struct sig_rule lib_sigrules[] = {
    { SIGPIPE , SIG_IGN   , NULL, 0, {{0}}, 0 },
    { SIGTTIN , SIG_IGN   , NULL, 0, {{0}}, 0 },
    { SIGTTOU , SIG_IGN   , NULL, 0, {{0}}, 0 },
    { 0       , NULL      , NULL, 0, {{0}}, 0 },
};
// clang-format on

static int init_cgroup(const struct cjail_ctx *ctx)
{
    if (ctx->cgroup_root) {
        if (cgroup_set_root(ctx->cgroup_root)) {
            return -1;
        }
    }

    if (ctx->cg_rss > 0) {
        if (cgroup_create("memory")) {
            return -1;
        }
        if (cgroup_write("memory", "memory.limit_in_bytes", "%lld",
                         ctx->cg_rss * 1024) < 0) {
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
        if (errno != ESRCH) {
            return -1;
        } else {
            return 0;
        }
    }
    if (waitpid(pid, NULL, 0) < 0) {
        return -1;
    }
    return 0;
}

static pid_t cjail_wait(struct exec_meta *meta)
{
    int wstatus;
    pid_t retp;
retry:
    retp = waitpid(meta->jailpid, &wstatus, 0);
    if (retp < 0) {
        if (errno == ECHILD) {
            fatalf("Lost control of child namespace init process\n");
            goto error;
        } else if (errno == EINTR) {
            if (meta->interrupted && !meta->child) {
                cjail_kill(meta->jailpid);
                goto error;
            }
            goto retry;
        } else {
            PFTL("waitpid");
            goto error;
        }
    }

    if ((WIFEXITED(wstatus) && WEXITSTATUS(wstatus) != 0) || WIFSIGNALED(wstatus)) {
        errorf("child namespace init process abnormal terminated\n");
        if (WIFEXITED(wstatus)) {
            meta->jail_errno = WEXITSTATUS(wstatus);
        } else if (WIFSIGNALED(wstatus)) {
            errorf("Received signal: %d\n", WTERMSIG(wstatus));
            switch (WTERMSIG(wstatus)) {
                case SIGSEGV:
                case SIGFPE:
                case SIGILL:
                case SIGIOT:
                case SIGBUS:
                    meta->jail_errno = EFAULT;
                case SIGKILL:
                    meta->jail_errno = ECANCELED;
                default:
                    meta->jail_errno = EINTR;
            }
        }
        errorf("setup process failed with error: %s\n", strerror(meta->jail_errno));

        goto error;
    }

    return retp;

error:
    return -1;
}

static int handle_sock(const struct epoll_event *event, int epfd, struct exec_meta *meta, ts_t *ts, struct cjail_result *result)
{
    if (event->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
        debugf("Caught socket event: %#x on fd: %d\n", event->events, event->data.fd);
        debugf("Socket closed by peer, stop listening!\n");
        if (epoll_del(epfd, event->data.fd)) {
            PFTL("delete socketpair epoll event");
            return -1;
        }
        return 0;
    }
    if (event->events & EPOLLIN) {
        struct ucred cred;
        switch (recv_magic(meta->sockpair[0])) {
            case -1:
                PFTL("receive magic packet");
                return -1;
            case CRED_MAGIC:
                devf("Got CRED_MAGIC\n");
                if (recv_cred(meta->sockpair[0], &cred) < 0) {
                    PFTL("receive cred packet");
                    return -1;
                }
                /* We only have one child process now, so ignore other request if childpid is set. */
                if (meta->childpid) {
                    break;
                }
                meta->childpid = cred.pid;
                debugf("Got childpid: %d\n", meta->childpid);
                if (meta->ctx.cg_rss) {
                    cgroup_write("memory", "tasks", "%d", meta->childpid);
                }
                if (taskstats_add_task(ts, meta->childpid)) {
                    PFTL("listen on child process");
                    return -1;
                }
                /* No longer use real-time signal to notify */
                if (send_ready(meta->sockpair[0]) < 0) {
                    PFTL("notify container process");
                    return -1;
                }
                break;
            case RESULT_MAGIC:
                /* get result from socket */
                devf("Got RESULT_MAGIC\n");
                if (recv_result(meta->sockpair[0], result) < 0) {
                    PERR("get result");
                }
                meta->result = 1;
                break;
            default:
                errorf("Received unknown magic\n");
                break;
        }
    }

    return 0;
}

static int handle_sigfd(int sigfd, struct exec_meta *meta)
{
    struct signalfd_siginfo sinfo;
    if (read(sigfd, &sinfo, sizeof(sinfo)) < 0) {
        return -1;
    }
    switch (sinfo.ssi_signo) {
        case SIGHUP:
        case SIGINT:
        case SIGQUIT:
        case SIGTERM:
            meta->interrupted = 1;
            cjail_kill(meta->jailpid);
            break;
        case SIGCHLD:
            if (sinfo.ssi_code != SI_USER && sinfo.ssi_code != SI_QUEUE && sinfo.ssi_pid == meta->jailpid) {
                meta->child = 1;
                if (!meta->interrupted) {
                    if (cjail_wait(meta) < 0) {
                        return -1;
                    }
                }
            }
            break;
    }
    return 0;
}

int cjail_exec(const struct cjail_ctx *ctx, struct cjail_result *result)
{
    unsigned char clone_stack[STACKSIZE] __attribute__((aligned(16)));
    int ret = 0, cloned = 0;
    unsigned int flag = SIGCHLD | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWPID;
    ts_t *ts;
    //struct taskstats ts = { 0 };
    struct cleanupstack cstack = { 0 }, socketstack = { 0 };
    struct exec_meta *meta = NULL;
    sigset_t sigset, origset;
    int epfd, sigfd;

    if (geteuid()) {
        RETERR(EPERM);
    }
    if (!ctx) {
        RETERR(EINVAL);
    }

    /* Record original signal mask */
    sigprocmask(SIG_SETMASK, NULL, &origset);

    meta = (struct exec_meta *)malloc(sizeof(struct exec_meta));
    memset(meta, 0, sizeof(struct exec_meta));
    stack_push(&cstack, CLN_FREE, &meta);
    meta->ctx = *ctx;

    installsigs(lib_sigrules);
    stack_push(&cstack, CLN_SIGSET, lib_sigrules);

    /* Create socketpair */
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, meta->sockpair)) {
        PFTL("create main socketpair");
        ret = -1;
        goto out_cleanup;
    }
    stack_push(&cstack, CLN_CLOSE, meta->sockpair[0]);
    stack_push(&socketstack, CLN_CLOSE, meta->sockpair[1]);
    if (set_passcred(meta->sockpair[0])) {
        PFTL("set SO_PASSCRED on socketpair");
        ret = -1;
        goto out_cleanup;
    }

    /* Initialize cgroup */
    if (init_cgroup(&meta->ctx)) {
        ret = -1;
        goto out_cleanup;
    }
    if (meta->ctx.cg_rss > 0) {
        stack_push(&cstack, CLN_CGROUP, "memory");
    }

    /* Block signals for signalfd */
    sigsetset(&sigset, 5, SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGCHLD);
    sigprocmask(SIG_SETMASK, &sigset, NULL);

    /* Setup taskstats */
    if ((ts = taskstats_new()) == NULL) {
        ret = -1;
        goto out_cleanup;
    }
    stack_push(&cstack, CLN_TASKSTAT, ts);

    /* Clone a process in new namespace */
    if (!meta->ctx.sharenet) flag |= CLONE_NEWNET;
    meta->jailpid = clone(jail_init, clone_stack + STACKSIZE, flag, (void *)meta);
    if (meta->jailpid < 0) {
        PFTL("clone child namespace init process");
        ret = -1;
        goto out_cleanup;
    }
    cloned = 1;
    /* Use cleanupstack to close the client side */
    do_cleanup(&socketstack);
    debugf("Init PID: %d\n", meta->jailpid);

    sigfd = signalfd(-1, &sigset, SFD_CLOEXEC);
    if (sigfd < 0) {
        PFTL("create signalfd");
        ret = -1;
        goto out_cleanup;
    }
    stack_push(&cstack, CLN_CLOSE, sigfd);

    /* Setup Epoll */
    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        PFTL("create epoll file descriptor");
        ret = -1;
        goto out_cleanup;
    }
    stack_push(&cstack, CLN_CLOSE, epfd);
    if (epoll_add(epfd, meta->sockpair[0], EPOLLIN | EPOLLERR | EPOLLRDHUP)) {
        PFTL("add communicate socket epoll event");
        ret = -1;
        goto out_cleanup;
    }
    if (epoll_add(epfd, sigfd, EPOLLIN)) {
        PFTL("add signalfd epoll event");
        ret = -1;
        goto out_cleanup;
    }
    if (epoll_add(epfd, taskstats_sockfd(ts), EPOLLIN)) {
        PFTL("add taskstats epoll event");
        ret = -1;
        goto out_cleanup;
    }

    /* Enter waiting loop */
    while (!meta->interrupted && (!meta->child || !meta->result)) {
        struct epoll_event epev[EPOLL_EVENT_CNT];
        int epcnt = 0;

        if ((epcnt = epoll_wait(epfd, epev, EPOLL_EVENT_CNT, -1)) < 0) {
            PFTL("wait epoll event");
            ret = -1;
            goto out_cleanup;
        }

        for (int i = 0; i < epcnt; i++) {
            devf("Got epoll event for fd: %d\n", epev[i].data.fd);
            if (epev[i].data.fd == meta->sockpair[0]) {
                if (handle_sock(&epev[i], epfd, meta, ts, result) < 0) {
                    ret = -1;
                    goto out_cleanup;
                }
            }
            if (epev[i].data.fd == sigfd) {
                if (epev[i].events & (EPOLLERR | EPOLLHUP)) {
                    fatalf("Signal fd unexpectedly be closed!");
                    ret = -1;
                    goto out_cleanup;
                }
                if (epev[i].events & EPOLLIN) {
                    if (handle_sigfd(sigfd, meta) < 0) {
                        ret = -1;
                        goto out_cleanup;
                    }
                    if (meta->interrupted) {
                        ret = -1;
                    }
                }
            }
            if (epev[i].data.fd == taskstats_sockfd(ts)) {
                if (epev[i].events & (EPOLLERR | EPOLLHUP)) {
                    errorf("Taskstats netlink socket unexpectedly be closed!");
                    if (epoll_del(epfd, taskstats_sockfd(ts))) {
                        PFTL("delete netlink socket epoll event");
                        ret = -1;
                        goto out_cleanup;
                    }
                }
                if (epev[i].events & EPOLLIN) {
                    if (taskstats_recv(ts) < 0) {
                        ret = -1;
                        goto out_cleanup;
                    }
                }
            }
        }
    }

    if (ret == 0 && result) {
        if (taskstats_get_stats(ts, meta->childpid, &result->stats)) {
            errorf("Failed to receive from taskstats.\n");
            ret = -1;
        }
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

out_cleanup:
    if (cloned) {
        if (!meta->child) {
            if (cjail_kill(meta->jailpid)) {
                ret = -1;
            }
        }
        /* Recover terminal process group */
        if (isatty(STDIN_FILENO)) {
            if (tcsetpgrp(STDIN_FILENO, getpgrp())) {
                PWRN("set back control terminal");
            }
        }
    }

    if (!errno && meta->jail_errno) {
        errno = meta->jail_errno;
    }
    if (meta->interrupted) {
        errno = EINTR;
    }

    do_cleanup(&socketstack);
    do_cleanup(&cstack);
    sigprocmask(SIG_SETMASK, &origset, NULL);

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


