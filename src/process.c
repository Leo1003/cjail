/**
 * @internal
 * @file process.c
 * @brief child process initilizing source
 */
#include "process.h"
#include "cjail.h"
#include "fds.h"
#include "logger.h"
#include "sigset.h"
#include "utils.h"

#include <errno.h>
#include <grp.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>

// clang-format off
static struct sig_rule child_sigrules[] = {
    { SIGTTIN , SIG_IGN, NULL, 0, {{0}}, 0 },
    { SIGTTOU , SIG_IGN, NULL, 0, {{0}}, 0 },
    { 0       , NULL   , NULL, 0, {{0}}, 0 },
};
// clang-format on

_Noreturn inline static void child_exit()
{
    exit(errno);
}

inline static int setrl(int res, long long val)
{
    struct rlimit rl;
    rl.rlim_cur = rl.rlim_max = val;
    return setrlimit(res, &rl);
}
static int set_rlimit(const struct cjail_ctx ctx)
{
    if (ctx.rlim_as > 0) {
        if (setrl(RLIMIT_AS, ctx.rlim_as * 1024))
            goto error;
        devf("set_rlimit: RLIMIT_AS set to %lld KB\n", ctx.rlim_as);
    }
    if (ctx.rlim_core >= 0) {
        if (setrl(RLIMIT_CORE, ctx.rlim_core * 1024))
            goto error;
        devf("set_rlimit: RLIMIT_CORE set to %lld KB\n", ctx.rlim_core);
    }
    if (ctx.rlim_nofile > 0) {
        if (setrl(RLIMIT_NOFILE, ctx.rlim_nofile))
            goto error;
        devf("set_rlimit: RLIMIT_NOFILE set to %lld\n", ctx.rlim_nofile);
    }
    if (ctx.rlim_fsize > 0) {
        if (setrl(RLIMIT_FSIZE, ctx.rlim_fsize * 1024))
            goto error;
        devf("set_rlimit: RLIMIT_FSIZE set to %lld KB\n", ctx.rlim_fsize);
    }
    if (ctx.rlim_proc > 0) {
        if (setrl(RLIMIT_NPROC, ctx.rlim_proc))
            goto error;
        devf("set_rlimit: RLIMIT_NPROC set to %lld\n", ctx.rlim_proc);
    }
    if (ctx.rlim_stack > 0) {
        if (setrl(RLIMIT_STACK, ctx.rlim_stack * 1024))
            goto error;
        devf("set_rlimit: RLIMIT_STACK set to %lld KB\n", ctx.rlim_stack);
    }
    return 0;

error:
    PFTL("setup_rlimit");
    return -1;
}

static int load_seccomp(const struct cjail_ctx ctx, struct sock_fprog *bpf)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        PFTL("set no new privs");
        return -1;
    }
    if (!ctx.seccomp_cfg)
        return 0;

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, bpf, 0, 0)) {
        PFTL("load seccomp filter");
        return -1;
    }
    return 0;
}

void child_process(struct exec_meta meta)
{
    /*
     *  Child process part
     */
    if (clearsigs())
        child_exit();
    if (installsigs(child_sigrules))
        child_exit();
    uid_t uid = meta.ctx.uid;
    gid_t gid = meta.ctx.gid;
    if (setresgid(gid, gid, gid)) {
        PFTL("setgid");
        child_exit();
    }
    if (setgroups(0, NULL)) {
        PFTL("setgroups");
        child_exit();
    }
    if (setresuid(uid, uid, uid)) {
        PFTL("setuid");
        child_exit();
    }
    if (setpgrp()) {
        PFTL("setpgrp");
        child_exit();
    }
    if (setup_fd(meta.ctx))
        child_exit();
    if (isatty(STDIN_FILENO)) {
        if (tcsetpgrp(STDIN_FILENO, getpgrp())) {
            PWRN("get control terminal");
        }
    }
    if (meta.ctx.cpuset) {
        if (sched_setaffinity(getpid(), sizeof(*meta.ctx.cpuset), meta.ctx.cpuset)) {
            PFTL("setup_cpumask");
            child_exit();
        }
    }
    if (set_rlimit(meta.ctx))
        child_exit();
    //To avoid seccomp block the systemcall
    //We move before it.
    int rtsig;
    sigset_t rtset;
    sigsetset(&rtset, 1, SIGREADY);
    sigwait(&rtset, &rtsig);
    devf("child continued from rt_signal\n");

    if (load_seccomp(meta.ctx, &meta.bpf))
        child_exit();
    execve(meta.ctx.argv[0], meta.ctx.argv, meta.ctx.environ);
    child_exit();
}
