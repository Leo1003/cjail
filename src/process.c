#include "cjail.h"
#include "fds.h"
#include "logger.h"
#include "process.h"
#include "sigset.h"
#include "utils.h"

#include <errno.h>
#include <grp.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>

static struct sig_rule child_sigrules[] = {
    { SIGTTIN , SIG_IGN, NULL, 0, {{0}}, 0 },
    { SIGTTOU , SIG_IGN, NULL, 0, {{0}}, 0 },
    { 0       , NULL   , NULL, 0, {{0}}, 0 },
};

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
static int set_rlimit(const struct cjail_para para)
{
    if (para.rlim_as > 0) {
        if (setrl(RLIMIT_AS, para.rlim_as * 1024))
            goto error;
        devf("setup_rlimit: RLIMIT_AS set to %lld KB\n", para.rlim_as);
    }
    if (para.rlim_core >= 0) {
        if (setrl(RLIMIT_CORE, para.rlim_core * 1024))
            goto error;
        devf("setup_rlimit: RLIMIT_CORE set to %lld KB\n", para.rlim_core);
    }
    if (para.rlim_nofile > 0) {
        if (setrl(RLIMIT_NOFILE, para.rlim_nofile))
            goto error;
        devf("setup_rlimit: RLIMIT_NOFILE set to %lld\n", para.rlim_nofile);
    }
    if (para.rlim_fsize > 0) {
        if (setrl(RLIMIT_FSIZE, para.rlim_fsize * 1024))
            goto error;
        devf("setup_rlimit: RLIMIT_FSIZE set to %lld KB\n", para.rlim_fsize);
    }
    if (para.rlim_proc > 0) {
        if (setrl(RLIMIT_NPROC, para.rlim_proc))
            goto error;
        devf("setup_rlimit: RLIMIT_NPROC set to %lld\n", para.rlim_proc);
    }
    if (para.rlim_stack > 0) {
        if (setrl(RLIMIT_STACK, para.rlim_stack * 1024))
            goto error;
        devf("setup_rlimit: RLIMIT_STACK set to %lld KB\n", para.rlim_stack);
    }
    return 0;

    error:
    PFTL("setup_rlimit");
    return -1;
}

static int load_seccomp(const struct cjail_para para, struct sock_fprog* bpf)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        PFTL("set no new privs");
        return -1;
    }
    if (!para.seccompcfg)
        return 0;

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, bpf, 0, 0)) {
        PFTL("load seccomp filter");
        return -1;
    }
    return 0;
}

void child_process(struct exec_para ep)
{
    /*
     *  Child process part
     */
    if (clearsigs())
        child_exit();
    if (installsigs(child_sigrules))
        child_exit();
    uid_t uid = ep.para.uid;
    gid_t gid = ep.para.gid;
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
    if (setup_fd(ep.para))
        child_exit();
    if (isatty(STDIN_FILENO)) {
        if (tcsetpgrp(STDIN_FILENO, getpgrp())) {
            PWRN("get control terminal");
        }
    }
    if (ep.para.cpuset) {
        if (sched_setaffinity(getpid(), sizeof(*ep.para.cpuset), ep.para.cpuset)) {
            PFTL("setup_cpumask");
            child_exit();
        }
    }
    if (set_rlimit(ep.para))
        child_exit();
    //To avoid seccomp block the systemcall
    //We move before it.
    int rtsig;
    sigset_t rtset;
    sigsetset(&rtset, 1, SIGREADY);
    sigwait(&rtset, &rtsig);
    devf("child continued from rt_signal\n");
    //sigprocmask(SIG_UNBLOCK, &rtset, NULL);

    if (load_seccomp(ep.para, &ep.bpf))
        child_exit();
    execve(ep.para.argv[0], ep.para.argv, ep.para.environ);
    child_exit();
}
