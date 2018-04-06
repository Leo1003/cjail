#include "cjail.h"
#include "child_init.h"
#include "setup.h"
#include "sigset.h"
#include "taskstats.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/taskstats.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

static volatile sig_atomic_t alarmed = 0, interrupted = 0;
static int child_exit_fd;
void sigact(int sig);
inline static void child_exit();

static struct sig_rule init_sigrules[] =
{
    { SIGHUP  , sigact , NULL, {{0}}, 0 },
    { SIGINT  , sigact , NULL, {{0}}, 0 },
    { SIGQUIT , sigact , NULL, {{0}}, 0 },
    { SIGALRM , sigact , NULL, {{0}}, 0 },
    { SIGTERM , sigact , NULL, {{0}}, 0 },
    { SIGCHLD , sigact , NULL, {{0}}, 0 },
    { SIGTTIN , SIG_IGN, NULL, {{0}}, 0 },
    { SIGTTOU , SIG_IGN, NULL, {{0}}, 0 },
    { SIGREADY, sigact , NULL, {{0}}, 0 },
    { 0       , NULL   , NULL, {{0}}, 0 },
};

static struct sig_rule child_sigrules[] =
{
    { SIGTTIN , SIG_IGN, NULL, {{0}}, 0 },
    { SIGTTOU , SIG_IGN, NULL, {{0}}, 0 },
    { SIGREADY, SIG_IGN, NULL, {{0}}, 0 },
    { 0       , NULL   , NULL, {{0}}, 0 },
};

int child_init(void *arg UNUSED)
{
    pid_t pid;
    struct termios term;
    int ttymode, chwaited = 0, errorpipe[2];

    if(getpid() != 1)
    {
        perrf("This process should be run as init process.\n");
        exit(EINVAL);
    }

    //we should register the signals, otherwise they will be ignored because we are init process
    //init_signalset();
    IFERR(installsigs(init_sigrules, SA_NOCLDSTOP))
    {
        PRINTERR("install init signals");
        exit(errno);
    }

    close(exec_para.resultpipe[0]);
    IFERR(prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0))
    {
        PRINTERR("set parent death signal");
        exit(errno);
    }

    IFERR(setup_fs())
        exit(errno);

    //block the signal SIGRTMIN
    int sig;
    sigset_t rtset;
    sigsetset(&rtset, 2, SIGCHLD, SIGRTMIN);
    sigprocmask(SIG_BLOCK, &rtset, NULL);

    //save tty setting and restore it back if needed
    ttymode = (tcgetattr(STDIN_FILENO, &term) == 0);

    IFERR(pipe_c(errorpipe))
    {
        PRINTERR("create pipe");
        exit(errno);
    }

    pid = fork();
    if(pid > 0)
    {
        struct cjail_result result;
        siginfo_t sinfo;
        struct timeval stime, etime, timespan;
        memset(&result, 0, sizeof(result));

        close(errorpipe[1]);

        pdebugf("Writing tasks file, PID: %d\n", pid);
        FILE *pidfile = fdopen(exec_para.cgtasksfd, "r+");
        if(!pidfile)
        {
            PRINTERR("fdopen cgroup task");
            exit(errno);
        }
        fprintf(pidfile, "%d", pid);
        fflush(pidfile);
        fclose(pidfile);
        pdebugf("Writed into tasks file\n");

        //prevent race condition
        sigwait(&rtset, &sig);
        if(sig == SIGCHLD)
        {
            //child should not exit now
            perrf("Child process exit unexpectedly!\n");
        }
        if(sig == SIGRTMIN)
        {
            pdebugf("init continued from rt_signal\n");
            kill(pid, SIGRTMIN);
        }
        sigprocmask(SIG_UNBLOCK, &rtset, NULL);

        gettimeofday(&stime, NULL);
        if(timerisset(&exec_para.para.lim_time))
        {
            pdebugf("Setting timer...\n");
            struct itimerval it;
            it.it_value = exec_para.para.lim_time;
            memset(&it.it_interval, 0, sizeof(it.it_interval));
            IFERR(setitimer(ITIMER_REAL, &it, NULL))
            {
                PRINTERR("setitimer");
                exit(errno);
            }
        }

        while(1)
        {
            IFERR(waitid(P_ALL, 0, &sinfo, WEXITED))
            {
                if(errno == ECHILD)
                    break;
            }
            if(interrupted)
            {
                perrf("Received signal, aborting...\n");
                exit(EINTR);
            }
            if(alarmed)
            {
                alarmed = 0;
                pdebugf("Execution timeout, killing process...\n");
                IFERR(kill(-1, SIGKILL))
                {
                    if(errno != ESRCH)
                    {
                        PRINTERR("kill timeouted child process");
                        exit(errno);
                    }
                }
                result.timekill = 1;
                continue;
            }
            if(sinfo.si_pid == pid)
            {
                chwaited = 1;
                result.info = sinfo;
            }
        }
        if(!chwaited)
        {
            perrf("Lost control of child process\n");
            exit(ECHILD);
        }

        gettimeofday(&etime, NULL);
        timersub(&etime, &stime, &timespan);
        result.time = timespan;

        if(ttymode)
        {
            IFERR(tcsetattr(STDIN_FILENO, TCSANOW, &term))
                PRINTERR("restore terminal setting");
        }
        //move setup failed to here
        if(result.info.si_code == CLD_KILLED && result.info.si_status == SIGUSR1)
        {
            perrf("setup child process failed\n");
            int childerr = 0;
            read(errorpipe[0], &childerr, sizeof(childerr));
            exit(childerr);
        }

        pdebugf("Sending result...\n");
        write(exec_para.resultpipe[1], &result, sizeof(result));

        exit(0);
    }
    else if(pid == 0)
    {
        /*
         *  Child process part
         */
        close(errorpipe[0]);
        child_exit_fd = errorpipe[1];
        IFERR(clearsigs())
            child_exit();
        IFERR(installsigs(child_sigrules, 0))
            child_exit();
        uid_t uid = exec_para.para.uid;
        gid_t gid = exec_para.para.gid;
        IFERR(setresgid(gid, gid, gid))
        {
            PRINTERR("setgid");
            child_exit();
        }
        IFERR(setgroups(0, NULL))
        {
            PRINTERR("setgroups");
            child_exit();
        }
        IFERR(setresuid(uid, uid, uid))
        {
            PRINTERR("setuid");
            child_exit();
        }
        IFERR(setpgrp())
        {
            PRINTERR("setpgrp");
            child_exit();
        }
        if(isatty(STDIN_FILENO))
        {
            IFERR(tcsetpgrp(STDIN_FILENO, getpgrp()))
            {
                PRINTERR("setpgrp");
                child_exit();
            }
        }
        IFERR(setup_cpumask())
            child_exit();
        IFERR(setup_rlimit())
            child_exit();
        IFERR(setup_fd())
            child_exit();
        //To avoid seccomp block the systemcall
        //We move before it.
        sigwait(&rtset, &sig);
        pdebugf("child continued from rt_signal\n");
        sigprocmask(SIG_UNBLOCK, &rtset, NULL);

        IFERR(setup_seccomp(exec_para.para.argv))
            child_exit();
#ifndef NDEBUG
        pdebugf("argv: {");
        for(int i = 0; exec_para.para.argv[i]; i++)
        {
            pdebugf(" ");
            if(i > 0)
                pdebugf(", ");
            pdebugf("%s", exec_para.para.argv[i]);
        }
        pdebugf(" }\n");
#endif
        execve(exec_para.para.argv[0], exec_para.para.argv, exec_para.para.environ);
        if(errno == ENOENT)
            exit(255);
        child_exit();
    }
    else
    {
        PRINTERR("fork");
        exit(errno);
    }
    exit(EFAULT); // it shouldn't be here!
}

void sigact(int sig)
{
    switch(sig)
    {
        case SIGHUP:
        case SIGINT:
        case SIGQUIT:
        case SIGTERM:
            interrupted = 1;
            break;
        case SIGALRM:
            alarmed = 1;
            break;
        case SIGCHLD:
            break;
    }
}

inline static void child_exit()
{
    write(child_exit_fd, &errno, sizeof(errno));
    raise(SIGUSR1);
}
