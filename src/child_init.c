#include "cjail.h"
#include "child_init.h"
#include "setup.h"
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

inline static void init_signalset()
{
    struct sigaction sa;
    bzero(&sa, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGHUP);
    sigaddset(&sa.sa_mask, SIGINT);
    sigaddset(&sa.sa_mask, SIGQUIT);
    sigaddset(&sa.sa_mask, SIGALRM);
    sigaddset(&sa.sa_mask, SIGTERM);
    sigaddset(&sa.sa_mask, SIGCHLD);
    sigaddset(&sa.sa_mask, SIGRTMIN);
    sa.sa_handler = sigact;
    sa.sa_flags = SA_NOCLDSTOP;
    sigaction(SIGHUP , &sa, NULL);
    sigaction(SIGINT , &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGALRM, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGCHLD, &sa, NULL);
    sigaction(SIGRTMIN, &sa, NULL);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
}

int child_init(void *arg UNUSED)
{
    pid_t pid;
    struct termios term;
    int ttymode, chwaited = 0;

    if(getpid() != 1)
    {
        perrf("This process should be run as init process.\n");
        exit(EINVAL);
    }

    //we should register the signals, otherwise they will be ignored because we are init process
    init_signalset();

    close(exec_para.resultpipe[0]);
    IFERR(setcloexec(exec_para.resultpipe[1]))
        exit(errno);
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
    sigemptyset(&rtset);
    sigaddset(&rtset, SIGCHLD); //Prevent child error
    sigaddset(&rtset, SIGRTMIN);
    sigprocmask(SIG_BLOCK, &rtset, NULL);

    //save tty setting and restore it back if needed
    ttymode = (tcgetattr(STDIN_FILENO, &term) == 0);

    pid = fork();
    if(pid > 0)
    {
        struct cjail_result result;
        siginfo_t sinfo;
        struct timeval stime, etime, timespan;
        memset(&result, 0, sizeof(result));

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
        if(exec_para.para.lim_time)
        {
            struct itimerval it;
            it.it_value = *exec_para.para.lim_time;
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
            //set back control tty
            //because we are in the pid namespace, getpgrp() will always return 0
            //using getpid() instead
            IFERR(tcsetpgrp(STDIN_FILENO, getpid()))
            {
                PRINTERR("set back control terminal");
            }
            IFERR(tcsetattr(STDIN_FILENO, TCSADRAIN, &term))
            {
                PRINTERR("restore terminal setting");
            }
        }

        pdebugf("Sending result...\n");
        write(exec_para.resultpipe[1], &result, sizeof(result));

        //move setup failed to here
        if(result.info.si_code == CLD_KILLED && result.info.si_status == SIGUSR1)
        {
            perrf("setup child process failed\n");
            exit(1);
        }
        exit(0);
    }
    else if(pid == 0)
    {
        IFERR(setup_signals())
            raise(SIGUSR1);
        uid_t uid = exec_para.para.uid;
        gid_t gid = exec_para.para.gid;
        IFERR(setresgid(gid, gid, gid))
        {
            PRINTERR("setgid");
            raise(SIGUSR1);
        }
        IFERR(setgroups(0, NULL))
        {
            PRINTERR("setgroups");
            raise(SIGUSR1);
        }
        IFERR(setresuid(uid, uid, uid))
        {
            PRINTERR("setuid");
            raise(SIGUSR1);
        }
        IFERR(setpgrp())
        {
            PRINTERR("setpgrp");
            raise(SIGUSR1);
        }
        if(isatty(STDIN_FILENO))
        {
            IFERR(tcsetpgrp(STDIN_FILENO, getpgrp()))
            {
                PRINTERR("setpgrp");
                raise(SIGUSR1);
            }
        }
        IFERR(setup_cpumask())
            raise(SIGUSR1);
        IFERR(setup_rlimit())
            raise(SIGUSR1);
        IFERR(setup_fd())
            raise(SIGUSR1);
        //To avoid seccomp block the systemcall
        //We move before it.
        sigwait(&rtset, &sig);
        pdebugf("child continued from rt_signal\n");
        sigprocmask(SIG_UNBLOCK, &rtset, NULL);
        signal(SIGRTMIN, SIG_DFL);

        IFERR(setup_seccomp(exec_para.para.argv))
            raise(SIGUSR1);
        pdebugf("Every things ready, execing target process\n");
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
        raise(SIGUSR1);
    }
    else
    {
        PRINTERR("fork");
        exit(errno);
    }
    exit(EFAULT); // it shouldn't be here!
}
