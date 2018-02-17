#include "cjail.h"
#include "child_init.h"
#include "setup.h"
#include "taskstats.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/taskstats.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

static int alarmed = 0;
static int interrupted = 0;
static int child = 0;
static int continued = 0;

void sigact(int sig, siginfo_t *info, void *data)
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
            child = 1;
            break;
    }
    if(sig == SIGRTMIN)
    {
        continued = 1;
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
    sa.sa_sigaction = sigact;
    sa.sa_flags = SA_NOCLDSTOP | SA_SIGINFO;
    sigaction(SIGHUP , &sa, NULL);
    sigaction(SIGINT , &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGALRM, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGCHLD, &sa, NULL);
    sigaction(SIGRTMIN, &sa, NULL);
}

int child_init(void *arg)
{
    pid_t pid;

    //we should register the signals, otherwise they will be ignored because we are init process
    init_signalset();

    close(exec_para.resultpipe[0]);
    IFERR(setup_fs())
        _exit(1);

    pid = fork();
    if(pid > 0)
    {
        struct cjail_result result;
        siginfo_t sinfo;
        struct timeval stime, etime, timespan;
        bzero(&result, sizeof(result));

        pdebugf("Writing tasks file, PID: %d\n", pid);
        FILE *pidfile = fdopen(exec_para.cgtasksfd, "r+");
        if(!pidfile)
        {
            PRINTERR("fdopen cgroup task");
            goto error;
        }
        fprintf(pidfile, "%d", pid);
        fflush(pidfile);
        fclose(pidfile);
        pdebugf("Writed into tasks file\n");
        if(!continued)
            pause();
        pdebugf("init continued from rt_signal\n");

        gettimeofday(&stime, NULL);
        if(exec_para.para.lim_time)
        {
            struct itimerval it;
            it.it_value = *exec_para.para.lim_time;
            IFERR(setitimer(ITIMER_REAL, &it, NULL))
            {
                PRINTERR("setitimer");
                goto error;
            }
        }

        wait:
        IFERR(waitid(P_ALL, 0, &sinfo, WEXITED))
        {
            switch(errno)
            {
                case EINTR:
                    break;
                case ECHILD:
                    perrf("child process missing\n");
                    goto error;
                default:
                    PRINTERR("waitid");
                    goto error;
            }
        }
        if(interrupted)
        {
            perrf("Received signal, aborting...\n");
            goto error;
        }
        if(alarmed)
        {
            alarmed = 0;
            IFERR(kill(pid, SIGKILL))
            {
                if(errno == ESRCH)
                    goto wait;
                PRINTERR("kill timeouted child process");
                goto error;
            }
            goto wait;
        }
        if(!child)
        {
            perrf("Not received SIGCHLD");
            goto error;
        }
        gettimeofday(&etime, NULL);
        timersub(&etime, &stime, &timespan);
        //FIXME: child may double fork a process
        if(sinfo.si_pid != pid)
        {
            perrf("Lost control of child process\n");
            pdebugf("PID should be: %d, but return %d\n", pid, sinfo.si_pid);
            goto error;
        }
        switch(sinfo.si_code)
        {
            case CLD_EXITED:
                break;
            case CLD_KILLED:
            case CLD_DUMPED:
                if(sinfo.si_status == SIGUSR1)
                {
                    perrf("setup child process failed\n");
                    goto error;
                }
                break;
            default:
                PRINTERR("unknown return type");
                goto error;
        }

        result.info = sinfo;
        result.time = timespan;

        write(exec_para.resultpipe[1], &result, sizeof(result));
        exit(0);

        error:
        _exit(1);
    }
    else if(pid == 0)
    {
        uid_t uid = exec_para.para.uid;
        gid_t gid = exec_para.para.gid;
        IFERR(setresgid(gid, gid, gid))
        {
            PRINTERR("setgid");
            raise(SIGUSR1);
        }
        IFERR(setresuid(uid, uid, uid))
        {
            PRINTERR("setuid");
            raise(SIGUSR1);
        }
        IFERR(reset_signals())
            raise(SIGUSR1);
        IFERR(setup_cpumask())
            raise(SIGUSR1);
        IFERR(setup_rlimit())
            raise(SIGUSR1);
        IFERR(setup_fd())
            raise(SIGUSR1);
        //To avoid seccomp block the pause systemcall
        //We move pause before it.
        if(!continued)
            pause();
        signal(SIGRTMIN, SIG_DFL);
        pdebugf("child continued from rt_signal\n");
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
        //TODO: Better environ setting
        execve(exec_para.para.argv[0], exec_para.para.argv, exec_para.para.environ);
        raise(SIGUSR1);
    }
    else
    {
        PRINTERR("fork");
        _exit(1);
    }
    _exit(1); // it shouldn't be here!
}
