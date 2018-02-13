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
    sa.sa_sigaction = sigact;
    sa.sa_flags = SA_NOCLDSTOP | SA_SIGINFO | SA_RESTART;
    sigaction(SIGHUP , &sa, NULL);
    sigaction(SIGINT , &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGALRM, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGCHLD, &sa, NULL);
}

int child_init(void *arg)
{
    struct ts_socket tssock;
    pid_t pid;

    //we should register the signals, otherwise they will be ignored because we are init process
    init_signalset();

    close(exec_para->resultpipe[0]);
    IFERR(setup_fs())
        abort();
    IFERR(setup_taskstats(&tssock))
        abort();

    pid = fork();
    if(pid > 0)
    {
        struct cjail_result result;
        siginfo_t sinfo;
        struct taskstats ts;
        struct timeval stime, etime, timespan;
        gettimeofday(&stime, NULL);
        if(exec_para->para.lim_time)
        {
            struct itimerval it;
            it.it_value = *exec_para->para.lim_time;
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
        int ts_ret;
        while((ts_ret = taskstats_getstats(&tssock, &ts)) == 0)
        {
            if(ts_ret == -1)
                goto error;
            pdebugf("getstats ok!\n");
        }
        result.info = sinfo;
        result.time = timespan;
        result.stats = ts;
        write(exec_para->resultpipe[1], &result, sizeof(result));
        taskstats_destory(&tssock);
        exit(0);

        error:
        taskstats_destory(&tssock);
        abort();
    }
    else if(pid == 0)
    {
        uid_t uid = exec_para->para.uid;
        gid_t gid = exec_para->para.gid;
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
        IFERR(setup_signals())
            raise(SIGUSR1);
        IFERR(setup_cpumask())
            raise(SIGUSR1);
        IFERR(setup_rlimit())
            raise(SIGUSR1);
        IFERR(setup_fd())
            raise(SIGUSR1);
        IFERR(setup_seccomp(exec_para->para.argv))
            raise(SIGUSR1);
        execve(exec_para->para.argv[0], exec_para->para.argv, exec_para->para.environ);
        raise(SIGUSR1);
    }
    else
    {
        PRINTERR("fork");
        abort();
    }
    abort(); // it shouldn't be here!
}
