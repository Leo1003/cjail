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
#include <sys/types.h>
#include <sys/wait.h>

static int alarmed = 0;
//TODO: Better signal handler
//      (we should register the signals, otherwise they will be ignored because we are init process)
//TODO: Get actual time
//TODO: Redesign return struct

void alarm_sigact(int sig, siginfo_t *info, void *data)
{
    alarmed = 1;
}

int child_init(void *arg)
{
    struct ts_socket tssock;
    pid_t pid;

    IFERR(setup_fs())
        abort();
    IFERR(setup_taskstats(&tssock))
        abort();

    pid = fork();
    if(pid > 0)
    {
        siginfo_t sinfo;
        struct taskstats ts;
        if(exec_para->lim_time)
        {
            struct sigaction sa;
            sigemptyset(&sa.sa_mask);
            sigaddset(&sa.sa_mask, SIGALRM);
            sa.sa_sigaction = alarm_sigact;
            sigaction(SIGALRM, &sa, NULL);
            struct itimerval it;
            it.it_value = *exec_para->lim_time;
            IFERR(setitimer(ITIMER_REAL, &it, NULL))
            {
                PRINTERR("setitimer");
                goto error;
            }
        }
        IFERR(waitid(P_ALL, 0, &sinfo, WEXITED))
        {
            switch(errno)
            {
                case EINTR:
                    perrf("Received signal, aborting.\n");
                    goto error;
                case ECHILD:
                    perrf("child process missing\n");
                    goto error;
                default:
                    PRINTERR("waitid");
                    goto error;
            }
        }
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
        exit(0);

        error:
        taskstats_destory(&tssock);
        abort();
    }
    else if(pid == 0)
    {
        uid_t uid = exec_para->uid;
        gid_t gid = exec_para->gid;
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
        IFERR(setup_seccomp(exec_para->argv))
            raise(SIGUSR1);
        execve(exec_para->argv[0], exec_para->argv, exec_para->environ);
        raise(SIGUSR1);
    }
    else
    {
        PRINTERR("fork");
        abort();
    }
    abort(); // it shouldn't be here!
}
