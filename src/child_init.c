#include "cjail.h"
#include "child_init.h"
#include "setup.h"
#include "sigset.h"
#include "taskstats.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/filter.h>
#include <linux/taskstats.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <sys/signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

static volatile sig_atomic_t alarmed = 0, interrupted = 0;
void sigact(int sig);
inline static void child_exit();
static int ifchildfailed(pid_t pid);

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
    pid_t childpid;
    struct termios term;
    char *new_argc = INITNAME;
    int ttymode, childstatus = 0;

    if (getpid() != 1) {
        perrf("This process should be run as init process.\n");
        exit(EINVAL);
    }

    //it should register the signals, otherwise, they will be ignored because it's a init process
    IFERR (installsigs(init_sigrules, SA_NOCLDSTOP)) {
        PRINTERR("install init signals");
        exit(errno);
    }
    //block the signal SIGRTMIN
    int rtsig;
    sigset_t rtset;
    sigsetset(&rtset, 2, SIGCHLD, SIGREADY);
    sigprocmask(SIG_BLOCK, &rtset, NULL);

    close(exec_para.resultpipe[0]);
    IFERR (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)) {
        PRINTERR("set parent death signal");
        exit(errno);
    }

    //set new hostname in UTS namespace
    IFERR (sethostname(UTSNAME, sizeof(UTSNAME))) {
        PRINTERR("set hostname");
    }

    //replace cmdline
    if (prctl(PR_SET_MM, PR_SET_MM_ARG_START, new_argc, 0, 0) ||
        prctl(PR_SET_MM, PR_SET_MM_ARG_END, new_argc + strlen(new_argc) + 1, 0, 0) ||
        prctl(PR_SET_NAME, PROCNAME, 0, 0, 0)) {
            PRINTERR("set argc");
        }

    //mount filesystems
    IFERR (setup_fs())
        exit(errno);

    //save tty setting and restore it back if needed
    ttymode = (tcgetattr(STDIN_FILENO, &term) == 0);

    //precompile seccomp bpf to reduce the impact on timing
    struct sock_fprog bpf;
    IFERR (setup_seccomp_compile(&bpf, exec_para.para.argv))
        exit(errno);


    childpid = fork();
    if(childpid > 0)
    {
        struct cjail_result result;
        siginfo_t sinfo;
        struct timeval stime, etime, timespan;
        memset(&result, 0, sizeof(result));

        pdebugf("Writing tasks file, PID: %d\n", childpid);
        FILE *pidfile = fdopen(exec_para.cgtasksfd, "r+");
        if(!pidfile)
        {
            PRINTERR("fdopen cgroup task");
            exit(errno);
        }
        fprintf(pidfile, "%d", childpid);
        fflush(pidfile);
        fclose(pidfile);
        pdebugf("Writed into tasks file\n");

        //prevent race condition
        sigwait(&rtset, &rtsig);
        if(rtsig == SIGCHLD)
        {
            //child should not exit now
            perrf("Child process exit unexpectedly!\n");
        }
        if(rtsig == SIGRTMIN)
        {
            pdebugf("init continued from rt_signal\n");
            kill(childpid, SIGREADY);
        }
        sigprocmask(SIG_UNBLOCK, &rtset, NULL);

        gettimeofday(&stime, NULL);
        if(timerisset(&exec_para.para.lim_time))
        {
            pdebugf("Setting timer...\n");
            struct itimerval it;
            memset(&it, 0, sizeof(it));
            it.it_value = exec_para.para.lim_time;
            IFERR(setitimer(ITIMER_REAL, &it, NULL))
            {
                PRINTERR("setitimer");
                exit(errno);
            }
        }

        while(1)
        {
            IFERR(waitid(P_ALL, 0, &sinfo, WEXITED | WNOWAIT))
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
                alarmed = 0;
                continue;
            }
            if(sinfo.si_pid == childpid)
            {
                switch(ifchildfailed(sinfo.si_pid))
                {
                    case 1:
                        childstatus = -1;
                        break;
                    case 0:
                        childstatus = 1;
                        break;
                    case -1:
                        exit(errno);
                }
                result.info = sinfo;
            }
            waitpid(sinfo.si_pid, NULL, 0); // Cleanup the zombie process here
        }

        //deregister alarm
        if (timerisset(&exec_para.para.lim_time)) {
            struct itimerval itz;
            memset(&itz, 0, sizeof(itz));
            IFERR (setitimer(ITIMER_REAL, &itz, NULL))
                PRINTERR("stop itimer");
        }

        gettimeofday(&etime, NULL);
        timersub(&etime, &stime, &timespan);
        result.time = timespan;

        if(ttymode)
        {
            IFERR(tcsetattr(STDIN_FILENO, TCSANOW, &term))
                PRINTERR("restore terminal setting");
        }

        //check child setup process failed
        if (!childstatus) {
            perrf("Lost control of child process\n");
            exit(ECHILD);
        }
        error_t childerr = 0;
        if(childstatus == -1)
        {
            switch (result.info.si_code)
            {
                case CLD_EXITED:
                    childerr = result.info.si_status;
                    break;
                case CLD_KILLED:
                case CLD_DUMPED:
                    perrf("Child process killed by %s\n", strsignal(result.info.si_status));
                    switch (result.info.si_status)
                    {
                        case SIGHUP:
                        case SIGINT:
                        case SIGQUIT:
                        case SIGTERM:
                            childerr = EINTR;
                            break;
                        case SIGKILL:
                            //check if killed by oom killer
                            if(exec_para.para.cg_rss && exec_para.para.cg_rss < 256)
                                childerr = ENOMEM;
                            break;
                        case SIGSYS:
                            childerr = ENOSYS;
                            break;
                        default:
                            childerr = EFAULT;
                            break;
                    }
                    break;
            }
        }
        pdebugf("Sending result...\n");
        write(exec_para.resultpipe[1], &result, sizeof(result));

        exit(childerr);
    }
    else if(childpid == 0)
    {
        /*
         *  Child process part
         */
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
        IFERR(setup_fd())
            child_exit();
        if(isatty(STDIN_FILENO))
        {
            IFERR(tcsetpgrp(STDIN_FILENO, getpgrp()))
            {
                PRINTERR("get control terminal");
            }
        }
        IFERR(setup_cpumask())
            child_exit();
        IFERR(setup_rlimit())
            child_exit();
        //To avoid seccomp block the systemcall
        //We move before it.
        sigwait(&rtset, &rtsig);
        pdebugf("child continued from rt_signal\n");
        sigprocmask(SIG_UNBLOCK, &rtset, NULL);

        IFERR(setup_seccomp_load(&bpf))
            child_exit();
        execve(exec_para.para.argv[0], exec_para.para.argv, exec_para.para.environ);
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

static int ifchildfailed(pid_t pid)
{
    FILE *fp;
    char statpath[PATH_MAX];
    unsigned long procflag;
    snprintf(statpath, sizeof(char) * PATH_MAX, "/proc/%d/stat", pid);
    fp = fopen(statpath, "r");
    if (!fp) {
        PRINTERR("open proc stat file");
        return -1;
    }
    IFERR(fscanf(fp, "%*s %*s %*s %*s %*s %*s %*s %*s %lu", &procflag))
    {
        PRINTERR("read proc stat file");
        return -1;
    }
    fclose(fp);
    if(procflag & 0x00000040) /* PF_FORKNOEXEC: forked but didn't exec */
        return 1;
    return 0;
}

inline static void child_exit()
{
    exit(errno);
}
