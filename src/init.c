#include "cjail.h"
#include "init.h"
#include "fds.h"
#include "filesystem.h"
#include "process.h"
#include "scmp.h"
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
inline static void child_exit();

void sigact(int sig)
{
    switch (sig) {
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

static struct sig_rule init_sigrules[] = {
    { SIGHUP  , sigact , NULL, 0, {{0}}, 0 },
    { SIGINT  , sigact , NULL, 0, {{0}}, 0 },
    { SIGQUIT , sigact , NULL, 0, {{0}}, 0 },
    { SIGALRM , sigact , NULL, 0, {{0}}, 0 },
    { SIGTERM , sigact , NULL, 0, {{0}}, 0 },
    { SIGCHLD , sigact , NULL, SA_NOCLDSTOP, {{0}}, 0 },
    { SIGTTIN , SIG_IGN, NULL, 0, {{0}}, 0 },
    { SIGTTOU , SIG_IGN, NULL, 0, {{0}}, 0 },
    { SIGREADY, sigact , NULL, 0, {{0}}, 0 },
    { 0       , NULL   , NULL, 0, {{0}}, 0 },
};

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
    if (fscanf(fp, "%*s %*s %*s %*s %*s %*s %*s %*s %lu", &procflag) < 0) {
        PRINTERR("read proc stat file");
        return -1;
    }
    fclose(fp);
    if (procflag & 0x00000040) /* PF_FORKNOEXEC: forked but didn't exec */
        return 1;
    return 0;
}

static int setprocname(const char *argv, const char *procname)
{
    int ret = -1;
    if (argv) {
        ret = prctl(PR_SET_MM, PR_SET_MM_ARG_START, argv, 0, 0) ||
            prctl(PR_SET_MM, PR_SET_MM_ARG_END, argv + strlen(argv) + 1, 0, 0);
    }
    if (!ret && procname) {
        ret = prctl(PR_SET_NAME, procname, 0, 0, 0);
    }
    return ret;
}

static int write_tasks(int fd, pid_t pid)
{
    pdebugf("Writing tasks file, PID: %d\n", pid);
    int dfd = dup(fd);
    FILE *pidfile = fdopen(dfd, "r+");
    if (!pidfile) {
        close(dfd);
        return -1;
    }
    fprintf(pidfile, "%d", pid);
    fflush(pidfile);
    fclose(pidfile);
    pdebugf("Writed into tasks file\n");
    return 0;
}

static int set_timer(const struct timeval time) {
    struct itimerval it;
    memset(&it, 0, sizeof(it));
    it.it_value = time;
    if (setitimer(ITIMER_REAL, &it, NULL)) {
        return -1;
    }
    return 0;
}

static int unset_timer() {
    struct itimerval it;
    memset(&it, 0, sizeof(it));
    if (setitimer(ITIMER_REAL, &it, NULL)) {
        return -1;
    }
    return 0;
}

error_t get_child_error(const siginfo_t *info, int cg_rss) {
    switch (info->si_code) {
        case CLD_EXITED:
            return info->si_status;
        case CLD_KILLED:
        case CLD_DUMPED:
            switch (info->si_status) {
                case SIGHUP:
                case SIGINT:
                case SIGQUIT:
                case SIGTERM:
                    return EINTR;
                case SIGKILL:
                    //check if killed by oom killer
                    if (cg_rss && cg_rss < 256) {
                        return ENOMEM;
                    } else {
                        return EINTR;
                    }
                case SIGXFSZ:
                    return EFBIG;
                case SIGSYS:
                    return ENOSYS;
                default:
                    return EFAULT;
            }
            break;
        default:
            //should not occur
            return EFAULT;
    }
}

static int mount_fs(const struct cjail_para para)
{
    if (privatize_fs()) {
        goto error;
    }
    if (jail_mount("", para.chroot, "/proc", FS_PROC, "")) {
        PRINTERR("mount procfs");
        goto error;
    }
    if (jail_mount("", para.chroot, "/dev", FS_UDEV, "")) {
        PRINTERR("mount devfs");
        goto error;
    }
    if (jail_chroot(para.chroot, para.workingDir)) {
        goto error;
    }
    return 0;

    error:
    PRINTERR("setup_fs");
    return -1;
}

int child_init(void *arg)
{
    /*
     * The address passed with PR_SET_MM_ARG_START, PR_SET_MM_ARG_END should
     * belong to a process stack area.
     */
    char new_argv[4096] = INITNAME;
    int ttymode, childstatus = -1;
    pid_t childpid;
    struct termios term;
    struct exec_para ep = *(struct exec_para *) arg;

    if (getpid() != 1) {
        perrf("This process should be run as init process.\n");
        exit(EINVAL);
    }

    //it should register the signals, otherwise, they will be ignored because it's a init process
    if (installsigs(init_sigrules)) {
        PRINTERR("install init signals");
        exit(errno);
    }
    //block the signal SIGREADY(SIGRTMIN)
    int rtsig;
    sigset_t rtset;
    sigsetset(&rtset, 2, SIGCHLD, SIGREADY);
    sigprocmask(SIG_BLOCK, &rtset, NULL);

    close(ep.resultpipe[0]);
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)) {
        PRINTERR("set parent death signal");
        exit(errno);
    }
    //set new hostname in UTS namespace
    if (sethostname(UTSNAME, sizeof(UTSNAME))) {
        PRINTERR("set hostname");
    }
    //replace cmdline
    if (setprocname(new_argv, PROCNAME)) {
        PRINTERR("set process name");
    }

    //mount filesystems
    if (mount_fs(ep.para)) {
        exit(errno);
    }

    //save tty setting and restore it back if needed
    ttymode = (tcgetattr(STDIN_FILENO, &term) == 0);

    //precompile seccomp bpf to reduce the impact on timing
    if (compile_seccomp(ep.para, &ep.bpf))
        exit(errno);

    childpid = fork();
    if (childpid > 0) {
        struct cjail_result result;
        siginfo_t sinfo;
        struct timeval stime, etime, timespan;
        memset(&result, 0, sizeof(result));

        if (write_tasks(ep.cgtasksfd, childpid)) {
            PRINTERR("write tasks file");
            exit(errno);
        }

        sigwait(&rtset, &rtsig);
        switch (rtsig) {
            case SIGCHLD:
                perrf("Child process exit unexpectedly!\n");
                break;
            case SIGREADY:
                pdebugf("init continued from rt_signal\n");
                kill(childpid, SIGREADY);
                break;
            default:
                perrf("Unknown signal!\n");
                exit(EFAULT);
                break;
        }
        sigprocmask(SIG_UNBLOCK, &rtset, NULL);

        gettimeofday(&stime, NULL);
        if (timerisset(&ep.para.lim_time)) {
            pdebugf("Setting timer...\n");
            if (set_timer(ep.para.lim_time)) {
                PRINTERR("setitimer");
                exit(errno);
            }
        }

        while (1) {
            if (waitid(P_ALL, 0, &sinfo, WEXITED | WNOWAIT) < 0) {
                if(errno == ECHILD)
                    break;
            }
            if (interrupted) {
                perrf("Received signal, aborting...\n");
                exit(EINTR);
            }
            if (alarmed) {
                pdebugf("Execution timeout, killing process...\n");
                if (kill(-1, SIGKILL)) {
                    if (errno != ESRCH) {
                        PRINTERR("kill timeouted child process");
                        exit(errno);
                    }
                }
                result.timekill = 1;
                alarmed = 0;
                continue;
            }
            if (sinfo.si_pid == childpid) {
                if ((childstatus = ifchildfailed(sinfo.si_pid)) < 0) {
                    exit(errno);
                }
                result.info = sinfo;
            }
            // Cleanup the zombie process here
            waitpid(sinfo.si_pid, NULL, 0);
        }

        //deregister alarm
        if (timerisset(&ep.para.lim_time)) {
            if (unset_timer()) {
                PRINTERR("stop itimer");
            }
        }

        gettimeofday(&etime, NULL);
        timersub(&etime, &stime, &timespan);
        result.time = timespan;

        if (ttymode) {
            if (tcsetattr(STDIN_FILENO, TCSANOW, &term))
                PRINTERR("restore terminal setting");
        }

        //check if lost control of child process
        error_t childerr = 0;
        if (childstatus < 0) {
            perrf("Lost control of child process\n");
            exit(ECHILD);
        } else if (childstatus) {
            childerr = get_child_error(&result.info, ep.para.cg_rss);
        }
        getrusage(RUSAGE_CHILDREN, &result.rus);
        pdebugf("Sending result...\n");
        write(ep.resultpipe[1], &result, sizeof(result));

        exit(childerr);
    } else if(childpid == 0) {
        child_process(ep);
    } else {
        PRINTERR("fork");
        exit(errno);
    }
    // unreachable
}
