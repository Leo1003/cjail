/**
 * @internal
 * @file init.c
 * @brief init process(PID 1) in the pid namespace daemon source
 */
#include "init.h"
#include "cjail.h"
#include "config.h"
#include "fds.h"
#include "filesystem.h"
#include "logger.h"
#include "process.h"
#include "sigset.h"
#include "simple_seccomp.h"
#include "taskstats.h"
#include "trace.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <seccomp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <sys/signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static volatile sig_atomic_t alarmed = 0, interrupted = 0;

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
            if (kill(-1, SIGKILL) && errno != ESRCH) {
                alarmed = -errno;
                return;
            }
            alarmed = 1;
            break;
        case SIGCHLD:
            break;
    }
}

// clang-format off
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

const struct jail_mount_ctx procctx = {
    .type = "proc",
    .source = NULL,
    .target = "/proc",
    .fstype = NULL,
    .flags = JAIL_MNT_RW,
    .data = NULL
};
const struct jail_mount_ctx devctx = {
    .type = "udevfs",
    .source = NULL,
    .target = "/dev",
    .fstype = NULL,
    .flags = JAIL_MNT_RW,
    .data = NULL
};
// clang-format on

static int ifchildfailed(pid_t pid)
{
    FILE *fp;
    char statpath[PATH_MAX];
    unsigned long procflag;
    snprintf(statpath, sizeof(char) * PATH_MAX, "/proc/%d/stat", pid);
    fp = fopen(statpath, "r");
    if (!fp) {
        PFTL("open proc stat file");
        return -1;
    }
    if (fscanf(fp, "%*s %*s %*s %*s %*s %*s %*s %*s %lu", &procflag) < 0) {
        PFTL("read proc stat file");
        fclose(fp);
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
    devf("Writing tasks file, PID: %d\n", pid);
    int dfd = dup(fd);
    FILE *pidfile = fdopen(dfd, "r+");
    if (!pidfile) {
        close(dfd);
        return -1;
    }
    fprintf(pidfile, "%d", pid);
    fflush(pidfile);
    fclose(pidfile);
    devf("Writed into tasks file\n");
    return 0;
}

static int set_timer(const struct timeval time)
{
    struct itimerval it;
    memset(&it, 0, sizeof(it));
    it.it_value = time;
    if (setitimer(ITIMER_REAL, &it, NULL)) {
        return -1;
    }
    return 0;
}

static int unset_timer()
{
    struct itimerval it;
    memset(&it, 0, sizeof(it));
    if (setitimer(ITIMER_REAL, &it, NULL)) {
        return -1;
    }
    return 0;
}

error_t get_child_error(const siginfo_t *info, int cg_rss)
{
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
        return -1;
    }

    if (jail_mount(para.chroot, &procctx)) {
        PFTL("mount procfs");
        return -1;
    }
    if (jail_mount(para.chroot, &devctx)) {
        PFTL("mount devfs");
        return -1;
    }

    if (para.mount_cfg) {
        struct jail_mount_item *cur = para.mount_cfg->head;
        while (cur) {
            if (jail_mount(para.chroot, &(cur->ctx))) {
                fatalf("Failed to mount <%s> -> %s: %s\n", cur->ctx.fstype, cur->ctx.target, strerror(errno));
                return -1;
            }
            cur = cur->next;
        }
    }

    if (jail_chroot(para.chroot, para.workingDir)) {
        return -1;
    }
    return 0;
}

static int allow_execve(struct seccomp_config *cfg, void *argv)
{
    struct seccomp_rule exec_rule;
    struct args_rule arg1 = {
        .cmp = CMP_EQ,
        .value = (u_int64_t)argv
    };
    memset(&exec_rule, 0, sizeof(exec_rule));
    exec_rule.type = RULE_ALLOW;
    exec_rule.syscall = __NR_execve;
    exec_rule.args[1] = arg1;
    return scconfig_add(cfg, &exec_rule, 1);
}

int child_init(void *arg)
{
    /*
     * The address passed with PR_SET_MM_ARG_START, PR_SET_MM_ARG_END should
     * belong to a process stack area.
     */
    char new_argv[4096] = CFG_INITNAME;
    int ttymode, childstatus = -1;
    pid_t childpid;
    struct termios term;
    struct exec_para ep = *(struct exec_para *)arg;

    if (getpid() != 1) {
        fatalf("This process should be run as init process.\n");
        exit(EINVAL);
    }

    //it should register the signals, otherwise, they will be ignored because it's a init process
    if (installsigs(init_sigrules)) {
        PFTL("install init signals");
        exit(errno);
    }
    //block the signal SIGREADY(SIGRTMIN)
    int rtsig;
    sigset_t rtset;
    sigsetset(&rtset, 2, SIGCHLD, SIGREADY);
    sigprocmask(SIG_BLOCK, &rtset, NULL);

    close(ep.resultpipe[0]);
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)) {
        PFTL("set parent death signal");
        exit(errno);
    }
    //set new hostname in UTS namespace
    if (sethostname(CFG_UTSNAME, sizeof(CFG_UTSNAME))) {
        PWRN("set hostname");
    }
    //replace cmdline
    if (setprocname(new_argv, CFG_PROCNAME)) {
        PWRN("set process name");
    }

    //mount filesystems
    if (mount_fs(ep.para)) {
        exit(errno);
    }

    //save tty setting and restore it back if needed
    ttymode = (tcgetattr(STDIN_FILENO, &term) == 0);

    //detect if we need to trace the child process
    int traceflag = 0;
    //precompile seccomp bpf to reduce the impact on timing
    if (ep.para.seccomp_cfg) {
        if (ep.para.seccomp_cfg->deny_action == DENY_TRACE || ep.para.seccomp_cfg->deny_action == DENY_TRACE_KILL) {
            traceflag = 1;
        }
        if (allow_execve(ep.para.seccomp_cfg, ep.para.argv)) {
            exit(errno);
        }
        if (scconfig_compile(ep.para.seccomp_cfg, &ep.bpf)) {
            exit(errno);
        }
    }

    childpid = fork();
    if (childpid > 0) {
        struct cjail_result result;
        siginfo_t sinfo;
        struct timeval stime, etime, timespan;
        struct trace_ops ops;
        memset(&result, 0, sizeof(result));

        if (write_tasks(ep.cgtasksfd, childpid)) {
            PFTL("write tasks file");
            exit(errno);
        }

        if (traceflag) {
            trace_seize(childpid);
            ops.seccomp_event = scconfig_get_callback(ep.para.seccomp_cfg);
        }

        sigwait(&rtset, &rtsig);
        switch (rtsig) {
            case SIGCHLD:
                errorf("Child process exit unexpectedly!\n");
                break;
            case SIGREADY:
                devf("init continued from rt_signal\n");
                kill(childpid, SIGREADY);
                break;
            default:
                fatalf("Unknown signal!\n");
                exit(EINTR);
                break;
        }
        sigprocmask(SIG_UNBLOCK, &rtset, NULL);

        gettimeofday(&stime, NULL);
        if (timerisset(&ep.para.lim_time)) {
            devf("Setting timer...\n");
            if (set_timer(ep.para.lim_time)) {
                PFTL("setitimer");
                exit(errno);
            }
        }

        while (1) {
            // Check signals
            if (interrupted) {
                errorf("Received signal, aborting...\n");
                exit(EINTR);
            }
            if (alarmed) {
                if (alarmed < 0) {
                    PFTL("kill timeouted child process");
                    exit(-alarmed);
                }
                debugf("Execution timeout, killed process.\n");
                result.timekill = 1;
                alarmed = 0;
            }
            // Wait child process
            if (waitid(P_ALL, 0, &sinfo, WEXITED | (traceflag ? WSTOPPED : 0) | WNOWAIT) < 0) {
                if (errno == ECHILD)
                    break;
                if (errno == EINTR) {
                    continue;
                }
            }
            // Handle wait
            if (sinfo.si_code == CLD_EXITED || sinfo.si_code == CLD_KILLED || sinfo.si_code == CLD_DUMPED) {
                if (sinfo.si_pid == childpid) {
                    if ((childstatus = ifchildfailed(sinfo.si_pid)) < 0) {
                        exit(errno);
                    }
                    result.info = sinfo;
                }
                // Cleanup the zombie process here
                waitpid(sinfo.si_pid, NULL, 0);
            } else {
                if (trace_handle(&sinfo, &ops)) {
                    if (errno == ESRCH) {
                        continue;
                    }
                    exit(errno);
                }
            }
        }

        //deregister alarm
        if (timerisset(&ep.para.lim_time)) {
            if (unset_timer()) {
                PWRN("stop itimer");
            }
        }

        gettimeofday(&etime, NULL);
        timersub(&etime, &stime, &timespan);
        result.time = timespan;

        if (ttymode) {
            if (tcsetattr(STDIN_FILENO, TCSANOW, &term))
                PWRN("restore terminal setting");
        }

        //check if lost control of child process
        error_t childerr = 0;
        if (childstatus < 0) {
            fatalf("Lost control of child process\n");
            exit(ECHILD);
        } else if (childstatus) {
            childerr = get_child_error(&result.info, ep.para.cg_rss);
        }
        getrusage(RUSAGE_CHILDREN, &result.rus);
        devf("Sending result...\n");
        write(ep.resultpipe[1], &result, sizeof(result));

        exit(childerr);
    } else if (childpid == 0) {
        child_process(ep);
    } else {
        PFTL("fork");
        exit(errno);
    }
    // Should be unreachable
}
