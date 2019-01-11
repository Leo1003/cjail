#define _GNU_SOURCE
#include <cjail/cjail.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <seccomp.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;
static volatile sig_atomic_t interrupted = 0;

void sigint(int sig)
{
    interrupted++;
}

extern int seccomplist[];

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Please specify command!\n");
        exit(1);
    }
    cpu_set_t cpuset;
    struct cjail_ctx para;
    struct cjail_result res;
    bzero(&para, sizeof(para));
    para.argv = argv + 1;
    struct timeval limt = { .tv_sec = 0, .tv_usec = 0 };

    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    //para.chroot = "/mnt";
    para.cpuset = &cpuset;
    para.environ = NULL;
    //para.rlim_as = 65536;
    para.rlim_nofile = 5;
    para.rlim_fsize = 1024;
    para.rlim_proc = 10;
    para.rlim_core = 0;
    para.lim_time = limt;
    para.cg_rss = 2048;
    para.uid = 10000;
    para.gid = 10000;
    para.workingDir = "/tmp";
    para.preservefd = 1;
    //para.seccomplist = seccomplist;

    signal(SIGHUP, sigint);
    signal(SIGINT, sigint);
    signal(SIGTERM, sigint);

    int ret;
    if((ret = cjail_exec(&para, &res)) == 0)
    {
        printf("Time: %ld.%06ld sec\n", res.time.tv_sec, res.time.tv_usec);
        printf("Timeout: %d\n", res.timekill);
        printf("Oomkill: %d\n", res.oomkill);
        printf("---\n");
        printf("PID: %u\n", res.stats.ac_pid);
        printf("command: %s\n", res.stats.ac_comm);
        printf("status: %u\n", res.stats.ac_exitcode);
        printf("time:\n");
        printf("    start: %u\n", res.stats.ac_btime);
        printf("        elapsed: %llu\n", res.stats.ac_etime);
        printf("        user: %llu\n", res.stats.ac_utime);
        printf("        system: %llu\n", res.stats.ac_stime);
        printf("memory:\n");
        printf("    bytetime:\n");
        printf("        rss: %llu\n", res.stats.coremem);
        printf("        vsz: %llu\n", res.stats.virtmem);
        printf("    peak:\n");
        printf("        rss: %llu\n", res.stats.hiwater_rss);
        printf("        vsz: %llu\n", res.stats.hiwater_vm);
        printf("io:\n");
        printf("    bytes:\n");
        printf("        read: %llu\n", res.stats.read_char);
        printf("        write: %llu\n", res.stats.write_char);
        printf("    syscalls:\n");
        printf("        read: %llu\n", res.stats.read_syscalls);
        printf("        write: %llu\n", res.stats.write_syscalls);
        switch(res.info.si_code)
        {
            case CLD_EXITED:
                printf("Exitcode: %d\n", res.info.si_status);
                break;
            case CLD_KILLED:
            case CLD_DUMPED:
                printf("Signaled: %d %s\n", res.info.si_status, strsignal(res.info.si_status));
                break;
        }
    }
    else
    {
        printf("Failed: %s\n", strerror(-ret));
    }
    //pause();
    printf("Interrupted: %d\n", interrupted);
    return 0;
}
