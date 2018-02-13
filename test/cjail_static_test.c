#include "cjail.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char** environ;
int main()
{
    char *cargv[] = {"/bin/bash", NULL};
    cpu_set_t cpuset;
    struct cjail_para para;
    struct cjail_result res;
    bzero(&para, sizeof(para));
    para.argv = cargv;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    para.cpuset = &cpuset;
    para.environ = environ;
    para.rlim_proc = 10;
    para.rlim_core = 0;
    para.uid = 10000;
    para.gid = 10000;
    para.workingDir = "/";
    int ret;
    if((ret = cjail_exec(&para, &res)) == 0)
    {
        printf("Time: %ld.%06ld sec\n", res.time.tv_sec, res.time.tv_usec);
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
        printf("Exitcode: %d\n", res.info.si_status);
    }
    else
    {
        printf("Failed: %s\n", strerror(-ret));
    }
    return 0;
}
