#include "cjail.h"
#include "utils.h"

#include <getopt.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void usage();

enum OPTVAL
{
    OPT_PFD = 256,
    OPT_NET,
    OPT_CGR
};

const char opts[] = "e:EC:D:u:g:i:o:r:I:O:R:S:v:c:z:p:s:t:G:m:";
const struct option longopts[] =
{
    {"environ",     required_argument,  NULL, 'e'},
    {"inherit-env", no_argument,        NULL, 'E'},
    {"chroot",      required_argument,  NULL, 'C'},
    {"workingDir",  required_argument,  NULL, 'D'},
    {"uid",         required_argument,  NULL, 'u'},
    {"gid",         required_argument,  NULL, 'g'},
    {"file-input",  required_argument,  NULL, 'i'},
    {"file-output", required_argument,  NULL, 'o'},
    {"file-err",    required_argument,  NULL, 'r'},
    {"fd-input",    required_argument,  NULL, 'I'},
    {"fd-output",   required_argument,  NULL, 'O'},
    {"fd-err",      required_argument,  NULL, 'R'},
    {"preserve-fd", no_argument,        NULL, OPT_PFD},
    {"share-net",   no_argument,        NULL, OPT_NET},
    {"cpuset",      required_argument,  NULL, 'S'},
    {"limit-vss",   required_argument,  NULL, 'v'},
    {"limit-core",  required_argument,  NULL, 'c'},
    {"limit-fsize", required_argument,  NULL, 'z'},
    {"limit-proc",  required_argument,  NULL, 'p'},
    {"limit-stack", required_argument,  NULL, 's'},
    {"limit-time",  required_argument,  NULL, 't'},
    {"cgroup-root", required_argument,  NULL, OPT_CGR},
    {"limit-rss",   required_argument,  NULL, 'm'},
    {NULL,          0,                  NULL,  0 }
};

void sighandler(int sig)
{
    return;
}

unsigned long toul(char* str, int abr)
{
    char *p;
    unsigned long ret;
    ret = strtoul(str, &p, 10);
    if(strlen(p))
    {
        perrf("Error: Invalid number: %s\n", str);
        if(abr)
            exit(1);
    }
    return ret;
}

long long int toll(char* str, int abr)
{
    char *p;
    long long int ret;
    ret = strtoll(str, &p, 10);
    if(strlen(p))
    {
        perrf("Error: Invalid number: %s\n", str);
        if(abr)
            exit(1);
    }
    return ret;
}

struct timeval totime(char* str, int abr)
{
    char *p;
    double sec;
    struct timeval ret;
    sec = strtod(str, &p);
    if(strlen(p))
    {
        perrf("Error: Invalid number: %s\n", str);
        if(abr)
            exit(1);
    }
    ret.tv_sec = floor(sec);
    ret.tv_usec = fmod(sec, 1.0) * 1000000;
    return ret;
}

int main(int argc, char *argv[], char *envp[])
{
    int o;
    cpu_set_t cpuset;
    struct cjail_para para;
    struct cjail_result res;
    cjail_para_init(&para);
    struct timeval time;
#ifndef NDEBUG
    char cpustr[1024];
#endif
    while((o = getopt_long(argc, argv, opts, longopts, NULL)) >= 0)
    {
        switch(o)
        {
            case 'e':
                //TODO: Convert environ utils
                break;
            case 'E':
                para.environ = envp;
                break;
            case 'C':
                para.chroot = optarg;
                break;
            case 'D':
                para.workingDir = optarg;
                break;
            case 'u':
                para.uid = toul(optarg, 1);
                if(para.uid == 65535)
                {
                    perrf("Error: Invalid UID: %s\n", optarg);
                    exit(1);
                }
                break;
            case 'g':
                para.gid = toul(optarg, 1);
                if(para.gid == 65535)
                {
                    perrf("Invalid GID: %s", optarg);
                    exit(1);
                }
                break;
            case 'i':
                para.redir_input = optarg;
                break;
            case 'o':
                para.redir_output = optarg;
                break;
            case 'r':
                para.redir_err = optarg;
                break;
            case 'I':
                para.fd_input = toul(optarg, 1);
                break;
            case 'O':
                para.fd_output = toul(optarg, 1);
                break;
            case 'R':
                para.fd_err = toul(optarg, 1);
                break;
            case OPT_PFD:
                para.preservefd = 1;
                break;
            case OPT_NET:
                para.sharenet = 1;
                break;
            case 'S':
                //TODO: Write CPU mask parser utils
                if(cpuset_parse(optarg, &cpuset) < 0)
                {
                    perrf("Invalid cpuset string: %s\n", optarg);
                    exit(1);
                }
                para.cpuset = &cpuset;
#ifndef NDEBUG
                cpuset_tostr(&cpuset, cpustr, 1024);
                pdebugf("cpuset: %s\n", cpustr);
#endif
                break;
            case 'v':
                para.rlim_as = toll(optarg, 1);
                break;
            case 'c':
                para.rlim_core = toll(optarg, 1);
                break;
            case 'z':
                para.rlim_fsize = toll(optarg, 1);
                break;
            case 'p':
                para.rlim_proc = toll(optarg, 1);
                break;
            case 's':
                para.rlim_stack = toll(optarg, 1);
                break;
            case 't':
                time = totime(optarg, 1);
                para.lim_time = &time;
                break;
            case OPT_CGR:
                para.cgroup_root = optarg;
                break;
            case 'm':
                para.cg_rss = toll(optarg, 1);
                break;
            default:
                usage();
                break;
        }
    }
    if(optind >= argc)
    {
        perrf("Error: command not specified\n");
        exit(1);
    }
    para.argv = argv + optind;
    if(!para.uid)
        perrf("Warning: Running with UID 0\n");
    if(!para.gid)
        perrf("Warning: Running with GID 0\n");
    signal(SIGHUP, sighandler);
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    int ret = cjail_exec(&para, &res);
    if(ret)
    {
        perrf("Error: cjail failure.\n");
        exit(ret);
    }
    printf("Time: %ld.%06ld sec\n", res.time.tv_sec, res.time.tv_usec);
    printf("---\n");
    printf("PID: %u\n", res.stats.ac_pid);
    printf("UID: %u\n", res.stats.ac_uid);
    printf("GID: %u\n", res.stats.ac_gid);
    printf("command: %s\n", res.stats.ac_comm);
    printf("exit status: %u\n", res.stats.ac_exitcode);
    printf("NICE: %u\n", res.stats.ac_nice);
    printf("time:\n");
    printf("    start: %u\n", res.stats.ac_btime);
    printf("        elapsed: %llu\n", res.stats.ac_etime);
    printf("        user: %llu\n", res.stats.ac_utime);
    printf("        system: %llu\n", res.stats.ac_stime);
    printf("CPU:\n");
    printf("    count: %llu\n", res.stats.cpu_count);
    printf("    realtime: %llu\n", res.stats.cpu_run_real_total);
    printf("    virttime: %llu\n", res.stats.cpu_run_virtual_total);
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
    return 0;
}

void usage()
{
    //TODO: Write usage
}
