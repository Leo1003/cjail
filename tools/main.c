#include <cjail.h>

#include <argz.h>
#include <envz.h>
#include <getopt.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define perrf(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#ifdef NDEBUG
#define devf(fmt, ...)
#else
#define devf(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#endif

void usage(char *name);
void print_result(const struct cjail_result *res);

enum OPTVAL {
    OPT_PFD = 256,
    OPT_NET,
    OPT_CGR
};

const char opts[] = "e:EC:D:u:g:i:o:r:I:O:R:S:f:v:c:z:p:s:t:G:m:h";
const struct option longopts[] = {
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
    {"limit-nofile",required_argument,  NULL, 'f'},
    {"limit-fsize", required_argument,  NULL, 'z'},
    {"limit-proc",  required_argument,  NULL, 'p'},
    {"limit-stack", required_argument,  NULL, 's'},
    {"limit-time",  required_argument,  NULL, 't'},
    {"cgroup-root", required_argument,  NULL, OPT_CGR},
    {"limit-rss",   required_argument,  NULL, 'm'},
    {"help",        no_argument      ,  NULL, 'h'},
    {NULL,          0,                  NULL,  0 }
};

unsigned long toul(char* str, int abr)
{
    char *p;
    unsigned long ret;
    ret = strtoul(str, &p, 10);
    if (strlen(p)) {
        perrf("Error: Invalid number: %s\n", str);
        if (abr)
            exit(1);
    }
    return ret;
}

long long int toll(char* str, int abr)
{
    char *p;
    long long int ret;
    ret = strtoll(str, &p, 10);
    if (strlen(p)) {
        perrf("Error: Invalid number: %s\n", str);
        if (abr)
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
    if (strlen(p)) {
        perrf("Error: Invalid number: %s\n", str);
        if (abr)
            exit(1);
    }
    ret.tv_sec = floor(sec);
    ret.tv_usec = fmod(sec, 1.0) * 1000000;
    return ret;
}

int parse_env(const char *str, char **dest[], char *envp[])
{
    char *argz = NULL, *envz = NULL, *i = NULL;
    size_t argz_len = 0, envz_len = 0;
    if (argz_create_sep(str, ';', &argz, &argz_len)) {
        perror("create list");
        goto error;
    }

    if (envp)
        if (argz_create(envp, &envz, &envz_len)) {
            perror("create envz");
            goto error;
        }
    envz_strip(&envz, &envz_len);

    while ((i = argz_next(argz, argz_len, i))) {
        if (i[0] == '!') {
            devf("removing: %s\n", i + 1);
            envz_remove(&envz, &envz_len, i + 1);
            continue;
        }
        if (!strchr(i, '=')) {
            if (envz_add(&envz, &envz_len, i, getenv(i))) {
                perror("add environ");
                goto error;
            }
        } else {
            if (argz_add(&envz, &envz_len, i)) {
                perror("inherit environ");
                goto error;
            }
        }
    }
    free(argz);
    argz = NULL;
    argz_len = 0;

    envz_strip(&envz, &envz_len);

    *dest = malloc((argz_count(envz, envz_len) + 1) * sizeof(char *));
    argz_extract(envz, envz_len, *dest);
    return 0;

    error:
    if (argz)
        free(argz);
    return -1;
}

int main(int argc, char *argv[], char *envp[])
{
    int o;
    cpu_set_t cpuset;
    struct cjail_para para;
    struct cjail_result res;
    struct timeval time;
    int inherenv = 0;
    char *envstr = NULL, **para_env = NULL;
#ifndef NDEBUG
    char cpustr[1024];
#endif
    cjail_para_init(&para);
    while ((o = getopt_long(argc, argv, opts, longopts, NULL)) >= 0) {
        switch(o) {
            case 'e':
                envstr = optarg;
                break;
            case 'E':
                inherenv = 1;
                break;
            case 'C':
                para.chroot = optarg;
                break;
            case 'D':
                para.workingDir = optarg;
                break;
            case 'u':
                para.uid = toul(optarg, 1);
                if (para.uid >= 65535) {
                    perrf("Error: Invalid UID: %s\n", optarg);
                    exit(1);
                }
                break;
            case 'g':
                para.gid = toul(optarg, 1);
                if (para.gid >= 65535) {
                    perrf("Error: Invalid GID: %s", optarg);
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
                para.redir_error = optarg;
                break;
            case 'I':
                para.fd_input = toul(optarg, 1);
                break;
            case 'O':
                para.fd_output = toul(optarg, 1);
                break;
            case 'R':
                para.fd_error = toul(optarg, 1);
                break;
            case OPT_PFD:
                para.preservefd = 1;
                break;
            case OPT_NET:
                para.sharenet = 1;
                break;
            case 'S':
                if (cpuset_parse(optarg, &cpuset) < 0) {
                    perrf("Error: Invalid cpuset string: %s\n", optarg);
                    exit(1);
                }
                para.cpuset = &cpuset;
#ifndef NDEBUG
                cpuset_tostr(&cpuset, cpustr, 1024);
                devf("cpuset: %s\n", cpustr);
#endif
                break;
            case 'v':
                para.rlim_as = toll(optarg, 1);
                break;
            case 'c':
                para.rlim_core = toll(optarg, 1);
                break;
            case 'f':
                para.rlim_nofile = toll(optarg, 1);
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
                para.lim_time = time;
                break;
            case OPT_CGR:
                para.cgroup_root = optarg;
                break;
            case 'm':
                para.cg_rss = toll(optarg, 1);
                break;
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            default:
                usage(argv[0]);
                exit(1);
        }
    }
    if (optind >= argc) {
        perrf("Error: command not specified\n");
        exit(1);
    }
    para.argv = argv + optind;
    devf("arguments parsing completed\n");
    if (!para.uid)
        perrf("WARN : Running with UID 0!!!\n");
    if (!para.gid)
        perrf("WARN : Running with GID 0!!!\n");

    if (envstr) {
        if (parse_env(envstr, &para_env, (inherenv ? envp : NULL ))) {
            perrf("ERROR: Parsing environment variables\n");
            exit(1);
        }
        para.environ = para_env;
    }
    if (inherenv && !envstr)
        para.environ = envp;

    int ret = cjail_exec(&para, &res);

    if (para_env) {
        free(para_env);
        para_env = NULL;
    }
    if (ret) {
        perrf("cjail failure. %s\n", strerror(errno));
        exit(1);
    }
    print_result(&res);
    return 0;
}

void print_result(const struct cjail_result *res)
{
    printf("Time: %ld.%06ld sec\n", res->time.tv_sec, res->time.tv_usec);
    printf("Timeout: %d\n", res->timekill);
    printf("Oomkill: %d\n", res->oomkill);
    printf("----------TASKSTAT----------\n");
    printf("PID: %u\n", res->stats.ac_pid);
    printf("UID: %u\n", res->stats.ac_uid);
    printf("GID: %u\n", res->stats.ac_gid);
    printf("command: %s\n", res->stats.ac_comm);
    printf("exit status: %u\n", res->stats.ac_exitcode);
    printf("NICE: %u\n", res->stats.ac_nice);
    printf("time:\n");
    printf("    start: %u\n", res->stats.ac_btime);
    printf("        elapsed: %llu\n", res->stats.ac_etime);
    printf("        user: %llu\n", res->stats.ac_utime);
    printf("        system: %llu\n", res->stats.ac_stime);
    printf("CPU:\n");
    printf("    count: %llu\n", res->stats.cpu_count);
    printf("    realtime: %llu\n", res->stats.cpu_run_real_total);
    printf("    virttime: %llu\n", res->stats.cpu_run_virtual_total);
    printf("memory:\n");
    printf("    bytetime:\n");
    printf("        rss: %llu\n", res->stats.coremem);
    printf("        vsz: %llu\n", res->stats.virtmem);
    printf("    peak:\n");
    printf("        rss: %llu\n", res->stats.hiwater_rss);
    printf("        vsz: %llu\n", res->stats.hiwater_vm);
    printf("io:\n");
    printf("    bytes:\n");
    printf("        read: %llu\n", res->stats.read_char);
    printf("        write: %llu\n", res->stats.write_char);
    printf("    syscalls:\n");
    printf("        read: %llu\n", res->stats.read_syscalls);
    printf("        write: %llu\n", res->stats.write_syscalls);
    printf("-----------RUSAGE-----------\n");
    printf("user time: %ld.%06ld\n", res->rus.ru_utime.tv_sec, res->rus.ru_utime.tv_usec);
    printf("system time: %ld.%06ld\n", res->rus.ru_stime.tv_sec, res->rus.ru_stime.tv_usec);
    printf("max_rss: %ld\n", res->rus.ru_maxrss);
    printf("inblock: %ld\n", res->rus.ru_inblock);
    printf("outblock: %ld\n", res->rus.ru_oublock);
    printf("major fault: %ld\n", res->rus.ru_majflt);
    printf("minor fault: %ld\n", res->rus.ru_minflt);
    printf("content switch: %ld\n", res->rus.ru_nvcsw);
    printf("icontent switch: %ld\n", res->rus.ru_nivcsw);
    printf("----------------------------\n");
    switch (res->info.si_code) {
        case CLD_EXITED:
            printf("Exitcode: %d\n", res->info.si_status);
            break;
        case CLD_KILLED:
        case CLD_DUMPED:
            printf("Signaled: %d %s\n", res->info.si_status, strsignal(res->info.si_status));
            break;
    }
}

void usage(char *name)
{
    printf("Usage: %s [OPTIONS...] [--] PROGRAM... [ARG...]\n", name);
    printf("       %s --help\n", name);
    printf("\n");
    printf("  -C, --chroot=PATH\t\tset the root path of the jail\n");
    printf("  -D, --workingDir=PATH\t\tchange the working directory of the program\n");
    printf("  -u, --uid=UID\t\t\tset the user of the program\n");
    printf("  -g, --gid=GID\t\t\tset the group of the program\n");
    printf("  -S, --cpuset=SET\t\tset cpu affinity of the program with a list separated by ','\n");
    printf("      \t\t\t\teach entry should be <CPU> or <CPU>-<CPU>\n");
    printf("      --share-net\t\tnot to unshare the net namespace while creating the jail\n");
    printf("      --cgroup-root=PATH\tchange cgroup filesystem root path (default: /sys/fs/cgroup)\n");
    printf("  -h, --help\t\t\tshow this help\n");
    printf("\n");
    printf(" Resource Limit Options:\n");
    printf("  -v, --limit-vss=SIZE\t\tlimit the memory space size can be allocated per process (KB)\n");
    printf("  -c, --limit-core=SIZE\t\tlimit the core file size can be generated (KB)\n");
    printf("  -z, --limit-fsize=SIZE\tlimit the max file size can be created (KB)\n");
    printf("  -p, --limit-proc=NUM\t\tlimit the process number in the jail\n");
    printf("  -s, --limit-stack=SIZE\tlimit the stack size of one process (KB)\n");
    printf("  -t, --limit-time=SEC\t\tlimit the total running time of the jail (sec)\n");
    printf("  -m, --limit-rss=SIZE\t\tlimit the memory size can be used of the jail (KB)\n");
    printf("\n");
    printf(" I/O Options:\n");
    printf("  -i, --file-input=FILE\t\tredirect stdin of the program to the file\n");
    printf("  -o, --file-output=FILE\tredirect stdout of the program to the file\n");
    printf("  -r, --file-err=FILE\t\tredirect stderr of the program to the file\n");
    printf("  -I, --fd-input=FD\t\tredirect stdin of the program to the file descriptor\n");
    printf("  -O, --fd-output=FD\t\tredirect stdout of the program to the file descriptor\n");
    printf("  -R, --fd-err=FD\t\tredirect stderr of the program to the file descriptor\n");
    printf("      --preserve-fd\t\tdo not close file descriptors greater than 2\n");
    printf("\n");
    printf(" Environment Variables Options:\n");
    printf("  -e, --environ=ENV\t\tset the environment variables of the program with a list separated by ';'\n");
    printf("      \t\t\t\teach entry should be <name>, !<name>, <name>=<value>\n");
    printf("      \t\t\t\t<name>        : try to inherit the environment variable from the parent process\n");
    printf("      \t\t\t\t!<name>       : unset the environment variable inheriting from the parent process\n");
    printf("      \t\t\t\t<name>=<value>: set the environment variable using giving name and value\n");
    printf("  -E, --inherit-env\t\tinherit all environment variables from the parent process\n");
}
