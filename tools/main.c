/**
 * @dir tools/
 * @brief command line tools source directory
 */
/**
 * @internal
 * @file main.c
 * @brief cjail command line interface(cli) source
 */
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

#define STR_BUF 256

void usage(char *name);
void print_result(const struct cjail_result *res);

enum OPTVAL {
    OPT_PFD = 256,
    OPT_NET,
    OPT_CGR,
    OPT_SCC,
    OPT_ALR,
};

const char opts[] = "e:Ec:d:u:g:i:o:r:I:O:R:s:V:C:F:Z:P:S:T:m:qvh";
const struct option longopts[] = {
    {"environ",     required_argument,  NULL, 'e'},
    {"inherit-env", no_argument,        NULL, 'E'},
    {"chroot",      required_argument,  NULL, 'c'},
    {"workingDir",  required_argument,  NULL, 'd'},
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
    {"cpuset",      required_argument,  NULL, 's'},
    {"limit-vss",   required_argument,  NULL, 'V'},
    {"limit-core",  required_argument,  NULL, 'C'},
    {"limit-nofile",required_argument,  NULL, 'F'},
    {"limit-fsize", required_argument,  NULL, 'Z'},
    {"limit-proc",  required_argument,  NULL, 'P'},
    {"limit-stack", required_argument,  NULL, 'S'},
    {"limit-time",  required_argument,  NULL, 'T'},
    {"cgroup-root", required_argument,  NULL, OPT_CGR},
    {"limit-rss",   required_argument,  NULL, 'm'},
    {"seccomp-cfg", required_argument,  NULL, OPT_SCC},
    {"allow-root",  no_argument      ,  NULL, OPT_ALR},
    {"quiet",       no_argument      ,  NULL, 'q'},
    {"verbose",     no_argument      ,  NULL, 'v'},
    {"help",        no_argument      ,  NULL, 'h'},
    {NULL,          0,                  NULL,  0 }
};

unsigned long toul(char* str, int abort)
{
    char *p;
    unsigned long ret;
    ret = strtoul(str, &p, 10);
    if (strlen(p)) {
        perrf("Error: Invalid number: %s\n", str);
        if (abort)
            exit(1);
    }
    return ret;
}

long long int toll(char* str, int abort)
{
    char *p;
    long long int ret;
    ret = strtoll(str, &p, 10);
    if (strlen(p)) {
        perrf("Error: Invalid number: %s\n", str);
        if (abort)
            exit(1);
    }
    return ret;
}

struct timeval totime(char* str, int abort)
{
    char *p;
    double sec;
    struct timeval ret;
    sec = strtod(str, &p);
    if (strlen(p)) {
        perrf("Error: Invalid number: %s\n", str);
        if (abort)
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
    int inherenv = 0, allow_root = 0;
    char *envstr = NULL, **para_env = NULL, *sccfg_path = NULL;
    parser_error_t pserr;
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
            case 'c':
                para.chroot = optarg;
                break;
            case 'd':
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
            case 's':
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
            case 'V':
                para.rlim_as = toll(optarg, 1);
                break;
            case 'C':
                para.rlim_core = toll(optarg, 1);
                break;
            case 'F':
                para.rlim_nofile = toll(optarg, 1);
                break;
            case 'Z':
                para.rlim_fsize = toll(optarg, 1);
                break;
            case 'P':
                para.rlim_proc = toll(optarg, 1);
                break;
            case 'S':
                para.rlim_stack = toll(optarg, 1);
                break;
            case 'T':
                time = totime(optarg, 1);
                para.lim_time = time;
                break;
            case OPT_CGR:
                para.cgroup_root = optarg;
                break;
            case 'M':
                para.cg_rss = toll(optarg, 1);
                break;
            case OPT_SCC:
                sccfg_path = optarg;
                break;
            case OPT_ALR:
                allow_root = 1;
                break;
            case 'q':
                set_log_level(LOG_SLIENT);
                break;
            case 'v':
                if (get_log_level() != LOG_SLIENT) {
                    set_log_level(LOG_DEBUG);
                }
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

    if (sccfg_path) {
        para.seccompcfg = scconfig_parse_path(sccfg_path, 0);
        if (!para.seccompcfg) {
            perrf("Failed to parse seccomp config file: %s\n", sccfg_path);
            pserr = parser_get_err();
            if (pserr.line) {
                perrf("At line %d: ", pserr.line);
            }
            perrf("%s\n", parser_errstr(pserr.type));
            exit(1);
        }
    }

    if (!para.uid && !allow_root) {
        perrf("ERROR: Running with UID 0!!!\n");
        perrf("Specify \"--allow-root\" option to allow running as root.\n");
        exit(1);
    }
    if (!para.gid && !allow_root) {
        perrf("ERROR: Running with GID 0!!!\n");
        perrf("Specify \"--allow-root\" option to allow running as root.\n");
        exit(1);
    }

    if (envstr) {
        if (parse_env(envstr, &para_env, (inherenv ? envp : NULL ))) {
            perrf("ERROR: Parsing environment variables\n");
            exit(1);
        }
        para.environ = para_env;
    }
    if (inherenv && !envstr) {
        para.environ = envp;
    }

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
    scconfig_free(para.seccompcfg);
    return 0;
}

void print_result(const struct cjail_result *res)
{
    char timestr[STR_BUF + 1];
    struct tm time;
    if (!localtime_r((time_t *)&res->stats.ac_btime, &time)) {
        snprintf(timestr, sizeof(timestr), "%u", res->stats.ac_btime);
    }
    strftime(timestr, sizeof(timestr), "%F %T", &time);

    printf("++++++++ Execution Result ++++++++\n");
    printf("Time: %ld.%06ld sec\n", res->time.tv_sec, res->time.tv_usec);
    printf("Timeout: %s\n", (res->timekill ? "Y" : "N"));
    printf("Oomkill: %d\n", res->oomkill);
    printf("-------- TASKSTAT --------\n");
    printf("PID: %u\n", res->stats.ac_pid);
    printf("UID: %u\n", res->stats.ac_uid);
    printf("GID: %u\n", res->stats.ac_gid);
    printf("command: %s\n", res->stats.ac_comm);
    printf("exit status: %u\n", res->stats.ac_exitcode);
    printf("NICE: %u\n", res->stats.ac_nice);
    printf("time:\n");
    printf("    start: %s\n", timestr);
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
    printf("I/O:\n");
    printf("    bytes:\n");
    printf("        read: %llu\n", res->stats.read_char);
    printf("        write: %llu\n", res->stats.write_char);
    printf("    syscalls:\n");
    printf("        read: %llu\n", res->stats.read_syscalls);
    printf("        write: %llu\n", res->stats.write_syscalls);
    printf("--------  RUSAGE  --------\n");
    printf("user time: %ld.%06ld\n", res->rus.ru_utime.tv_sec, res->rus.ru_utime.tv_usec);
    printf("system time: %ld.%06ld\n", res->rus.ru_stime.tv_sec, res->rus.ru_stime.tv_usec);
    printf("max_rss: %ld\n", res->rus.ru_maxrss);
    printf("inblock: %ld\n", res->rus.ru_inblock);
    printf("outblock: %ld\n", res->rus.ru_oublock);
    printf("major fault: %ld\n", res->rus.ru_majflt);
    printf("minor fault: %ld\n", res->rus.ru_minflt);
    printf("content switch: %ld\n", res->rus.ru_nvcsw);
    printf("icontent switch: %ld\n", res->rus.ru_nivcsw);
    printf("--------------------------\n");
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
    printf("  -c, --chroot=PATH\t\tset the root path of the jail\n");
    printf("  -d, --workingDir=PATH\t\tchange the working directory of the program\n");
    printf("  -u, --uid=UID\t\t\tset the user of the program\n");
    printf("  -g, --gid=GID\t\t\tset the group of the program\n");
    printf("  -s, --cpuset=SET\t\tset cpu affinity of the program with a list separated by ','\n");
    printf("      \t\t\t\teach entry should be <CPU> or <CPU>-<CPU>\n");
    printf("      --share-net\t\tnot to unshare the net namespace while creating the jail\n");
    printf("      --cgroup-root=PATH\tchange cgroup filesystem root path (default: /sys/fs/cgroup)\n");
    printf("      --allow-root\t\tallow uid or gid to be 0 (root)\n");
    printf("  -q, --quiet\t\t\tnot to print any message\n");
    printf("  -v  --verbose\t\t\tprint more details\n");
    printf("  -h, --help\t\t\tshow this help\n");
    printf("\n");
    printf(" Resource Limit Options:\n");
    printf("  -V, --limit-vss=SIZE\t\tlimit the memory space size can be allocated per process (KB)\n");
    printf("  -C, --limit-core=SIZE\t\tlimit the core file size can be generated (KB)\n");
    printf("  -Z, --limit-fsize=SIZE\tlimit the max file size can be created (KB)\n");
    printf("  -P, --limit-proc=NUM\t\tlimit the process number in the jail\n");
    printf("  -S, --limit-stack=SIZE\tlimit the stack size of one process (KB)\n");
    printf("  -T, --limit-time=SEC\t\tlimit the total running time of the jail (sec)\n");
    printf("  -M, --limit-rss=SIZE\t\tlimit the memory size can be used of the jail (KB)\n");
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
    printf("\n");
    printf(" Seccomp Options:\n");
    printf("      --seccomp-cfg=FILE\tspecify seccomp rules to load\n");
}
