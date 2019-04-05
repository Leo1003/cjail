/**
 * @dir tools/
 * @brief command line tools source directory
 */
/**
 * @internal
 * @file main.c
 * @brief cjail command line interface(cli) source
 */
#define _GNU_SOURCE
#include <cjail/cjail.h>
#include <cjail/utils.h>

#include <argz.h>
#include <bsd/string.h>
#include <envz.h>
#include <getopt.h>
#include <math.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/acct.h>
#include <time.h>

#define perrf(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#ifdef NDEBUG
#define devf(fmt, ...)
#else
#define devf(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#endif

// clang-format off
#define STATFLAGS_GENERAL           0x00000001UL
#define STATFLAGS_TASKSTATS         0x00000002UL
#define STATFLAGS_TASKSTATS_TIME    0x00000004UL
#define STATFLAGS_TASKSTATS_CPU     0x00000008UL
#define STATFLAGS_TASKSTATS_MEM     0x00000010UL
#define STATFLAGS_TASKSTATS_IO      0x00000020UL
#define STATFLAGS_RUSAGE            0x00000040UL
#define STATFLAGS_NOFMTTIME         0x00000080UL
#define STATFLAGS_NOFMTFLAGS        0x00000100UL
#define STATFLAGS_INVALID           0xFFFFFFFFUL

#define STATFLAGS_TASKSTATS_ALL     (STATFLAGS_TASKSTATS | STATFLAGS_TASKSTATS_TIME | STATFLAGS_TASKSTATS_CPU | STATFLAGS_TASKSTATS_MEM | STATFLAGS_TASKSTATS_IO)
#define STATFLAGS_NOFMT_ALL         (STATFLAGS_NOFMTTIME | STATFLAGS_NOFMTFLAGS)
#define STATFLAGS_ALL               (STATFLAGS_GENERAL | STATFLAGS_TASKSTATS_ALL | STATFLAGS_RUSAGE)

const table_uint32 statflags_table[] = {
    { "general",            STATFLAGS_GENERAL },
    { "taskstats",          STATFLAGS_TASKSTATS },
    { "taskstats-time",     STATFLAGS_TASKSTATS_TIME },
    { "taskstats-cpu",      STATFLAGS_TASKSTATS_CPU },
    { "taskstats-mem",      STATFLAGS_TASKSTATS_MEM },
    { "taskstats-memory",   STATFLAGS_TASKSTATS_MEM },
    { "taskstats-io",       STATFLAGS_TASKSTATS_IO },
    { "taskstats-all",      STATFLAGS_TASKSTATS },
    { "rusage",             STATFLAGS_RUSAGE },
    { "all",                STATFLAGS_ALL },
    { "no-format",          STATFLAGS_NOFMT_ALL },
    { "no-format-time",     STATFLAGS_NOFMTTIME },
    { "no-format-flags",    STATFLAGS_NOFMTFLAGS },
    { "default",            STATFLAGS_GENERAL },
    { NULL,                 STATFLAGS_INVALID },
};
// clang-format on

#define TIMESTR_BUF 256

void usage(const char *name);
void print_result(const struct cjail_result *res, unsigned long flags);

enum OPTVAL {
    OPT_PFD = 256,
    OPT_NET,
    OPT_CGR,
    OPT_SCC,
    OPT_ALR,
    OPT_SUC,
};

// clang-format off
const char opts[] = "e:Ec:d:u:g:i:o:r:I:O:R:s:V:C:F:Z:P:S:T:m:t::qvh";
const struct option longopts[] = {
    { "environ",        required_argument,  NULL, 'e' },
    { "inherit-env",    no_argument,        NULL, 'E' },
    { "chroot",         required_argument,  NULL, 'c' },
    { "workingDir",     required_argument,  NULL, 'd' },
    { "uid",            required_argument,  NULL, 'u' },
    { "gid",            required_argument,  NULL, 'g' },
    { "file-input",     required_argument,  NULL, 'i' },
    { "file-output",    required_argument,  NULL, 'o' },
    { "file-err",       required_argument,  NULL, 'r' },
    { "fd-input",       required_argument,  NULL, 'I' },
    { "fd-output",      required_argument,  NULL, 'O' },
    { "fd-err",         required_argument,  NULL, 'R' },
    { "preserve-fd",    no_argument,        NULL, OPT_PFD },
    { "share-net",      no_argument,        NULL, OPT_NET },
    { "cpuset",         required_argument,  NULL, 's' },
    { "limit-vss",      required_argument,  NULL, 'V' },
    { "limit-core",     required_argument,  NULL, 'C' },
    { "limit-nofile",   required_argument,  NULL, 'F' },
    { "limit-fsize",    required_argument,  NULL, 'Z' },
    { "limit-proc",     required_argument,  NULL, 'P' },
    { "limit-stack",    required_argument,  NULL, 'S' },
    { "limit-time",     required_argument,  NULL, 'T' },
    { "cgroup-root",    required_argument,  NULL, OPT_CGR },
    { "limit-rss",      required_argument,  NULL, 'm' },
    { "seccomp-cfg",    required_argument,  NULL, OPT_SCC },
    { "allow-root",     no_argument,        NULL, OPT_ALR },
    { "alway-success",  no_argument,        NULL, OPT_SUC },
    { "statistics",     optional_argument,  NULL, 't' },
    { "quiet",          no_argument,        NULL, 'q' },
    { "verbose",        no_argument,        NULL, 'v' },
    { "help",           no_argument,        NULL, 'h' },
    { NULL,             0,                  NULL,  0  }
};
// clang-format on

unsigned long toul(const char *str, int abort)
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

long long int toll(const char *str, int abort)
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

unsigned long parse_statistics_token(const char *token, int abort)
{
    unsigned long flags = utable_to_uint(statflags_table, token);
    if (flags == STATFLAGS_INVALID) {
        perrf("Invalid statistic flag: %s\n", token);
        if (abort) {
            exit(1);
        } else {
            return 0;
        }
    }
    return flags;
}

unsigned long parse_statistics_flags(const char *arg, int abort)
{
    unsigned long flags = 0;
    if (arg) {
        // Since it is not a right way to modify arguments in argv, we make a copy of it first.
        size_t len = strlen(arg);
        char *arg_cpy = (char *)malloc(sizeof(char) * (len + 1));
        if (!arg_cpy) {
            perrf("Failed to allocate memory\n");
            exit(1);
        }
        strncpy(arg_cpy, arg, sizeof(char) * (len + 1));

        char *p = strtok(arg_cpy, ", \t");
        while (p != NULL) {
            flags |= parse_statistics_token(p, abort);
            p = strtok(NULL, ", \t");
        }
        free(arg_cpy);
    } else {
        flags |= parse_statistics_token("default", false);
    }
    return flags;
}

struct timeval totime(const char *str, int abort)
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

int parse_env(const char *str, char *envp[], char **dest[], char **data)
{
    char *argz = NULL, *envz = NULL, *i = NULL;
    size_t argz_len = 0, envz_len = 0;
    if (argz_create_sep(str, ';', &argz, &argz_len)) {
        perror("create list");
        goto error;
    }

    if (envp) {
        if (argz_create(envp, &envz, &envz_len)) {
            perror("create envz");
            goto error;
        }
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

    *dest = (char **)malloc((argz_count(envz, envz_len) + 1) * sizeof(char *));
    argz_extract(envz, envz_len, *dest);
    *data = envz;
    return 0;

error:
    if (argz) {
        free(argz);
    }
    if (envz) {
        free(envz);
    }
    return -1;
}

int main(int argc, char *argv[], char *envp[])
{
    int o;
    cpu_set_t cpuset;
    struct cjail_ctx ctx;
    struct cjail_result res;
    struct timeval time;
    bool inherenv = false, allow_root = false, alway_success = false;
    unsigned long statistics_flags = 0;
    char *envstr = NULL, **para_env = NULL, *envdata = NULL, *sccfg_path = NULL;
    parser_error_t pserr;
#ifndef NDEBUG
    char cpustr[1024];
#endif
    cjail_ctx_init(&ctx);
    while ((o = getopt_long(argc, argv, opts, longopts, NULL)) >= 0) {
        switch (o) {
            case 'e':
                envstr = optarg;
                break;
            case 'E':
                inherenv = true;
                break;
            case 'c':
                ctx.chroot = optarg;
                break;
            case 'd':
                ctx.workingDir = optarg;
                break;
            case 'u':
                ctx.uid = toul(optarg, 1);
                if (ctx.uid >= 65535) {
                    perrf("Error: Invalid UID: %s\n", optarg);
                    exit(1);
                }
                break;
            case 'g':
                ctx.gid = toul(optarg, 1);
                if (ctx.gid >= 65535) {
                    perrf("Error: Invalid GID: %s", optarg);
                    exit(1);
                }
                break;
            case 'i':
                ctx.redir_input = optarg;
                break;
            case 'o':
                ctx.redir_output = optarg;
                break;
            case 'r':
                ctx.redir_error = optarg;
                break;
            case 'I':
                ctx.fd_input = toul(optarg, 1);
                break;
            case 'O':
                ctx.fd_output = toul(optarg, 1);
                break;
            case 'R':
                ctx.fd_error = toul(optarg, 1);
                break;
            case OPT_PFD:
                ctx.preservefd = 1;
                break;
            case OPT_NET:
                ctx.sharenet = 1;
                break;
            case 's':
                if (cpuset_parse(optarg, &cpuset) < 0) {
                    perrf("Error: Invalid cpuset string: %s\n", optarg);
                    exit(1);
                }
                ctx.cpuset = &cpuset;
#ifndef NDEBUG
                cpuset_tostr(&cpuset, cpustr, 1024);
                devf("cpuset: %s\n", cpustr);
#endif
                break;
            case 'V':
                ctx.rlim_as = toll(optarg, 1);
                break;
            case 'C':
                ctx.rlim_core = toll(optarg, 1);
                break;
            case 'F':
                ctx.rlim_nofile = toll(optarg, 1);
                break;
            case 'Z':
                ctx.rlim_fsize = toll(optarg, 1);
                break;
            case 'P':
                ctx.rlim_proc = toll(optarg, 1);
                break;
            case 'S':
                ctx.rlim_stack = toll(optarg, 1);
                break;
            case 'T':
                time = totime(optarg, 1);
                ctx.lim_time = time;
                break;
            case OPT_CGR:
                ctx.cgroup_root = optarg;
                break;
            case 'm':
                ctx.cg_rss = toll(optarg, 1);
                break;
            case OPT_SCC:
                sccfg_path = optarg;
                break;
            case OPT_ALR:
                allow_root = true;
                break;
            case OPT_SUC:
                alway_success = true;
                break;
            case 't':
                statistics_flags = parse_statistics_flags(optarg, 1);
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
            case '?':
            case ':':
                usage(argv[0]);
                exit(1);
            default:
                perrf("Unexpected option character: %c\n", o);
        }
    }
    if (optind >= argc) {
        perrf("Error: command not specified\n");
        exit(1);
    }
    ctx.argv = argv + optind;

    if (sccfg_path) {
        ctx.seccomp_cfg = scconfig_parse_path(sccfg_path, 0);
        if (!ctx.seccomp_cfg) {
            perrf("Failed to parse seccomp config file: %s\n", sccfg_path);
            pserr = parser_get_err();
            if (pserr.line) {
                perrf("At line %d: ", pserr.line);
            }
            perrf("%s\n", parser_errstr(pserr.type));
            exit(1);
        }
    }

    if (!ctx.uid && !allow_root) {
        perrf("ERROR: Running with UID 0!!!\n");
        perrf("Specify \"--allow-root\" option to allow running as root.\n");
        exit(1);
    }
    if (!ctx.gid && !allow_root) {
        perrf("ERROR: Running with GID 0!!!\n");
        perrf("Specify \"--allow-root\" option to allow running as root.\n");
        exit(1);
    }

    if (envstr) {
        if (parse_env(envstr, (inherenv ? envp : NULL), &para_env, &envdata)) {
            perrf("ERROR: Parsing environment variables\n");
            exit(1);
        }
        ctx.environ = para_env;
    }
    if (inherenv && !envstr) {
        ctx.environ = envp;
    }

    int ret = cjail_exec(&ctx, &res);

    if (para_env) {
        free(para_env);
        para_env = NULL;
    }
    if (envdata) {
        free(envdata);
        envdata = NULL;
    }
    if (ret) {
        perrf("cjail failure. %s\n", strerror(errno));
        if (errno == ENOEXEC) {
            exit(255);
        }
        exit(254);
    }
    print_result(&res, statistics_flags);
    scconfig_free(ctx.seccomp_cfg);
    if (alway_success) {
        return 0;
    }
    return (res.info.si_code == CLD_EXITED ? res.info.si_status : res.info.si_status | 0x80);
}

char *printlocaltimef(char *buf, size_t size, const char *format, time_t time, unsigned long flags)
{
    struct tm t;
    if ((flags & STATFLAGS_NOFMTTIME) || !localtime_r(&time, &t)) {
        snprintf(buf, size, "%ld", time);
    } else {
        strftime(buf, size, format, &t);
    }
    return buf;
}

char *printtimeval(char *buf, size_t size, const struct timeval *time, unsigned long flags)
{
    if (flags & STATFLAGS_NOFMTTIME) {
        snprintf(buf, size, "%ld", time->tv_sec * 1000000 + time->tv_usec);
    } else {
        snprintf(buf, size, "%ld.%06ld sec", time->tv_sec, time->tv_usec);
    }
    return buf;
}

char *printusec(char *buf, size_t size, unsigned long long time, unsigned long flags)
{
    if (flags & STATFLAGS_NOFMTTIME) {
        snprintf(buf, size, "%llu", time);
    } else {
        snprintf(buf, size, "%llu.%06llu sec", time / 1000000, time % 1000000);
    }
    return buf;
}

char *printnsec(char *buf, size_t size, unsigned long long time, unsigned long flags)
{
    if (flags & STATFLAGS_NOFMTTIME) {
        snprintf(buf, size, "%llu", time);
    } else {
        snprintf(buf, size, "%llu.%09llu sec", time / 1000000000, time % 1000000000);
    }
    return buf;
}

char *flags_append(char *buf, size_t size, const char *flagstr)
{
    if (buf[0] != '\0') {
        strlcat(buf, " | ", size);
    }
    strlcat(buf, flagstr, size);
    return buf;
}

char *print_acctflags(char *buf, size_t size, unsigned char acctflags, unsigned long flags)
{
    if (flags & STATFLAGS_NOFMTFLAGS) {
        snprintf(buf, size, "0x%02hhx\n", acctflags);
    } else {
        buf[0] = '\0';
        if (acctflags & AFORK)  flags_append(buf, size, "AFORK");
        if (acctflags & ASU)    flags_append(buf, size, "ASU");
        if (acctflags & ACORE)  flags_append(buf, size, "ACORE");
        if (acctflags & AXSIG)  flags_append(buf, size, "AXSIG");
        strlcat(buf, "\n", size);
    }
    return buf;
}

void print_result(const struct cjail_result *res, unsigned long flags)
{
    // No need to print anything if nothing in the flags
    if (!(flags & STATFLAGS_ALL)) {
        return;
    }

    char timebuf[TIMESTR_BUF + 1];

    printf("++++++++ Execution Result ++++++++\n");
    if (flags & STATFLAGS_GENERAL) {
        switch (res->info.si_code) {
            case CLD_EXITED:
                printf("Exitcode: %d\n", res->info.si_status);
                break;
            case CLD_KILLED:
            case CLD_DUMPED:
                printf("Signaled: %d %s", res->info.si_status, strsignal(res->info.si_status));
                if (res->timekill) {
                    printf(" (Timeout)");
                }
                printf("\n");
                break;
        }
        printf("Time: %s\n", printtimeval(timebuf, sizeof(timebuf), &res->time, flags));
        printf("OOMkill: %d\n", res->oomkill);
    }

    if (flags & STATFLAGS_TASKSTATS_ALL) {
        printf("-------- TASKSTATS -------\n");
        if (flags & STATFLAGS_TASKSTATS) {
            printf("PID: %u\n", res->stats.ac_pid);
            printf("UID: %u\n", res->stats.ac_uid);
            printf("GID: %u\n", res->stats.ac_gid);
            printf("Command: %s\n", res->stats.ac_comm);
            printf("Exit Status: %u\n", res->stats.ac_exitcode);
            printf("Flags: %s", print_acctflags(timebuf, sizeof(timebuf), res->stats.ac_flag, flags));
            printf("NICE: %u\n", res->stats.ac_nice);
        }
        if (flags & STATFLAGS_TASKSTATS_TIME) {
            printf("Time:\n");
            printf("    Start: %s\n", printlocaltimef(timebuf, sizeof(timebuf), "%F %T", res->stats.ac_btime, flags));
            printf("        Elapsed: %s\n", printusec(timebuf, sizeof(timebuf), res->stats.ac_etime, flags));
            printf("        User: %s\n", printusec(timebuf, sizeof(timebuf), res->stats.ac_utime, flags));
            printf("        System: %s\n", printusec(timebuf, sizeof(timebuf), res->stats.ac_stime, flags));
        }
        if (flags & STATFLAGS_TASKSTATS_CPU) {
            printf("CPU:\n");
            printf("    Count: %llu\n", res->stats.cpu_count);
            printf("    Realtime: %s\n", printnsec(timebuf, sizeof(timebuf), res->stats.cpu_run_real_total, flags));
            printf("    Virttime: %s\n", printnsec(timebuf, sizeof(timebuf), res->stats.cpu_run_virtual_total, flags));
        }
        if (flags & STATFLAGS_TASKSTATS_MEM) {
            printf("Memory:\n");
            printf("    Bytetime:\n");
            printf("        RSS: %llu\n", res->stats.coremem);
            printf("        VSZ: %llu\n", res->stats.virtmem);
            printf("    High Watermark:\n");
            printf("        RSS: %llu\n", res->stats.hiwater_rss);
            printf("        VSZ: %llu\n", res->stats.hiwater_vm);
        }
        if (flags & STATFLAGS_TASKSTATS_IO) {
            printf("I/O:\n");
            printf("    Bytes:\n");
            printf("        Read: %llu\n", res->stats.read_char);
            printf("        Write: %llu\n", res->stats.write_char);
            printf("    Syscalls:\n");
            printf("        Read: %llu\n", res->stats.read_syscalls);
            printf("        Write: %llu\n", res->stats.write_syscalls);
        }
    }

    if (flags & STATFLAGS_RUSAGE) {
        printf("--------  RUSAGE  --------\n");
        printf("User Time: %s\n", printtimeval(timebuf, sizeof(timebuf), &res->rus.ru_utime, flags));
        printf("System Time: %s\n", printtimeval(timebuf, sizeof(timebuf), &res->rus.ru_stime, flags));
        printf("Max RSS: %ld\n", res->rus.ru_maxrss);
        printf("Inblock: %ld\n", res->rus.ru_inblock);
        printf("Outblock: %ld\n", res->rus.ru_oublock);
        printf("Major Fault: %ld\n", res->rus.ru_majflt);
        printf("Minor Fault: %ld\n", res->rus.ru_minflt);
        printf("Content Switch: %ld\n", res->rus.ru_nvcsw);
        printf("Icontent Switch: %ld\n", res->rus.ru_nivcsw);
    }

    printf("--------------------------\n");
}

void usage(const char *name)
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
    printf("      --alway-success\t\tExit with success even if child process exit with failed status\n");
    printf("  -t, --statistics[=FLAGS]\tPrint statistics to standard output\n");
    printf("      \t\t\t\tBy default, it prints execution result only\n");
    printf("      \t\t\t\tFor other flags, see the sections below\n");
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
    printf("\n");
    printf(" Seccomp Options:\n");
    printf("      --seccomp-cfg=FILE\tspecify seccomp rules to load\n");
    printf("\n");
    printf(" Statistics Flags:\n");
    printf("      default\t\t\tsame as \"general\"\n");
    printf("      general\t\t\tPrint exit status\n");
    printf("      taskstats\t\t\tPrint basic taskstats\n");
    printf("      taskstats-time\t\tPrint taskstats time related statistics\n");
    printf("      taskstats-cpu\t\tPrint taskstats CPU time statistics\n");
    printf("      taskstats-memory\t\tPrint taskstats memory statistics\n");
    printf("      taskstats-mem\t\tAlias for \"taskstats-memory\"\n");
    printf("      taskstats-io\t\tPrint taskstats IO statistics\n");
    printf("      taskstats-all\t\tPrint all taskstats\n");
    printf("      rusage\t\t\tPrint rusage\n");
    printf("      all\t\t\tPrint all statistics above\n");
    printf("      no-format\t\t\tNot to format anything\n");
    printf("      no-format-time\t\tNot to format times\n");
    printf("      no-format-flags\t\tNot to format taskstats flags\n");
}
