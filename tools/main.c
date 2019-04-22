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
#define STATFLAGS_STATUS            0x00000001UL
#define STATFLAGS_TASKSTATS         0x00000002UL
#define STATFLAGS_TASKSTATS_TIME    0x00000004UL
#define STATFLAGS_TASKSTATS_CPU     0x00000008UL
#define STATFLAGS_TASKSTATS_MEM     0x00000010UL
#define STATFLAGS_TASKSTATS_IO      0x00000020UL
#define STATFLAGS_RUSAGE            0x00000040UL
#define STATFLAGS_NOFMTTIME         0x00000080UL
#define STATFLAGS_NOFMTFLAGS        0x00000100UL
#define STATFLAGS_NOFMTSIZE         0x00000200UL
#define STATFLAGS_NOFMTAVG          0x00000400UL
// internal use only
#define STATFLAGS_SIZEUSEC          0x80000000UL
#define STATFLAGS_INVALID           0xFFFFFFFFUL

#define STATFLAGS_TASKSTATS_ALL     (STATFLAGS_TASKSTATS | STATFLAGS_TASKSTATS_TIME | STATFLAGS_TASKSTATS_CPU | STATFLAGS_TASKSTATS_MEM | STATFLAGS_TASKSTATS_IO)
#define STATFLAGS_NOFMT_ALL         (STATFLAGS_NOFMTTIME | STATFLAGS_NOFMTFLAGS | STATFLAGS_NOFMTSIZE | STATFLAGS_NOFMTAVG)
#define STATFLAGS_ALL               (STATFLAGS_STATUS | STATFLAGS_TASKSTATS_ALL | STATFLAGS_RUSAGE)

const table_uint32 statflags_table[] = {
    { "status",             STATFLAGS_STATUS },
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
    { "no-format-size",     STATFLAGS_NOFMTSIZE },
    { "no-average",         STATFLAGS_NOFMTAVG },
    { "default",            STATFLAGS_STATUS },
    { "none",               0 },
    { NULL,                 STATFLAGS_INVALID },
};
// clang-format on

#define FMTSTR_BUF 256

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

// Prettify datetime
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

// Prettify struct timeval
char *printtimeval(char *buf, size_t size, const struct timeval *time, unsigned long flags)
{
    if (flags & STATFLAGS_NOFMTTIME) {
        snprintf(buf, size, "%ld", time->tv_sec * 1000000 + time->tv_usec);
    } else {
        //snprintf(buf, size, "%ld.%06ld sec", time->tv_sec, time->tv_usec);
        unsigned long long usec = time->tv_sec * 1000000 + time->tv_usec;
        snprintf(buf, size, "%.03lf sec", usec / 1000000.0);
    }
    return buf;
}

// Prettify time in micro second
char *printusec(char *buf, size_t size, unsigned long long time, unsigned long flags)
{
    if (flags & STATFLAGS_NOFMTTIME) {
        snprintf(buf, size, "%llu", time);
    } else {
        //snprintf(buf, size, "%llu.%06llu sec", time / 1000000, time % 1000000);
        snprintf(buf, size, "%.03lf sec", time / 1000000.0);
    }
    return buf;
}

// Prettify time in nano second
char *printnsec(char *buf, size_t size, unsigned long long time, unsigned long flags)
{
    if (flags & STATFLAGS_NOFMTTIME) {
        snprintf(buf, size, "%llu", time);
    } else {
        //snprintf(buf, size, "%llu.%09llu sec", time / 1000000000, time % 1000000000);
        snprintf(buf, size, "%.03lf sec", time / 1000000000.0);
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

// Prettify print unix acct flags
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

enum size_unit {
    Bytes = 0,
    KBytes,
    MBytes,
    GBytes,
    TBytes,
    PBytes,
    EBytes,
    ZBytes,
    YBytes,
};

const char *str_unit(enum size_unit unit)
{
    switch (unit)
    {
        case Bytes:
            return "Bytes";
        case KBytes:
            return "KB";
        case MBytes:
            return "MB";
        case GBytes:
            return "GB";
        case TBytes:
            return "TB";
        case PBytes:
            return "PB";
        case EBytes:
            return "EB";
        case ZBytes:
            return "ZB";
        case YBytes:
            return "YB";
    }
}

static char *_print_size(char *buf, size_t size, double bytes, enum size_unit base_unit, unsigned long flags)
{
    enum size_unit cur_unit = base_unit;
    double cur_bytes = bytes;
    // Convert to bigger unit
    while (cur_bytes >= 1024.0) {
        if (cur_unit == TBytes) {
            // Reach maximum supported unit
            break;
        }
        cur_unit = (enum size_unit)(cur_unit + 1);
        cur_bytes /= 1024.0;
    }
    // Convert to smaller unit
    while (cur_bytes < 1.0) {
        if (cur_unit == Bytes) {
            // Reach minimum supported unit
            break;
        }
        cur_unit = (enum size_unit)(cur_unit - 1);
        cur_bytes *= 1024.0;
    }

    // Check if size-time unit
    if (flags & STATFLAGS_SIZEUSEC) {
        snprintf(buf, size, "%.2lf %s-usecs", cur_bytes, str_unit(cur_unit));
    } else {
        snprintf(buf, size, "%.2lf %s", cur_bytes, str_unit(cur_unit));
    }
    return buf;
}

// Prettify print size unit
char *print_size(char *buf, size_t size, unsigned long long bytes, enum size_unit base_unit, unsigned long flags)
{
    if (flags & STATFLAGS_NOFMTSIZE) {
        snprintf(buf, size, "%llu", bytes);
    } else {
        _print_size(buf, size, (double)bytes, base_unit, flags);
    }
    return buf;
}

char *print_average(char *buf, size_t size, unsigned long long bytetime, enum size_unit base_unit, unsigned long long usecs)
{
    double avg = (double)bytetime / (double)usecs;
    _print_size(buf, size, avg, base_unit, 0);
    return buf;
}

void print_result(const struct cjail_result *res, unsigned long flags)
{
    // No need to print anything if nothing in the flags
    if (!(flags & STATFLAGS_ALL)) {
        return;
    }

    char fmtbuf[FMTSTR_BUF + 1];

    printf("++++++++ Execution Result ++++++++\n");
    if (flags & STATFLAGS_STATUS) {
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
        printf("Time: %s\n", printtimeval(fmtbuf, sizeof(fmtbuf), &res->time, flags));
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
            printf("Flags: %s", print_acctflags(fmtbuf, sizeof(fmtbuf), res->stats.ac_flag, flags));
            printf("NICE: %u\n", res->stats.ac_nice);
        }
        if (flags & STATFLAGS_TASKSTATS_TIME) {
            printf("Time:\n");
            printf("    Start: %s\n", printlocaltimef(fmtbuf, sizeof(fmtbuf), "%F %T", res->stats.ac_btime, flags));
            printf("        Elapsed: %s\n", printusec(fmtbuf, sizeof(fmtbuf), res->stats.ac_etime, flags));
            printf("        User: %s\n", printusec(fmtbuf, sizeof(fmtbuf), res->stats.ac_utime, flags));
            printf("        System: %s\n", printusec(fmtbuf, sizeof(fmtbuf), res->stats.ac_stime, flags));
        }
        if (flags & STATFLAGS_TASKSTATS_CPU) {
            printf("CPU:\n");
            printf("    Count: %llu\n", res->stats.cpu_count);
            printf("    Realtime: %s\n", printnsec(fmtbuf, sizeof(fmtbuf), res->stats.cpu_run_real_total, flags));
            printf("    Virttime: %s\n", printnsec(fmtbuf, sizeof(fmtbuf), res->stats.cpu_run_virtual_total, flags));
        }
        if (flags & STATFLAGS_TASKSTATS_MEM) {
            printf("Memory:\n");
            if (flags & STATFLAGS_NOFMTAVG) {
                printf("    Byte-Time:\n");
                printf("        RSS: %s\n", print_size(fmtbuf, sizeof(fmtbuf), res->stats.coremem, MBytes, flags | STATFLAGS_SIZEUSEC));
                printf("        VSZ: %s\n", print_size(fmtbuf, sizeof(fmtbuf), res->stats.virtmem, MBytes, flags | STATFLAGS_SIZEUSEC));
            } else {
                printf("    Average:\n");
                printf("        RSS: %s\n", print_average(fmtbuf, sizeof(fmtbuf), res->stats.coremem, MBytes, res->stats.ac_etime));
                printf("        VSZ: %s\n", print_average(fmtbuf, sizeof(fmtbuf), res->stats.virtmem, MBytes, res->stats.ac_etime));
            }
            printf("    High Watermark:\n");
            printf("        RSS: %s\n", print_size(fmtbuf, sizeof(fmtbuf), res->stats.hiwater_rss, KBytes, flags));
            printf("        VSZ: %s\n", print_size(fmtbuf, sizeof(fmtbuf), res->stats.hiwater_vm, KBytes, flags));
        }
        if (flags & STATFLAGS_TASKSTATS_IO) {
            printf("I/O:\n");
            printf("    Bytes:\n");
            printf("        Read: %s\n", print_size(fmtbuf, sizeof(fmtbuf), res->stats.read_char, Bytes, flags));
            printf("        Write: %s\n", print_size(fmtbuf, sizeof(fmtbuf), res->stats.write_char, Bytes, flags));
            printf("    Syscalls:\n");
            printf("        Read: %llu\n", res->stats.read_syscalls);
            printf("        Write: %llu\n", res->stats.write_syscalls);
        }
    }

    if (flags & STATFLAGS_RUSAGE) {
        printf("--------  RUSAGE  --------\n");
        printf("User Time: %s\n", printtimeval(fmtbuf, sizeof(fmtbuf), &res->rus.ru_utime, flags));
        printf("System Time: %s\n", printtimeval(fmtbuf, sizeof(fmtbuf), &res->rus.ru_stime, flags));
        printf("Max RSS: %s\n", print_size(fmtbuf, sizeof(fmtbuf), res->rus.ru_maxrss, KBytes, flags));
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
    printf("      \t\t\t\tIf this option doesn't specified, it wouldn't print out any statistics\n");
    printf("      \t\t\t\tIf no flags are given, it only prints exit status (same as \"default\" flag)\n");
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
    printf("      default\t\t\tsame as \"status\"\n");
    printf("      status\t\t\tPrint exit status\n");
    printf("      taskstats\t\t\tPrint basic taskstats\n");
    printf("      taskstats-time\t\tPrint taskstats time related statistics\n");
    printf("      taskstats-cpu\t\tPrint taskstats CPU time statistics\n");
    printf("      taskstats-memory\t\tPrint taskstats memory statistics\n");
    printf("      taskstats-mem\t\tAlias for \"taskstats-memory\"\n");
    printf("      taskstats-io\t\tPrint taskstats IO statistics\n");
    printf("      taskstats-all\t\tPrint all taskstats\n");
    printf("      rusage\t\t\tPrint rusage\n");
    printf("      all\t\t\tPrint all statistics above\n");
    printf("      none\t\t\tPrint nothing (This flag doesn't disable other flags)\n");
    printf("      no-format\t\t\tNot to format anything\n");
    printf("      no-format-time\t\tNot to format time\n");
    printf("      no-format-flags\t\tNot to format taskstats flags\n");
    printf("      no-format-size\t\tNot to format size\n");
    printf("      no-average\t\tDon't convert byte-time into average memory usage\n");
}
