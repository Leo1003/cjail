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
#include "statistics.h"
#include "utils.h"
#include <cjail/cjail.h>
#include <cjail/utils.h>

#include <argz.h>
#include <envz.h>
#include <getopt.h>
#include <math.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void usage(const char *name);

enum OPTVAL {
    OPT_PFD = 256,
    OPT_NET,
    OPT_CGR,
    OPT_SCC,
    OPT_ALR,
    OPT_SUC,
};

// clang-format off
const char opts[] = "e:Ec:d:u:g:i:o:r:I:O:R:M:s:V:C:F:Z:P:S:T:m:t::qvh";
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
    { "mount",          required_argument,  NULL, 'M' },
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

int parse_mnt_opt(const char *arg, struct jail_mount_list *mnt_list)
{
    struct jail_mount_ctx mnt_ctx;
    const size_t MNT_ARG_LEN = 1024;
    char arg_cp[MNT_ARG_LEN + 1];
    if (strlen(arg) > MNT_ARG_LEN) {
        return -1;
    }
    strncpy(arg_cp, arg, sizeof(arg_cp));
    arg_cp[MNT_ARG_LEN] = '\0';

    char *path_part = strtok(arg_cp, ":");
    //TODO: Uncompleted
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
            case 'M':
                // TODO: Parse mounting
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
