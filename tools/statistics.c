#define _GNU_SOURCE
#include "statistics.h"
#include "utils.h"
#include <cjail/cjail.h>
#include <cjail/utils.h>

#include <bsd/string.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/acct.h>
#include <time.h>
#define FMTSTR_BUF 256

// clang-format off
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

static char *flags_append(char *buf, size_t size, const char *flagstr)
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

char *print_average(char *buf, size_t size, unsigned long long bytetime, enum size_unit base_unit, unsigned long long usecs, unsigned long flags)
{
    double avg = (double)bytetime / (double)usecs;
    if (flags & STATFLAGS_NOFMTSIZE) {
        enum size_unit cur_unit = base_unit;
        while (cur_unit != Bytes) {
            cur_unit = (enum size_unit)(cur_unit - 1);
            avg *= 1024.0;
        }
        unsigned long long avg_bytes = (unsigned long long)round(avg);
        snprintf(buf, size, "%llu", avg_bytes);
    } else {
        _print_size(buf, size, avg, base_unit, 0);
    }

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

    print_taskstats(&res->stats, flags);

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

void print_taskstats(const struct taskstats *stats, unsigned long flags)
{
    char fmtbuf[FMTSTR_BUF + 1];
    if (!(flags & STATFLAGS_TASKSTATS_ALL)) {
        return;
    }
    printf("-------- TASKSTATS -------\n");
    if (flags & STATFLAGS_TASKSTATS) {
        printf("PID: %u\n", stats->ac_pid);
        printf("UID: %u\n", stats->ac_uid);
        printf("GID: %u\n", stats->ac_gid);
        printf("Command: %s\n", stats->ac_comm);
        printf("Exit Status: %u\n", stats->ac_exitcode);
        printf("Flags: %s", print_acctflags(fmtbuf, sizeof(fmtbuf), stats->ac_flag, flags));
        printf("NICE: %u\n", stats->ac_nice);
    }
    if (flags & STATFLAGS_TASKSTATS_TIME) {
        printf("Time:\n");
        printf("    Start: %s\n", printlocaltimef(fmtbuf, sizeof(fmtbuf), "%F %T", stats->ac_btime, flags));
        printf("        Elapsed: %s\n", printusec(fmtbuf, sizeof(fmtbuf), stats->ac_etime, flags));
        printf("        User: %s\n", printusec(fmtbuf, sizeof(fmtbuf), stats->ac_utime, flags));
        printf("        System: %s\n", printusec(fmtbuf, sizeof(fmtbuf), stats->ac_stime, flags));
    }
    if (flags & STATFLAGS_TASKSTATS_CPU) {
        printf("CPU:\n");
        printf("    Count: %llu\n", stats->cpu_count);
        printf("    Realtime: %s\n", printnsec(fmtbuf, sizeof(fmtbuf), stats->cpu_run_real_total, flags));
        printf("    Virttime: %s\n", printnsec(fmtbuf, sizeof(fmtbuf), stats->cpu_run_virtual_total, flags));
    }
    if (flags & STATFLAGS_TASKSTATS_MEM) {
        printf("Memory:\n");
        if (flags & STATFLAGS_NOFMTAVG) {
            printf("    Byte-Time:\n");
            printf("        RSS: %s\n", print_size(fmtbuf, sizeof(fmtbuf), stats->coremem, MBytes, flags | STATFLAGS_SIZEUSEC));
            printf("        VSZ: %s\n", print_size(fmtbuf, sizeof(fmtbuf), stats->virtmem, MBytes, flags | STATFLAGS_SIZEUSEC));
        } else {
            printf("    Average:\n");
            printf("        RSS: %s\n", print_average(fmtbuf, sizeof(fmtbuf), stats->coremem, MBytes, stats->ac_etime, flags));
            printf("        VSZ: %s\n", print_average(fmtbuf, sizeof(fmtbuf), stats->virtmem, MBytes, stats->ac_etime, flags));
        }
        printf("    High Watermark:\n");
        printf("        RSS: %s\n", print_size(fmtbuf, sizeof(fmtbuf), stats->hiwater_rss, KBytes, flags));
        printf("        VSZ: %s\n", print_size(fmtbuf, sizeof(fmtbuf), stats->hiwater_vm, KBytes, flags));
    }
    if (flags & STATFLAGS_TASKSTATS_IO) {
        printf("I/O:\n");
        printf("    Bytes:\n");
        printf("        Read: %s\n", print_size(fmtbuf, sizeof(fmtbuf), stats->read_char, Bytes, flags));
        printf("        Write: %s\n", print_size(fmtbuf, sizeof(fmtbuf), stats->write_char, Bytes, flags));
        printf("    Syscalls:\n");
        printf("        Read: %llu\n", stats->read_syscalls);
        printf("        Write: %llu\n", stats->write_syscalls);
    }
}
