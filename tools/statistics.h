#ifndef TOOLS_STATISTICS_H
#define TOOLS_STATISTICS_H

#include <cjail/cjail.h>
#include <cjail/utils.h>

#include <linux/taskstats.h>
#include <stdlib.h>

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
// clang-format on

unsigned long parse_statistics_flags(const char *arg, int abort);
void print_result(const struct cjail_result *res, unsigned long flags);
void print_taskstats(const struct taskstats *stats, unsigned long flags);

#endif
