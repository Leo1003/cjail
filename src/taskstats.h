/**
 * @internal
 * @file taskstats.h
 * @brief taskstat resource statistics header
 */
#ifndef TASKSTATS_H
#define TASKSTATS_H

#include "utils.h"
#include <sched.h>
#include <time.h>

#include <linux/genetlink.h>
#include <linux/taskstats.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

/* Maximum size of response requested or message sent */
#define MAX_CPU_MASK    1024

typedef struct _taskstats_control ts_t;

ts_t *taskstats_new();
int taskstats_sockfd(const ts_t *ts);
int taskstats_recv(ts_t *ts);
int taskstats_add_task(ts_t *ts, pid_t pid);
int taskstats_get_stats(ts_t *ts, pid_t pid, struct taskstats *stats);
int taskstats_free(ts_t *ts);

#endif
