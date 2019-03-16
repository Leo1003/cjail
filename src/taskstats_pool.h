#ifndef TASKSTATS_POOL_H
#define TASKSTATS_POOL_H

#include <linux/taskstats.h>
#include <sys/types.h>

typedef struct taskstats_item {
    pid_t pid;
    struct taskstats stats;
    struct taskstats_item *prev, *next;
} ts_item;

typedef struct taskstats_list {
    ts_item *head, *end;
} ts_list;

typedef struct taskstats_proc_pool {
    ts_list pending, completed;
} ts_pool;

void pool_init(ts_pool *pool);
int pool_append_pid(ts_pool *pool, pid_t pid);
int pool_completed(ts_pool *pool, pid_t pid, const struct taskstats *stats);
int pool_result(ts_pool *pool, pid_t pid, struct taskstats *stats);
int pool_drop(ts_pool *pool, pid_t pid);
void pool_fini(ts_pool *pool);

#endif
