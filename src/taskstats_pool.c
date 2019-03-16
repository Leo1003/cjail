#include "taskstats_pool.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

int ts_list_link(ts_list *list, ts_item *item)
{
    if (!list || !item) {
        errno = EINVAL;
        return -1;
    }

    item->next = NULL;
    if (!list->end) {
        list->head = list->end = item;
        item->prev = NULL;
    } else {
        item->prev = list->end;
        list->end->next = item;
        list->end = item;
    }
    return 0;
}
int ts_list_unlink(ts_list *list, ts_item *item)
{
    if (!list || !item) {
        errno = EINVAL;
        return -1;
    }

    if (item->prev) {
        item->prev->next = item->next;
    } else {
        list->head = item->next;
    }
    if (item->next) {
        item->next->prev = item->prev;
    } else {
        list->end = item->prev;
    }
    item->prev = item->next = NULL;
    return 0;
}
ts_item *ts_list_find(ts_list *list, pid_t pid)
{
    if (!list) {
        errno = EINVAL;
        return NULL;
    }

    ts_item *cur = list->head;
    while (cur) {
        if (cur->pid == pid) {
            break;
        }
        cur = cur->next;
    }
    return cur;
}
int ts_list_clear(ts_list *list)
{
    if (!list) {
        errno = EINVAL;
        return -1;
    }

    ts_item *cur = list->head, *prev = NULL;
    while (cur) {
        prev = cur;
        cur = cur->next;
        free(prev);
    }
    list->head = list->end = NULL;
    return 0;
}

void pool_init(ts_pool *pool)
{
    pool->pending.head = NULL;
    pool->pending.end = NULL;
    pool->completed.head = NULL;
    pool->completed.end = NULL;
}

int pool_append_pid(ts_pool *pool, pid_t pid)
{
    ts_item *new_item = (ts_item *)malloc(sizeof(ts_item));
    if (!new_item) {
        return -1;
    }

    new_item->pid = pid;
    memset(&new_item->stats, 0, sizeof(struct taskstats));
    new_item->prev = NULL;
    new_item->next = NULL;

    return ts_list_link(&pool->pending, new_item);
}

int pool_completed(ts_pool *pool, pid_t pid, const struct taskstats *stats)
{
    ts_item *item = ts_list_find(&pool->pending, pid);
    if (!item) {
        return 0;
    }

    ts_list_unlink(&pool->pending, item);
    memcpy(&item->stats, stats, sizeof(struct taskstats));
    ts_list_link(&pool->completed, item);
    return 0;
}

int pool_result(ts_pool *pool, pid_t pid, struct taskstats *stats)
{
    ts_item *item = ts_list_find(&pool->completed, pid);
    if (!item) {
        errno = ESRCH;
        return -1;
    }

    memcpy(stats, &item->stats, sizeof(struct taskstats));
    return 0;
}

int pool_drop(ts_pool *pool, pid_t pid)
{
    ts_item *item = ts_list_find(&pool->completed, pid);
    if (!item) {
        errno = ENOENT;
        return -1;
    }
    ts_list_unlink(&pool->completed, item);
    free(item);
    return 0;
}

void pool_fini(ts_pool *pool)
{
    ts_list_clear(&pool->pending);
    ts_list_clear(&pool->completed);
}
