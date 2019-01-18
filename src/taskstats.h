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

/* clang-format off */
#define BUFFER_SIZE         1024

#define TSCTRL_S_OK         0x80
#define TSCTRL_S_ERR        0xFF
#define TSCTRL_C_LISTEN     0x01
#define TSCTRL_C_STATUS     0x02
#define TSCTRL_S_STATUS     0x82
#define TSCTRL_C_RESULT     0x03
#define TSCTRL_S_RESULT     0x83
#define TSCTRL_C_STOP       0x04

enum taskstats_status {
    TSSTA_NONE,
    TSSTA_WAIT,
    TSSTA_DONE,
    TSSTA_WAIT_DONE,
};
/* clang-format on */

typedef struct taskstats_proc {
    pid_t pid;
    int socket;
} tsproc_t;

int taskstats_run(tsproc_t *tsproc);
int taskstats_listen(const tsproc_t *tsproc, pid_t pid);
int taskstats_status(const tsproc_t *tsproc);
int taskstats_result(const tsproc_t *tsproc, pid_t pid, struct taskstats *ts);
int taskstats_stop(const tsproc_t *tsproc);

#endif
