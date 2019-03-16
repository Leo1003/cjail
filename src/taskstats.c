/**
 * @internal
 * @file taskstats.c
 * @brief taskstat resource statistics source
 */
#include "taskstats.h"
#include "taskstats_pool.h"
#include "logger.h"
#include "utils.h"

#include <linux/taskstats.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <netlink/errno.h>
#include <netlink/handlers.h>
#include <netlink/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>

typedef struct _taskstats_control {
    struct nl_sock *sock;
    int familyid;
    ts_pool pool;
} ts_t;

static void setnlerr(int nlerr);

static int taskstats_send_cmd(struct nl_sock *sock, int familyid, __u8 genl_cmd, __u16 nla_type, void *nla_data, int nla_len)
{
    struct nl_msg *msg = nlmsg_alloc();
    int ret = 0;
    if (!msg) {
        return -1;
    }
    if (!genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, familyid, 0, 0, TASKSTATS_CMD_GET, TASKSTATS_VERSION)) {
        goto error;
    }
    if ((ret = nla_put(msg, nla_type, nla_len, nla_data)) < 0) {
        setnlerr(ret);
        goto error;
    }
    if ((ret = nl_send_auto(sock, msg)) < 0) {
        setnlerr(ret);
        goto error;
    }
    nlmsg_free(msg);
    return ret;

error:
    nlmsg_free(msg);
    return -1;
}

static int parse_aggr_attr(struct nlattr *attr, ts_pool *pool)
{
    int ret = 0;
    pid_t pid;
    struct nlattr *attrs[TASKSTATS_TYPE_MAX + 1];
    if ((ret = nla_parse_nested(attrs, TASKSTATS_TYPE_MAX, attr, NULL)) < 0) {
        errorf("Parsing nested netlink message error!\n");
        return -1;
    }
    if (attrs[TASKSTATS_TYPE_PID]) {
        pid = *(pid_t *)nla_data(attrs[TASKSTATS_TYPE_PID]);
    } else if (attrs[TASKSTATS_TYPE_TGID]) {
        pid = *(pid_t *)nla_data(attrs[TASKSTATS_TYPE_TGID]);
    } else {
        errorf("Can't find pid/tgid attribute!\n");
        return -1;
    }
    if (!attrs[TASKSTATS_TYPE_STATS]) {
        errorf("Can't find taskstats attribute!\n");
        return -1;
    }
    pool_completed(pool, pid, (struct taskstats *)nla_data(attrs[TASKSTATS_TYPE_STATS]));

    return 0;
}

static int taskstats_callback(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *hdr = nlmsg_hdr(msg);
    struct nlattr *attrs[TASKSTATS_TYPE_MAX + 1];
    ts_t *ts = (ts_t *)arg;

    int ret = 0;
    if ((ret = genlmsg_parse(hdr, 0, attrs, TASKSTATS_TYPE_MAX, NULL)) < 0) {
        errorf("Parsing generic netlink message error!\n");
        return NL_SKIP;
    }
    if (attrs[TASKSTATS_TYPE_AGGR_PID]) {
        if (parse_aggr_attr(attrs[TASKSTATS_TYPE_AGGR_PID], &ts->pool)) {
            return NL_SKIP;
        }
    } else if (attrs[TASKSTATS_TYPE_AGGR_TGID]) {
        if (parse_aggr_attr(attrs[TASKSTATS_TYPE_AGGR_TGID], &ts->pool)) {
            return NL_SKIP;
        }
    } else if (attrs[TASKSTATS_TYPE_NULL]) {
        ;
    } else {
        warnf("Received unknown taskstats message!\n");
    }

    return NL_OK;
}

ts_t *taskstats_new()
{
    int status;
    ts_t *ts;

    /* Acquire system cpumask */
    char cpumask[MAX_CPU_MASK];
    if (get_system_cpumask(cpumask, sizeof(cpumask)) < 0) {
        PERR("parse_cpuset");
        goto out;
    }

    /* Allocate struct */
    ts = (ts_t *)malloc(sizeof(ts_t));
    if (!ts) {
        return NULL;
    }
    pool_init(&ts->pool);

    /* Create generic netlink socket */
    ts->sock = nl_socket_alloc();
    if (!ts->sock) {
        PFTL("alloc netlink socket");
        goto out_free;
    }
    if ((status = genl_connect(ts->sock)) < 0) {
        PFTL("connect to generic netlink");
        setnlerr(status);
        goto out_nl;
    }
    /* Taskstats doesn't use normal sequence number */
    nl_socket_disable_seq_check(ts->sock);
    if (setcloexec(nl_socket_get_fd(ts->sock))) {
        goto out_nl;
    }
    devf("Created netlink socket: fd %d\n", nl_socket_get_fd(ts->sock));

    /* Resolve taskstats generic netlink family id */
    if ((ts->familyid = genl_ctrl_resolve(ts->sock, TASKSTATS_GENL_NAME)) < 0) {
        PFTL("get family id");
        setnlerr(ts->familyid);
        goto out_nl;
    }
    devf("Resolved family id: %d\n", ts->familyid);

    /* Register libnl callback */
    if ((status = nl_socket_modify_cb(ts->sock, NL_CB_VALID, NL_CB_CUSTOM, taskstats_callback, ts)) < 0) {
        PFTL("set callback function");
        setnlerr(status);
        goto out_nl;
    }
    /* Register taskstats cpumask */
    debugf("Setting cpumask to: %s\n", cpumask);
    if (taskstats_send_cmd(ts->sock, ts->familyid, TASKSTATS_CMD_GET, TASKSTATS_CMD_ATTR_REGISTER_CPUMASK, cpumask, strlen(cpumask) + 1) < 0) {
        PFTL("taskstats_setcpuset");
        goto out_nl;
    }
    return ts;

out_nl:
    nl_socket_free(ts->sock);
out_free:
    free(ts);
out:
    return NULL;
}

int taskstats_sockfd(const ts_t *ts)
{
    if (!ts || !ts->sock) {
        errno = EINVAL;
        return -1;
    }
    return nl_socket_get_fd(ts->sock);
}

int taskstats_recv(ts_t *ts)
{
    int cnt;
    if (!ts || !ts->sock) {
        errno = EINVAL;
        return -1;
    }

    /* Since nl_recvmsgs_default() doesn't provide the received messages count.
       We have to use this way to receive message. */
    struct nl_cb *def_cb = nl_socket_get_cb(ts->sock);
    if ((cnt = nl_recvmsgs_report(ts->sock, def_cb)) < 0) {
        errorf("Error occurred when receiving taskstats message: %s\n", nl_geterror(cnt));
        setnlerr(cnt);
        cnt = -1;
    }
    /* The nl_cb which returned from nl_socket_get_cb() has increased its reference count.
       So we need to put back its reference count. */
    nl_cb_put(def_cb);
    return cnt;
}

int taskstats_add_task(ts_t *ts, pid_t pid)
{
    if (!ts || !ts->sock) {
        errno = EINVAL;
        return -1;
    }
    return pool_append_pid(&ts->pool, pid);
}

int taskstats_get_stats(ts_t *ts, pid_t pid, struct taskstats *stats)
{
    if (!ts || !ts->sock) {
        errno = EINVAL;
        return -1;
    }
    return pool_result(&ts->pool, pid, stats);
}

int taskstats_free(ts_t *ts)
{
    if (!ts || !ts->sock) {
        errno = EINVAL;
        return -1;
    }

    /* Acquire system cpumask */
    char cpumask[MAX_CPU_MASK];
    if (get_system_cpumask(cpumask, sizeof(cpumask)) < 0) {
        PERR("parse_cpuset");
        return -1;
    }

    /* Deregister to save system resource */
    if (taskstats_send_cmd(ts->sock, ts->familyid, TASKSTATS_CMD_GET, TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK, cpumask, strlen(cpumask) + 1) < 0) {
        PWRN("deregister cpumask");
    }

    nl_socket_free(ts->sock);
    ts->sock = NULL;
    pool_fini(&ts->pool);
    free(ts);
    return 0;
}

/* Helper functions */
static int nlerr2syserr(int nlerr)
{
    int err = abs(nlerr);
    switch (err) {
        case NLE_SUCCESS:
            return 0;
        case NLE_FAILURE:
            return EINVAL;
        case NLE_INTR:
            return EINTR;
        case NLE_BAD_SOCK:
            return ENOTSOCK;
        case NLE_AGAIN:
            return EAGAIN;
        case NLE_NOMEM:
            return ENOMEM;
        case NLE_EXIST:
            return EEXIST;
        case NLE_INVAL:
            return EINVAL;
        case NLE_RANGE:
            return ERANGE;
        case NLE_MSGSIZE:
            return EMSGSIZE;
        case NLE_OPNOTSUPP:
            return EOPNOTSUPP;
        case NLE_AF_NOSUPPORT:
            return EAFNOSUPPORT;
        case NLE_OBJ_NOTFOUND:
            return ENOENT;
        case NLE_NOATTR:
            return ENOENT;
        case NLE_MISSING_ATTR:
            return ENOENT;
        case NLE_AF_MISMATCH:
            return EINVAL;
        case NLE_SEQ_MISMATCH:
            return EINVAL;
        case NLE_MSG_OVERFLOW:
            return EOVERFLOW;
        case NLE_MSG_TRUNC:
            return EBADMSG;
        case NLE_NOADDR:
            return EADDRNOTAVAIL;
        case NLE_SRCRT_NOSUPPORT:
            return ENOTSUP;
        case NLE_MSG_TOOSHORT:
            return ENOMSG;
        case NLE_MSGTYPE_NOSUPPORT:
            return ENOTSUP;
        case NLE_OBJ_MISMATCH:
            return EINVAL;
        case NLE_NOCACHE:
            return EINVAL;
        case NLE_BUSY:
            return EBUSY;
        case NLE_PROTO_MISMATCH:
            return EPROTONOSUPPORT;
        case NLE_NOACCESS:
            return EACCES;
        case NLE_PERM:
            return EPERM;
        case NLE_PKTLOC_FILE:
            return EACCES;
        case NLE_PARSE_ERR:
            return ENOMSG;
        case NLE_NODEV:
            return ENODEV;
        case NLE_IMMUTABLE:
            return EINVAL;
        case NLE_DUMP_INTR:
            return EINTR;
        default:
            return EINVAL;
    }
}

static void setnlerr(int nlerr)
{
    errno = nlerr2syserr(nlerr);
}
