/**
 * @internal
 * @file taskstats.c
 * @brief taskstat resource statistics source
 */
#define _GNU_SOURCE
#include "taskstats.h"
#include "cjail.h"
#include "logger.h"
#include "sigset.h"

#include <fcntl.h>
#include <linux/netlink.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <netlink/errno.h>
#include <netlink/handlers.h>
#include <netlink/netlink.h>

#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>

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
static ts_pool ts_global_pool;

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

enum taskstats_status pool_status(ts_pool *pool)
{
    enum taskstats_status status = TSSTA_NONE;
    if (pool->pending.head) status = (enum taskstats_status)(status & TSSTA_WAIT);
    if (pool->completed.head) status = (enum taskstats_status)(status & TSSTA_DONE);
    return status;
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

static int taskstats_daemon(int ctrl_socket);
static void setnlerr(int nlerr);

static int ctrl_send_ok(int ctrlsock)
{
    unsigned char sendbuf[1];
    sendbuf[0] = TSCTRL_S_OK;
    return send(ctrlsock, sendbuf, sizeof(sendbuf), 0);
}

static int ctrl_send_error(int ctrlsock)
{
    unsigned char sendbuf[1 + sizeof(errno)];
    sendbuf[0] = TSCTRL_S_ERR;
    memcpy(sendbuf + 1, &errno, sizeof(errno));
    return send(ctrlsock, sendbuf, sizeof(sendbuf), 0);
}

static int ctrl_send_status(int ctrlsock)
{
    unsigned char sendbuf[1 + sizeof(enum taskstats_status)];
    sendbuf[0] = TSCTRL_S_STATUS;
    *(enum taskstats_status *)(sendbuf + 1) = pool_status(&ts_global_pool);
    return send(ctrlsock, sendbuf, sizeof(sendbuf), 0);
}

static int ctrl_send_result(int ctrlsock, pid_t pid)
{
    unsigned char sendbuf[1 + sizeof(struct taskstats)];
    sendbuf[0] = TSCTRL_S_RESULT;
    if (pool_result(&ts_global_pool, pid, (struct taskstats *)(sendbuf + 1)) < 0) {
        return ctrl_send_error(ctrlsock);
    }
    return send(ctrlsock, sendbuf, sizeof(sendbuf), 0);
}

static int taskstats_ctrl_server(int ctrlsock)
{
    unsigned char recvbuf[BUFFER_SIZE];
    int ret = 0;
    pid_t pid;

    if (recv(ctrlsock, &recvbuf, BUFFER_SIZE, 0) < 0) {
        PFTL("receive control message on server side");
        return -1;
    }
    switch (recvbuf[0]) {
        case TSCTRL_C_STATUS:
            if (ctrl_send_status(ctrlsock) < 0) {
                ret = -1;
            }
            break;
        case TSCTRL_C_LISTEN:
            memcpy(&pid, recvbuf + 1, sizeof(pid_t));
            if (pool_append_pid(&ts_global_pool, pid)) {
                ret = ctrl_send_error(ctrlsock);
            }
            if (ctrl_send_ok(ctrlsock) < 0) {
                ret = -1;
            }
            break;
        case TSCTRL_C_RESULT:
            memcpy(&pid, recvbuf + 1, sizeof(pid_t));
            if (ctrl_send_result(ctrlsock, pid) < 0) {
                ret = -1;
            }
            break;
        case TSCTRL_C_STOP:
            ctrl_send_ok(ctrlsock);
            ret = 1;
            break;
        default:
            errorf("Received unknown control message: %#hhX\n", recvbuf[0]);
            ret = -1;
            break;
    }
    return ret;
}

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

static int parse_aggr_attr(struct nlattr *attr)
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
    pool_completed(&ts_global_pool, pid, (struct taskstats *)nla_data(attrs[TASKSTATS_TYPE_STATS]));
    return 0;
}

static int taskstats_callback(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *hdr = nlmsg_hdr(msg);
    struct nlattr *attrs[TASKSTATS_TYPE_MAX + 1];

    int ret = 0;
    if ((ret = genlmsg_parse(hdr, 0, attrs, TASKSTATS_TYPE_MAX, NULL)) < 0) {
        errorf("Parsing generic netlink message error!\n");
        return NL_SKIP;
    }
    if (attrs[TASKSTATS_TYPE_AGGR_PID]) {
        if (parse_aggr_attr(attrs[TASKSTATS_TYPE_AGGR_PID])) {
            return NL_SKIP;
        }
    } else if (attrs[TASKSTATS_TYPE_AGGR_TGID]) {
        if (parse_aggr_attr(attrs[TASKSTATS_TYPE_AGGR_TGID])) {
            return NL_SKIP;
        }
    } else if (attrs[TASKSTATS_TYPE_NULL]) {
        ;
    } else {
        warnf("Received unknown taskstats message!\n");
    }

    return NL_OK;
}

static volatile sig_atomic_t interrupted = 0;
static void sighandler(int sig)
{
    interrupted = 1;
}

// clang-format off
static struct sig_rule ts_sigrules[] = {
    { SIGHUP  , sighandler, NULL, 0, {{0}}, 0 },
    { SIGINT  , sighandler, NULL, 0, {{0}}, 0 },
    { SIGQUIT , sighandler, NULL, 0, {{0}}, 0 },
    { SIGPIPE , SIG_IGN   , NULL, 0, {{0}}, 0 },
    { SIGTERM , sighandler, NULL, 0, {{0}}, 0 },
    { SIGCHLD , SIG_IGN   , NULL, 0, {{0}}, 0 },
    { SIGTTIN , SIG_IGN   , NULL, 0, {{0}}, 0 },
    { SIGTTOU , SIG_IGN   , NULL, 0, {{0}}, 0 },
    { 0       , NULL      , NULL, 0, {{0}}, 0 },
};
// clang-format on

#define SAVEERR_GOTO(label) \
    do { \
        saved_errno = errno; \
        goto label; \
    } while(0)

static int taskstats_daemon(int ctrl_socket)
{
    int status = -1, ret = 0, familyid = 0, running = 1, epfd, saved_errno = 0;
    struct nl_sock *sock;
    struct epoll_event epev_nl, epev_ctrl;
    sigset_t emptyset;

    interrupted = 0;
    installsigs(ts_sigrules);
    pool_init(&ts_global_pool);
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)) {
        PERR("set parent death signal");
    }
    sigemptyset(&emptyset);
    sigprocmask(SIG_SETMASK, &emptyset, NULL);

    /* Acquire system cpumask */
    cpu_set_t system_cpuset;
    CPU_ZERO(&system_cpuset);
    for (int i = 0; i < get_nprocs(); i++) {
        CPU_SET(i, &system_cpuset);
    }
    char cpumask[MAX_CPU_MASK];
    if (cpuset_tostr(&system_cpuset, cpumask, sizeof(cpumask)) < 0) {
        PERR("parse_cpuset");
        SAVEERR_GOTO(out_pool);
    }

    /* Create generic netlink socket */
    sock = nl_socket_alloc();
    if (!sock) {
        PFTL("alloc netlink socket");
        SAVEERR_GOTO(out_pool);
    }
    if ((ret = genl_connect(sock)) < 0) {
        PFTL("connect to generic netlink");
        setnlerr(ret);
        SAVEERR_GOTO(out_nl);
    }
    nl_socket_disable_seq_check(sock);
    if (setcloexec(nl_socket_get_fd(sock))) {
        SAVEERR_GOTO(out_nl);
    }
    devf("Created netlink socket: fd %d\n", nl_socket_get_fd(sock));

    /* Resolve taskstats generic netlink family id */
    if ((ret = genl_ctrl_resolve(sock, TASKSTATS_GENL_NAME)) < 0) {
        PFTL("get family id");
        setnlerr(ret);
        SAVEERR_GOTO(out_nl);
    }
    familyid = ret;
    devf("Resolved family id: %d\n", familyid);

    /* Register libnl callback */
    if ((ret = nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, taskstats_callback, NULL)) < 0) {
        PFTL("set callback function");
        setnlerr(ret);
        SAVEERR_GOTO(out_nl);
    }
    /* Register taskstats cpumask */
    debugf("Setting cpumask to: %s\n", cpumask);
    if (taskstats_send_cmd(sock, familyid, TASKSTATS_CMD_GET, TASKSTATS_CMD_ATTR_REGISTER_CPUMASK, cpumask, strlen(cpumask) + 1) < 0) {
        PFTL("taskstats_setcpuset");
        SAVEERR_GOTO(out_nl);
    }

    /* Setup epoll */
    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        PFTL("create epoll file descriptor");
        SAVEERR_GOTO(out_dereg);
    }
    epev_nl = (struct epoll_event){
        .events = EPOLLIN,
        .data.fd = nl_socket_get_fd(sock)
    };
    epev_ctrl = (struct epoll_event){
        .events = EPOLLIN | EPOLLRDHUP,
        .data.fd = ctrl_socket
    };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, nl_socket_get_fd(sock), &epev_nl)) {
        PFTL("add netlink socket epoll event");
        SAVEERR_GOTO(out_epoll);
    }
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, ctrl_socket, &epev_ctrl)) {
        PFTL("add control socket epoll event");
        SAVEERR_GOTO(out_epoll);
    }

    /* Enter main loop */
    sigset_t mask, orig;
    sigsetset(&mask, 4, SIGHUP, SIGINT, SIGQUIT, SIGTERM);
    sigprocmask(SIG_SETMASK, &mask, &orig);
    ctrl_send_ok(ctrl_socket);
    while (running && !interrupted) {
        struct epoll_event epev_result[2];
        int epcnt = 0;
        if ((epcnt = epoll_pwait(epfd, epev_result, 2, -1, &orig)) < 0) {
            if (errno == EINTR) {
                /* to check if interrupted */
                continue;
            }
            PFTL("wait epoll event");
            goto out_epoll;
        }
        for (int i = 0; i < epcnt; i++) {
            if (epev_result[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                errorf("Caught socket event: %#x\n", epev_result[i].events);
                errorf("Socket closed by peer, stop running.\n");
                running = 0;
                continue;
            }
            if (epev_result[i].events & EPOLLIN) {
                if (epev_result[i].data.fd == nl_socket_get_fd(sock)) {
                    if ((ret = nl_recvmsgs_default(sock)) < 0) {
                        errorf("Error occurred when receiving taskstats message: %s\n", nl_geterror(ret));
                    }
                } else if (epev_result[i].data.fd == ctrl_socket) {
                    int ret = taskstats_ctrl_server(ctrl_socket);
                    if (ret < 0) {
                        PERR("receive control message");
                    }
                    if (ret == 1) {
                        debugf("Stopping taskstats daemon...\n");
                        running = 0;
                    }
                }
            }
        }
    }
    sigprocmask(SIG_SETMASK, &orig, NULL);

    status = 0;
    if (interrupted) {
        status = -1;
        saved_errno = EINTR;
    }
out_epoll:
    if (close(epfd)) {
        PWRN("close epoll file descriptor");
    }
out_dereg:
    /* Exit cleanup */
    if (taskstats_send_cmd(sock, familyid, TASKSTATS_CMD_GET, TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK, cpumask, strlen(cpumask) + 1) < 0) {
        PWRN("deregister cpumask");
    }
out_nl:
    nl_socket_free(sock);
out_pool:
    pool_fini(&ts_global_pool);

    if (saved_errno) {
        errno = saved_errno;
        ctrl_send_error(ctrl_socket);
    }
    if (close(ctrl_socket)) {
        PWRN("close control file descriptor");
    }
    return status;
}
#undef SAVEERR_GOTO

/* Client side functions */
int taskstats_run(tsproc_t *tsproc)
{
    int sockpair[2], sig, saved_errno;
    if (!tsproc) {
        errno = EINVAL;
        return -1;
    }
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockpair)) {
        PFTL("create socketpair");
        return -1;
    }
    sigset_t mask, orig;
    sigsetset(&mask, 1, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, &orig);

    pid_t pid = fork();
    if (pid == 0) {
        int ret = 0;
        if (close(sockpair[0])) {
            PERR("close sockpair 0");
        }
        ret = taskstats_daemon(sockpair[1]);
        if (ret) {
            ctrl_send_error(sockpair[1]);
        }
        exit(ret);
    } else if (pid > 0) {
        if (close(sockpair[1])) {
            PFTL("close sockpair 1");
            goto out_kill;
        }
        unsigned char recvbuf[BUFFER_SIZE];
        if (recv(sockpair[0], recvbuf, sizeof(recvbuf), 0) < 0) {
            PFTL("receive message");
            goto out_kill;
        }
        switch (recvbuf[0]) {
            case TSCTRL_S_OK:
                break;
            case TSCTRL_S_ERR:
                errno = *(int *)(recvbuf + 1);
                goto out_kill;
            default:
                errno = ENOMSG;
                goto out_kill;
        }
    } else {
        PFTL("fork taskstats listening process");
        close(sockpair[1]);
        goto parent_error;
    }
    sigprocmask(SIG_SETMASK, &orig, NULL);
    tsproc->pid = pid;
    tsproc->socket = sockpair[0];
    return 0;

out_kill:
    saved_errno = errno;
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    sigwait(&mask, &sig); /* consume SIGCHLD signal */
    errno = saved_errno;
parent_error:
    close(sockpair[0]);
    sigprocmask(SIG_SETMASK, &orig, NULL);
    return -1;
}

inline static int test_tsproc(const tsproc_t *tsproc)
{
    if (!tsproc) {
        errno = EINVAL;
        return -1;
    }
    if (kill(tsproc->pid, 0)) {
        return -1;
    }
    return 0;
}

int taskstats_listen(const tsproc_t *tsproc, pid_t pid)
{
    unsigned char sendbuf[1 + sizeof(pid_t)], recvbuf[BUFFER_SIZE];
    if (test_tsproc(tsproc)) {
        return -1;
    }
    sendbuf[0] = TSCTRL_C_LISTEN;
    memcpy(sendbuf + 1, &pid, sizeof(pid_t));
    if (send(tsproc->socket, sendbuf, sizeof(sendbuf), 0) < 0) {
        PFTL("send message");
        return -1;
    }
    if (recv(tsproc->socket, recvbuf, sizeof(recvbuf), 0) < 0) {
        PFTL("receive message");
        return -1;
    }
    switch (recvbuf[0]) {
        case TSCTRL_S_OK:
            break;
        case TSCTRL_S_ERR:
            errno = *(int *)(recvbuf + 1);
            return -1;
        default:
            errno = ENOMSG;
            return -1;
    }
    return 0;
}

int taskstats_status(const tsproc_t *tsproc)
{
    unsigned char sendbuf[1], recvbuf[BUFFER_SIZE];
    enum taskstats_status ret = TSSTA_NONE;
    if (test_tsproc(tsproc)) {
        return -1;
    }
    sendbuf[0] = TSCTRL_C_STATUS;
    if (send(tsproc->socket, sendbuf, sizeof(sendbuf), 0) < 0) {
        PFTL("send message");
        return -1;
    }
    if (recv(tsproc->socket, recvbuf, sizeof(recvbuf), 0) < 0) {
        PFTL("receive message");
        return -1;
    }
    switch (recvbuf[0]) {
        case TSCTRL_S_STATUS:
            memcpy(&ret, recvbuf + 1, sizeof(ret));
            break;
        default:
            errno = ENOMSG;
            return -1;
    }
    return ret;
}

int taskstats_result(const tsproc_t *tsproc, pid_t pid, struct taskstats *ts)
{
    unsigned char sendbuf[1 + sizeof(pid_t)], recvbuf[BUFFER_SIZE];
    if (test_tsproc(tsproc)) {
        return -1;
    }
    sendbuf[0] = TSCTRL_C_RESULT;
    memcpy(sendbuf + 1, &pid, sizeof(pid_t));
    if (send(tsproc->socket, sendbuf, sizeof(sendbuf), 0) < 0) {
        PFTL("send message");
        return -1;
    }
    if (recv(tsproc->socket, recvbuf, sizeof(recvbuf), 0) < 0) {
        PFTL("receive message");
        return -1;
    }
    switch (recvbuf[0]) {
        case TSCTRL_S_RESULT:
            if (ts) {
                memcpy(ts, recvbuf + 1, sizeof(struct taskstats));
            }
            break;
        case TSCTRL_S_ERR:
            errno = *(int *)(recvbuf + 1);
            devf("errno = %d %s\n", errno, strerror(errno));
            return -1;
        default:
            errno = ENOMSG;
            return -1;
    }
    return 0;
}

int taskstats_stop(const tsproc_t *tsproc)
{
    unsigned char sendbuf[1 + sizeof(pid_t)], recvbuf[BUFFER_SIZE];
    if (test_tsproc(tsproc)) {
        return -1;
    }
    int sig;
    sigset_t mask, orig;
    sigsetset(&mask, 1, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, &orig);

    sendbuf[0] = TSCTRL_C_STOP;
    if (send(tsproc->socket, sendbuf, sizeof(sendbuf), 0) < 0) {
        PFTL("send message");
        return -1;
    }
    if (recv(tsproc->socket, recvbuf, sizeof(recvbuf), 0) < 0) {
        PFTL("receive message");
        return -1;
    }
    switch (recvbuf[0]) {
        case TSCTRL_S_OK:
            break;
        default:
            warnf("Receive unknown message while stopping...\n");
            kill(tsproc->pid, SIGKILL);
            break;
    }
    waitpid(tsproc->pid, NULL, 0);
    sigwait(&mask, &sig); /* consume SIGCHLD signal */
    sigprocmask(SIG_SETMASK, &orig, NULL);
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
