/**
 * @internal
 * @file sigset.h
 * @brief signal management functions header
 */
#ifndef SIGSET_H
#define SIGSET_H

#include <signal.h>
#define SIGREADY 34

struct sig_rule
{
    int sig;
    void (* handler) (int);
    void (* ac_handler) (int, siginfo_t *, void *);
    int flags;
    struct sigaction sa_res;
    int saved;
};

int clearsigs();
int installsigs(struct sig_rule* rules);
int restoresigs(struct sig_rule *rules);
void sigsetset(sigset_t *set, int cnt, ...);

#endif
