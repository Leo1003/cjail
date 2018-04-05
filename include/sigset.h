#ifndef SIGSET_H
#define SIGSET_H

#include <signal.h>

struct sig_rule
{
    int sig;
    void (* handler) (int);
    void (* ac_handler) (int, siginfo_t *, void *);
    struct sigaction sa_res;
    int saved;
};

int clearsigs();
int installsigs(struct sig_rule *rules, int flags);
int restoresigs(struct sig_rule *rules);
void sigsetset(sigset_t *set, int cnt, ...);

#endif