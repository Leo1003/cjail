#ifndef SIGSET_H
#define SIGSET_H

#include <signal.h>

struct sig_rule
{
    int sig;
    void (* handler) (int);
    void (* ac_handler) (int, siginfo_t *, void *);
    struct sigaction saved;
};

void installsigs(struct sig_rule *rules, int flags);
void restoresigs(struct sig_rule *rules);
void sigsetset(sigset_t *set, int cnt, ...);

#endif