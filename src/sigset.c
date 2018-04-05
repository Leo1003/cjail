#include "cjail.h"
#include "sigset.h"
#include "utils.h"

#include <stdarg.h>

int clearsigs()
{
    for(int s = SIGHUP; s < SIGRTMAX; s++)
        signal(s, SIG_DFL);
    return 0;
}

int installsigs(struct sig_rule *rules, int flags)
{
    int i = 0;
    sigset_t set;
    memset(&set, 0, sizeof(set));
    //Setup sigaction mask
    while(rules[i].sig)
    {
        //prevent conflicting rules
        if(rules[i].sig > SIGRTMAX || sigismember(&set, rules[i].sig))
            RETERR(EINVAL);
        sigaddset(&set, rules[i].sig);
        i++;
    }
    //Setup signals
    i = 0;
    while(rules[i].sig)
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_mask = set;
        sa.sa_flags |= flags;
        if(rules[i].handler)
            sa.sa_handler = rules[i].handler;
        else
        {
            if(rules[i].ac_handler)
            {
                sa.sa_sigaction = rules[i].ac_handler;
                sa.sa_flags |= SA_SIGINFO;
            }
            else
                sa.sa_handler = SIG_DFL;
        }
        sigaction(rules[i].sig, &sa, &rules[i].sa_res);
        rules[i].saved = 1;
        i++;
    }
    return 0;
}

int restoresigs(struct sig_rule *rules)
{
    sigset_t set;
    memset(&set, 0, sizeof(set));
    int i = 0;
    while(rules[i].sig)
    {
        if(rules[i].sig > SIGRTMAX || sigismember(&set, rules[i].sig))
            RETERR(EINVAL);
        i++;
    }

    i = 0;
    while(rules[i].sig)
    {
        if(rules[i].saved)
        {
            sigaction(rules[i].sig, &rules[i].sa_res, NULL);
            rules[i].saved = 0;
        }
        i++;
    }
    return 0;
}

void sigsetset(sigset_t *set, int cnt, ...)
{
    sigemptyset(set);
    va_list ap;
    va_start(ap, cnt);
    for(int i = 0; i < cnt; i++)
        sigaddset(set, va_arg(ap, int));
    va_end(ap);
}
