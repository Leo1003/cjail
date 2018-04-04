#include "cjail.h"
#include "sigset.h"

#include <stdarg.h>

void sigsetset(sigset_t *set, int cnt, ...)
{
    sigemptyset(set);
    va_list ap;
    va_start(ap, cnt);
    for(int i = 0; i < cnt; i++)
        sigaddset(set, va_arg(ap, int));
    va_end(ap);
}
