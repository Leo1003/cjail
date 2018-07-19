#include "cjail.h"
#include "logger.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>

static enum logger_level loglv = LOG_NONE, lastlv = LOG_INFO;
static FILE *logfile = NULL;

static void init_logger()
{
#ifdef NDEBUG
    loglv = LOG_INFO;
#else
    loglv = LOG_DEBUG;
#endif  //NDEBUG
    logfile = stderr;
}

inline static void chk_logger_init()
{
    if (!loglv || !logfile) {
        init_logger();
    }
}

enum logger_level get_log_level()
{
    chk_logger_init();
    return loglv;
}

void set_log_level(enum logger_level level)
{
    chk_logger_init();
    if (level) {
        loglv = level;
    }
}

void set_log_file(FILE* f)
{
    chk_logger_init();
    if (f) {
        logfile = f;
    }
}

int swap_log_file()
{
    chk_logger_init();
    int nfd;
    if ((nfd = fcntl(fileno(logfile), F_DUPFD_CLOEXEC, 3)) < 0) {
        goto error;
    }
    FILE *nf = fdopen(nfd, "w");
    if (!nf) {
        goto error_fd;
    }
    if (fseek(nf, 0, SEEK_END) && errno != ESPIPE) {
        fclose(nf);
        goto error;
    }
    set_log_file(nf);
    devf("logger output swapped!\n");
    return 0;

error_fd:
    close(nfd);
error:
    return -1;
}

#ifdef NDEBUG
int loggerf(enum logger_level level, const char* format, ...)
#else
int loggerf(enum logger_level level, const char *src, int line, const char *format, ...)
#endif  //NDEBUG
{
    va_list ap;
    int ret = 0;
    enum logger_level l;
    error_t savederr = errno;
    chk_logger_init();
    if (level == LOG_SLIENT) {
        return 0;
    }
    if (level == LOG_NONE) {
        l = lastlv;
    } else {
        l = lastlv = level;
    }
    if (l < loglv) {
        return 0;
    }
    switch (level) {
        case LOG_DEBUG:
            ret += fprintf(logfile, "DEBUG: ");
            break;
        case LOG_INFO:
            ret += fprintf(logfile, "INFO : ");
            break;
        case LOG_WARN:
            ret += fprintf(logfile, "WARN : ");
            break;
        case LOG_ERROR:
            ret += fprintf(logfile, "ERROR: ");
            break;
        case LOG_FATAL:
            ret += fprintf(logfile, "FATAL: ");
            break;
        default:
            break;
    }
#ifndef NDEBUG
    if (level != LOG_NONE) {
        ret += fprintf(logfile, "[%s:%d]\t", src, line);
    }
#endif  //NDEBUG
    va_start(ap, format);
    ret += vfprintf(logfile, format, ap);
    va_end(ap);
    errno = savederr;
    return ret;
}
