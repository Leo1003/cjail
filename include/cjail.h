#ifndef _CJAIL_H
#define _CJAIL_H

#include <linux/filter.h>
#include <linux/taskstats.h>
#include <sched.h>
#include <stdio.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

//TODO: Complete Doxygen comments in this public header

/**
 * @struct cjail_para
 * @brief cjail executing parameters
 *
 * parameters indicating the sandbox settings and process configures
 */
struct cjail_para {
    unsigned int preservefd;    /**<  */
    unsigned int sharenet;      /**<  */
    int fd_input;               /**<  */
    int fd_output;              /**<  */
    int fd_err;                 /**<  */
    char *redir_input;          /**<  */
    char *redir_output;         /**<  */
    char *redir_err;            /**<  */
    char **argv;                /**<  */
    char **environ;             /**<  */
    char *chroot;               /**<  */
    char *workingDir;           /**<  */
    char *cgroup_root;          /**<  */
    cpu_set_t *cpuset;          /**<  */
    uid_t uid;                  /**<  */
    gid_t gid;                  /**<  */
    long long rlim_as;          /**<  */
    long long rlim_core;        /**<  */
    long long rlim_nofile;      /**<  */
    long long rlim_fsize;       /**<  */
    long long rlim_proc;        /**<  */
    long long rlim_stack;       /**<  */
    long long cg_rss;           /**<  */
    struct timeval lim_time;    /**<  */
    int *seccomplist;           /**<  */
};

/**
 * @struct cjail_result
 * @brief cjail result data
 *
 * containing process exit state and resource usage
 */
struct cjail_result {
    struct taskstats stats;     /**<  */
    struct rusage rus;          /**<  */
    siginfo_t info;             /**<  */
    struct timeval time;        /**<  */
    int timekill;               /**<  */
    int oomkill;                /**<  */
};

/**
 * @enum logger_level
 * @brief log levels to distinguish the importance of logs
 *
 * By using set_log_level() function, you can hide many unimportant logs, or
 * read more verbose messages.
 */
enum logger_level {
    LOG_NONE,           /**< for internal use only */
    LOG_DEBUG,          /**< debug level, output all messages */
    LOG_INFO,           /**< information level, default value for release build */
    LOG_WARN,           /**< warning level, some unimportant error occurred or dangerous settings */
    LOG_ERROR,          /**< error level, usually caused by wrong parameters */
    LOG_FATAL,          /**< fatal level, something wrong happened accidentally */
    LOG_SLIENT = 255    /**< let the logger DO NOT output anything! */
};

/**
 * @brief Initialize cjail_para struct
 *
 * @param[in,out] para cjail_para struct to be initialized
 */
void cjail_para_init(struct cjail_para *para);

/**
 * @brief Execute a process in the jail
 *
 * @param[in] para Executing parameters to the jail
 * @param[out] result Executing results to be filled
 * @return 0 if succeed, otherwise, -1
 */
int cjail_exec(const struct cjail_para *para, struct cjail_result *result);

/**
 * @brief Convert cpu_set_t to human readable format
 *
 * @param[in] cpuset cpu_set_t to be converted
 * @param[out] str Output string
 * @param[in] len The buffer size of str
 * @return string length if succeed, otherwise, -1
 */
int cpuset_tostr(const cpu_set_t *cpuset, char *str, size_t len);

/**
 * @brief Convert human readable format to cpu_set_t
 *
 * @param[in] str string to be converted
 * @param[out] cpuset Output
 * @return 0 if succeed, otherwise, -1
 */
int cpuset_parse(const char *str, cpu_set_t *cpuset);

/**
* @brief Get current log level
*
* @return current log level
*/
enum logger_level get_log_level();

/**
* @brief Set the log level
*
* @param[in] level log level to be set (can not be LOG_NONE)
*/
void set_log_level(enum logger_level level);

/**
* @brief Change the logger's output stream
*
* @param[in] f the new file stream
*/
void set_log_file(FILE * f);

#ifdef __cplusplus
}
#endif

#endif
