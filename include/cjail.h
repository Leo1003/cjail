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
    unsigned int preservefd;    /**< Set this to 1 to keep other file descriptors opening */
    unsigned int sharenet;      /**< Set this to 1 to share the same network namespace with host */
    int fd_input;               /**< The file descriptor to be the child's standard input */
    int fd_output;              /**< The file descriptor to be the child's standard output */
    int fd_err;                 /**< The file descriptor to be the child's standard error */
    char *redir_input;          /**< The file path to reopen as standard input (Under chroot environment) */
    char *redir_output;         /**< The file path to reopen as standard output (Under chroot environment) */
    char *redir_err;            /**< The file path to reopen as standard error (Under chroot environment) */
    char **argv;                /**< The command line of the child process (Under chroot environment) */
    char **environ;             /**< The environment variables of the child process */
    char *chroot;               /**< Make CJail chroot into this directory */
    char *workingDir;           /**< The initial working directory of the child process (Under chroot environment) */
    char *cgroup_root;          /**< The path where cgroup filesystems were mounted (default: /sys/fs/cgroup) */
    cpu_set_t *cpuset;          /**< The initial CPU affinity of the child process (To prevent process modify CPU affinity by themselves, block the sched_setaffinity() system call) */
    uid_t uid;                  /**< The UID of the child process (DO NOT SET THIS TO 0 [root]) */
    gid_t gid;                  /**< The GID of the child process (DO NOT SET THIS TO 0 [root]) */
    long long rlim_as;          /**< Limit processes' virtual memory(address space) */
    long long rlim_core;        /**< Limit core dump size */
    long long rlim_nofile;      /**< Limit file descriptors number can be opened by a process */
    long long rlim_fsize;       /**< Limit the maximum file size can be created by a process */
    long long rlim_proc;        /**< Limit the total processes number can be run at the same time (NOTE: Linux kernel determine this by real UID. If you run many CJail instance at the same time, remember to set their UID to different user, or they will interfere mutually. ) */
    long long rlim_stack;       /**< Limit the stack space of a process, it also including command-line arguments and environment variables */
    long long cg_rss;           /**< Use cgroup to limit the total memory used by all process in the jail */
    struct timeval lim_time;    /**< Limit the time of the jail can live */
    int *seccomplist;           /**< @deprecated this will be replaced by more powerful structure in the next version */
};

/**
 * @struct cjail_result
 * @brief cjail result data
 *
 * containing process exit state and resource usage
 */
struct cjail_result {
    struct taskstats stats;     /**< The taskstats statistics of the first process */
    struct rusage rus;          /**< The rusage statistics of the jail */
    siginfo_t info;             /**< The terminate information of the first process */
    struct timeval time;        /**< The execution time of the jail */
    int timekill;               /**< Set to 1 if the jail killed by hitting the time limit */
    int oomkill;                /**< The processes number killed by oom killer */
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
