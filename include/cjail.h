/**
 * @dir include/
 * @brief public headers directory
 */
/**
 * @file include/cjail.h
 * @brief cjail main public header
 */
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

#include "scconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @struct cjail_para
 * @brief cjail executing parameters
 *
 * parameters indicating the sandbox settings and process configures
 */
struct cjail_para {
    unsigned int preservefd;    /**< @brief Set this to 1 to keep non-standard file descriptors opening
                                     @warning Use this carefully! */
    unsigned int sharenet;      /**< @brief Set this to 1 to share the same network namespace with host
                                     @warning Use this carefully! */
    int fd_input;               /**< @brief The file descriptor to be the child's standard input
                                     @note This operation is after reopen standard I/O file descriptors */
    int fd_output;              /**< @brief The file descriptor to be the child's standard output
                                     @note This operation is after reopen standard I/O file descriptors */
    int fd_error;               /**< @brief The file descriptor to be the child's standard error
                                     @note This operation is after reopen standard I/O file descriptors */
    char *redir_input;          /**< @brief The file path to reopen as standard input
                                     @note This path is under chroot environment */
    char *redir_output;         /**< @brief The file path to reopen as standard output
                                     @note This path is under chroot environment */
    char *redir_error;          /**< @brief The file path to reopen as standard error
                                     @note This path is under chroot environment */
    char **argv;                /**< @brief The command line of the child process
                                     @note The path is under chroot environment */
    char **environ;             /**< @brief The environment variables of the child process
                                     @note Each string should be "[name]=[val]" */
    char *chroot;               /**< @brief Make CJail chroot into this directory
                                     @details And after a successful chroot, it will automatically change its working directory to new root
                                     @details Set to NULL to disable chroot */
    char *workingDir;           /**< @brief The initial working directory of the child process
                                     @note This path is under chroot environment
                                     @note Set to NULL to use current working directory */
    char *cgroup_root;          /**< @brief The path where cgroup filesystems were mounted (default: /sys/fs/cgroup) */
    cpu_set_t *cpuset;          /**< @brief The initial CPU affinity of the child process
                                     @note To prevent process modify CPU affinity by themselves, you can block the sched_setaffinity() system call */
    uid_t uid;                  /**< @brief The UID of the child process
                                     @warning DO NOT SET THIS TO 0 [root] */
    gid_t gid;                  /**< @brief The GID of the child process
                                     @warning DO NOT SET THIS TO 0 [root] */
    long long rlim_as;          /**< @brief Limit processes' virtual memory(address space)(KB)
                                     @note Set to zero to disable this limit */
    long long rlim_core;        /**< @brief Limit core dump size(KB)
                                     @note Set to negative value to disable this limit */
    long long rlim_nofile;      /**< @brief Limit file descriptors number can be opened by a process
                                     @note Set to zero to disable this limit */
    long long rlim_fsize;       /**< @brief Limit the maximum file size(KB) can be created by a process
                                     @note Set to zero to disable this limit */
    long long rlim_proc;        /**< @brief Limit the total processes number can be run at the same time
                                     @note Linux kernel determine this by real UID.
                                     If you run many CJail instance at the same time, remember to set their UID to different user, or they will interfere mutually. */
    long long rlim_stack;       /**< @brief Limit the stack space(KB) of a process
                                     @note Also including command-line arguments and environment variables
                                     @note Set to zero to disable this limit */
    long long cg_rss;           /**< @brief Use cgroup to limit the total memory(KB) used by all process in the jail
                                     @note Set to zero to disable this limit */
    struct timeval lim_time;    /**< @brief Limit the time of the jail can live
                                     @note set to zero to disable time limit */
    scconfig seccompcfg;        /**< @brief  */
};

/**
 * @struct cjail_result
 * @brief cjail result data
 *
 * containing process exit state and resource usage
 */
struct cjail_result {
    struct taskstats stats;     /**< @brief The taskstats statistics of the first process */
    struct rusage rus;          /**< @brief The rusage statistics of the jail */
    siginfo_t info;             /**< @brief The return status of the first process */
    struct timeval time;        /**< @brief The total execution time of the jail */
    int timekill;               /**< @brief Set to 1 if the jail killed by hitting the time limit */
    int oomkill;                /**< @brief The processes number killed by oom killer */
};

/**
 * @enum logger_level
 * @brief log levels to distinguish the importance of logs
 *
 * By using set_log_level() function, you can hide many unimportant logs, or
 * read more verbose messages.
 */
enum logger_level {
    LOG_NONE,           /**< @brief for internal use only */
    LOG_DEBUG,          /**< @brief debug level, output all messages */
    LOG_INFO,           /**< @brief information level, default value for release build */
    LOG_WARN,           /**< @brief warning level, some unimportant error occurred or dangerous settings */
    LOG_ERROR,          /**< @brief error level, usually caused by wrong parameters */
    LOG_FATAL,          /**< @brief fatal level, something wrong happened accidentally */
    LOG_SLIENT = 255    /**< @brief let the logger DO NOT output anything! */
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
 * @return Execution result
 * @retval 0 Succeed
 * @retval -1 One or more errors encountered
 */
int cjail_exec(const struct cjail_para *para, struct cjail_result *result);

/**
 * @brief Convert cpu_set_t to human readable format
 *
 * @param[in] cpuset cpu_set_t to be converted
 * @param[out] str Output string
 * @param[in] len The buffer size of str
 * @return String length if succeed
 * @retval Positive String length
 * @retval -1 One or more errors encountered
 */
int cpuset_tostr(const cpu_set_t *cpuset, char *str, size_t len);

/**
 * @brief Convert human readable format to cpu_set_t
 * @note A legal string should only contain numbers, ',', and '-'.
 * @n It must not have any space in it; otherwise, the convertion would error.
 * @n Each cpu number should be separated by ','.
 * @n You can also use '-' to represent continous cpu numbers, like "0,1-3,5,9-10".
 *
 * @param[in] str string to be converted
 * @param[out] cpuset Output
 * @return Execution result
 * @retval 0 Succeed
 * @retval -1 One or more errors encountered
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
