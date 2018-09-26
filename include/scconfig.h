#ifndef _SCCONFIG_H
#define _SCCONFIG_H

#define TRACE_MAGIC 28962       /**< @brief ptrace event message of DENY_TRACE */
#define TRACE_KILL_MAGIC 3666   /**< @brief ptrace event message of DENY_TRACE_KILL */

/**
 * @brief The seccomp configure struct. This object is made opaque.
 * Use scconfig_*() to use this type.
 */
typedef void * scconfig;

/**
 * @enum config_type
 * @brief Set configure's default action
 */
enum config_type {
    CFG_WHITELIST,      /**< @brief Allow system calls by default */
    CFG_BLACKLIST       /**< @brief Block system calls by default */
};

/**
 * @enum deny_method
 * @brief Set how to block the system call
 * @see scconfig_get_deny
 * @see scconfig_set_deny
 */
enum deny_method {
    DENY_KILL,          /**< @brief Send SIGKILL to kill the process */
    DENY_TRAP,          /**< @brief Send SIGSYS to kill the process */
    DENY_ERRNO,         /**< @brief Use ENOSYS to make system call fail */
    DENY_TRACE,         /**< @brief Print triggered system call, and make it fail using DENY_ERRNO */
    DENY_TRACE_KILL     /**< @brief Print triggered system call, and make it fail using DENY_KILL */
};

/**
 * @enum rule_type
 * @brief Indicate this rule will allow or deny the matched system call
 */
enum rule_type {
    RULE_ALLOW,         /**< @brief Allow the matched syscall */
    RULE_DENY           /**< @brief Deny the matched syscall */
};

/**
 * @enum compare
 * @brief Indicate how does the argument rule match
 */
enum compare {
    CMP_NONE = 0,       /**< @brief Disable this rule */
    CMP_EQ,             /**< @brief Argument should equal to the value */
    CMP_NE,             /**< @brief Argument should not equal to the value */
    CMP_GT,             /**< @brief Argument should greater than the value */
    CMP_GE,             /**< @brief Argument should greater than or equal to the value */
    CMP_LT,             /**< @brief Argument should less than the value */
    CMP_LE,             /**< @brief Argument should less than or equal to the value */
    CMP_MASK            /**< @brief After being masked, argument should equal to the value */
};

/**
 * @struct args_rule
 * @brief A argument rule in a seccomp rule
 */
struct args_rule {
    enum compare cmp;   /**< @brief Indicate how does the argument rule match
                             @see compare */
    u_int64_t value;    /**< @brief The value in the rule */
    u_int64_t mask;     /**< @brief The mask is used by CMP_MASK */
};

/**
 * @struct args_rule
 * @brief A seccomp rule that can match specify system call
 */
struct seccomp_rule {
    enum rule_type type;        /**< @brief Indicate this rule will allow or deny the matched system call
                                     @see rule_type */
    int syscall;                /**< @brief Indicate this rule will apply on what system call by its number */
    struct args_rule args[6];   /**< @brief 6 argument rules from argument 0 to 5 to match the system call
                                     @note Remember to set the unused rules' cmp to CMP_NONE
                                     @see srgs_rule */
};

/**
 * @brief Generate BPF program by configure
 *
 * @param cfg seccomp configure
 * @param[out] bpf output of the BPF program
 * @return Execution result
 * @retval 0 Succeed
 * @retval -1 One or more errors encountered
 */
int scconfig_compile(const scconfig cfg, struct sock_fprog *bpf);

/**
 * @brief Allocate and initialize a seccomp configure
 *
 * @param[in] type seccomp configure type
 * @return Pointer to the newly allocate configure
 * @retval pointer Succeed
 * @retval NULL One or more errors encountered
 */
scconfig scconfig_init(enum config_type type);

/**
 * @brief Get the current deny method of a seccomp configure
 *
 * @param cfg seccomp configure
 * @return current deny method
 */
enum deny_method scconfig_get_deny(const scconfig cfg);

/**
 * @brief Set deny method of a seccomp configure
 *
 * @param cfg seccomp configure
 * @param[in] deny deny method to set
 */
void scconfig_set_deny(scconfig cfg, enum deny_method deny);

/**
 * @brief Clear all rules in a configure
 *
 * @param cfg seccomp configure
 * @return Execution result
 * @retval 0 Succeed
 * @retval -1 One or more errors encountered
 */
int scconfig_clear(scconfig cfg);

/**
 * @brief Add rules into a configure
 *
 * @param cfg seccomp configure
 * @param[in] rules pointer to the first rule
 * @param[in] len the total rules count
 * @return Execution result
 * @retval 0 Succeed
 * @retval -1 One or more errors encountered
 */
int scconfig_add(scconfig cfg, const struct seccomp_rule *rules, size_t len);

/**
 * @brief Remove rules in a configure
 *
 * @param cfg seccomp configure
 * @param[in] i remove from i-th rule
 * @param[in] len the total rules count to be remove
 * @return Execution result
 * @retval 0 Succeed
 * @retval -1 One or more errors encountered
 */
int scconfig_remove(scconfig cfg, size_t i, size_t len);

/**
 * @brief Get a rule in a configure
 * @note The pointer may change after adding new rules or allocating.
 *
 * @param cfg seccomp configure
 * @param[in] i get the i-th rule
 * @return Pointer to the rule
 * @retval pointer Succeed
 * @retval NULL One or more errors encountered
 */
struct seccomp_rule * scconfig_get_rule(scconfig cfg, size_t i);

/**
 * @brief Preallocate memory for rules
 *
 * @param cfg seccomp configure
 * @param[in] len The total capacity of the configure
 * @return Execution result
 * @retval 0 Succeed
 * @retval -1 One or more errors encountered
 */
int scconfig_allocate(scconfig cfg, size_t len);

/**
 * @brief Get rules count in a configure
 *
 * @param cfg seccomp configure
 * @return Rules count
 */
size_t scconfig_len(const scconfig cfg);

/**
 * @brief Free the configure
 * @note you should not free one configure twice. It's advice to set the pointer to NULL after free
 *
 * @param cfg seccomp configure to be free
 */
void scconfig_free(scconfig cfg);

#endif
