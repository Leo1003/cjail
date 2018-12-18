#include "cjail.h"
#include "scconfig_parser.h"

#include <criterion/assert.h>
#include <criterion/criterion.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <seccomp.h>

#define SCCONFIG_PATH "/tmp/scconfig_test.conf"

static const char *basic_cfg_data =
    "###########################################\n"
    "###   seccomp config parser test file   ###\n"
    "###########################################\n"
    "\n"
    "# A basic example act like SECCOMP_SET_MODE_STRICT\n"
    "\n"
    "TYPE WHITELIST\n"
    "ACTION KILL\n"
    "\n"
    "ALLOW read()           # Read from fds\n"
    "ALLOW write()          # Write to fds\n"
    "ALLOW rt_sigreturn()   # Called when signal handler return\n"
    "ALLOW exit()           # Not exit_group()\n";

static const char *advanced_data =
    "###########################################\n"
    "###   seccomp config parser test file   ###\n"
    "###########################################\n"
    "\n"
    "# A advanced example for simple c program\n"
    "\n"
    "TYPE WHITELIST\n"
    "ACTION SIGNAL\n"
    "\n"
    "ALLOW read( <= 2 )             # Read from fds\n"
    "ALLOW write( <= 2 )            # Write to fds\n"
    "ALLOW rt_sigreturn             # Called when signal handler return\n"
    "ALLOW exit ()                  # Not exit_group()\n"
    "ALLOW exit_group ()\n"
    "ALLOW brk\n"
    "ALLOW arch_prctl\n"
    "ALLOW openat\n"
    "ALLOW close\n"
    "ALLOW mmap ( , , , & 0xf == 0x2, , )\n"
    "ALLOW mprotect\n"
    "ALLOW munmap\n"
    "ALLOW access\n"
    "ALLOW fstat\n"
    "ALLOW lseek\n"
    "DENY ptrace(!=0)\n"
    "DENY sched_setaffinity\n";

static int write_file(const char *path, const char *data)
{
    int ret = -1;
    FILE *f = fopen(path, "w");
    if (!f) {
        return ret;
    }
    if (fprintf(f, "%s", data) == EOF) {
        goto out;
    }
    if (fflush(f) < 0) {
        goto out;
    }
    ret = 0;
out:
    fclose(f);
    return ret;
}

int cmp(struct seccomp_rule *a, struct seccomp_rule *b)
{
    if (a->type != b->type) {
        return (a->type < b->type ? -1 : 1);
    }
    if (a->syscall != b->syscall) {
        return (a->syscall < b->syscall ? -1 : 1);
    }
    for (int i = 0; i < 6; i++) {
        if (a->args[i].cmp != b->args[i].cmp) {
            return (a->args[i].cmp < b->args[i].cmp ? -1 : 1);
        }
        if (a->args[i].value != b->args[i].value) {
            return (a->args[i].value < b->args[i].value ? -1 : 1);
        }
        if (a->args[i].mask != b->args[i].mask) {
            return (a->args[i].mask < b->args[i].mask ? -1 : 1);
        }
    }
    return 0;
}

static void check_basic_config(struct seccomp_config *cfg)
{
    if (parser_get_err().type) {
        cr_log_error("Parser Error Type: %d; Line: %d\n", parser_get_err().type, parser_get_err().line);
    }
    cr_assert_eq(parser_get_err().type, ErrNone);

    cr_assert_not_null(cfg);
    cr_expect_eq(scconfig_get_type(cfg), CFG_WHITELIST);
    cr_expect_eq(scconfig_get_deny(cfg), DENY_KILL);
    cr_assert_eq(scconfig_len(cfg), 4);

    struct seccomp_rule rules[4];
    memset(rules, 0, sizeof(rules));
    rules[0].type = RULE_ALLOW;
    rules[0].syscall = SCMP_SYS(read);
    rules[1].type = RULE_ALLOW;
    rules[1].syscall = SCMP_SYS(write);
    rules[2].type = RULE_ALLOW;
    rules[2].syscall = SCMP_SYS(rt_sigreturn);
    rules[3].type = RULE_ALLOW;
    rules[3].syscall = SCMP_SYS(exit);

    for (int i = 0; i < 4; i++) {
        cr_expect_eq(cmp(scconfig_get_rule(cfg, i), &rules[i]), 0);
    }
}

static void check_advance_config(struct seccomp_config *cfg)
{
    if (parser_get_err().type) {
        cr_log_error("Parser Error Type: %d; Line: %d\n", parser_get_err().type, parser_get_err().line);
    }
    cr_assert_eq(parser_get_err().type, ErrNone);

    cr_assert_not_null(cfg);
    cr_expect_eq(scconfig_get_type(cfg), CFG_WHITELIST);
    cr_expect_eq(scconfig_get_deny(cfg), DENY_TRAP);
    cr_assert_eq(scconfig_len(cfg), 17);

    struct seccomp_rule rules[17];
    memset(rules, 0, sizeof(rules));
    rules[0].type = RULE_ALLOW;
    rules[0].syscall = SCMP_SYS(read);
    rules[0].args[0] = (struct args_rule) { CMP_LE, 2, 0 };
    rules[1].type = RULE_ALLOW;
    rules[1].syscall = SCMP_SYS(write);
    rules[1].args[0] = (struct args_rule) { CMP_LE, 2, 0 };
    rules[2].type = RULE_ALLOW;
    rules[2].syscall = SCMP_SYS(rt_sigreturn);
    rules[3].type = RULE_ALLOW;
    rules[3].syscall = SCMP_SYS(exit);
    rules[4].type = RULE_ALLOW;
    rules[4].syscall = SCMP_SYS(exit_group);
    rules[5].type = RULE_ALLOW;
    rules[5].syscall = SCMP_SYS(brk);
    rules[6].type = RULE_ALLOW;
    rules[6].syscall = SCMP_SYS(arch_prctl);
    rules[7].type = RULE_ALLOW;
    rules[7].syscall = SCMP_SYS(openat);
    rules[8].type = RULE_ALLOW;
    rules[8].syscall = SCMP_SYS(close);
    rules[9].type = RULE_ALLOW;
    rules[9].syscall = SCMP_SYS(mmap);
    rules[9].args[3] = (struct args_rule) { CMP_MASK, 0x2, 0xf };
    rules[10].type = RULE_ALLOW;
    rules[10].syscall = SCMP_SYS(mprotect);
    rules[11].type = RULE_ALLOW;
    rules[11].syscall = SCMP_SYS(munmap);
    rules[12].type = RULE_ALLOW;
    rules[12].syscall = SCMP_SYS(access);
    rules[13].type = RULE_ALLOW;
    rules[13].syscall = SCMP_SYS(fstat);
    rules[14].type = RULE_ALLOW;
    rules[14].syscall = SCMP_SYS(lseek);
    rules[15].type = RULE_DENY;
    rules[15].syscall = SCMP_SYS(ptrace);
    rules[15].args[0] = (struct args_rule) { CMP_NE, 0x0, 0x0 };
    rules[16].type = RULE_DENY;
    rules[16].syscall = SCMP_SYS(sched_setaffinity);


    for (int i = 0; i < 17; i++) {
        cr_log_info("Checking rule %d...\n", i);
        cr_expect_eq(cmp(scconfig_get_rule(cfg, i), &rules[i]), 0);
    }
}

Test(path_test, test_1)
{
    struct seccomp_config *cfg = scconfig_parse_path(SCCONFIG_PATH, 0);
    check_basic_config(cfg);

    scconfig_free(cfg);
}

void file_setup()
{
    if (write_file(SCCONFIG_PATH, basic_cfg_data) < 0) {
        cr_assert_fail("Failed to write to config file");
    }
}

void file_teardown()
{
    if (unlink(SCCONFIG_PATH)) {
        cr_assert_fail("Failed to remove the config file");
    }
}

Test(fp_test, test_1, .init = file_setup, .fini = file_teardown)
{
    FILE *fp = fopen(SCCONFIG_PATH, "r");
    if (!fp) {
        cr_assert_fail("Failed to open config file\n");
    }

    struct seccomp_config *cfg = scconfig_parse_file(fp, 0);
    check_basic_config(cfg);

    scconfig_free(cfg);
    fclose(fp);
}

Test(string_test, test_1)
{
    struct seccomp_config *cfg = scconfig_parse_string(basic_cfg_data, 0);
    check_basic_config(cfg);

    scconfig_free(cfg);
}

Test(adv_test, test_1)
{
    struct seccomp_config *cfg = scconfig_parse_string(advanced_data, 0);
    check_advance_config(cfg);

    scconfig_free(cfg);
}
