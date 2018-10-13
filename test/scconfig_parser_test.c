#include "cjail.h"
#include "scconfig_parser.h"

#include <check.h>
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

static void check_basic_config(struct seccomp_config *cfg)
{
    fprintf(stderr, "Parser Error Type: %d; Line: %d\n", parser_get_err().type, parser_get_err().line);

    ck_assert_ptr_nonnull(cfg);
    ck_assert_int_eq(scconfig_get_type(cfg), CFG_WHITELIST);
    ck_assert_int_eq(scconfig_get_deny(cfg), DENY_KILL);
    ck_assert_int_eq(scconfig_len(cfg), 4);

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
        ck_assert_mem_eq(scconfig_get_rule(cfg, i), &rules[i], sizeof(struct seccomp_rule));
    }
}

START_TEST(path_test_1)
{
    struct seccomp_config *cfg = scconfig_parse_path(SCCONFIG_PATH, 0);
    check_basic_config(cfg);

    scconfig_free(cfg);
}
END_TEST

START_TEST(fp_test_1)
{
    FILE *fp = fopen(SCCONFIG_PATH, "r");
    if (!fp) {
        ck_abort_msg("Failed to open config file");
    }

    struct seccomp_config *cfg = scconfig_parse_file(fp, 0);
    check_basic_config(cfg);

    scconfig_free(cfg);
    fclose(fp);
}
END_TEST

START_TEST(string_test_1)
{
    struct seccomp_config *cfg = scconfig_parse_string(basic_cfg_data, 0);
    check_basic_config(cfg);

    scconfig_free(cfg);
}
END_TEST

Suite* suite()
{
    Suite *s = suite_create("scconfig_parser");

    TCase *t_path = tcase_create("by_path");
    TCase *t_fp = tcase_create("by_fp");
    TCase *t_string = tcase_create("by_string");

    tcase_add_test(t_path, path_test_1);
    tcase_add_test(t_fp, fp_test_1);
    tcase_add_test(t_string, string_test_1);

    suite_add_tcase(s, t_path);
    suite_add_tcase(s, t_fp);
    suite_add_tcase(s, t_string);
    return s;
}

int main()
{
    //Extract file
    if (write_file(SCCONFIG_PATH, basic_cfg_data) < 0) {
        ck_abort_msg("Failed to write to config file");
    }

    int number_failed;
    Suite *s;
    SRunner *sr;

    s = suite();
    sr = srunner_create(s);

    #ifdef NDEBUG
    srunner_run_all(sr, CK_NORMAL);
    #else
    srunner_run_all(sr, CK_VERBOSE);
    #endif
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
