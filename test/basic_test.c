#define _GNU_SOURCE
#include <cjail/cjail.h>

#include <criterion/assert.h>
#include <criterion/criterion.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

void setup()
{
    if (geteuid()) {
        cr_skip_test("Not running as root!\n");
    }
}

TestSuite(basic_test, .init = setup);

Test(basic_test, test_1)
{
    char *argv[] = { "/bin/echo", NULL };
    struct cjail_para para;
    struct cjail_result result;
    cjail_para_init(&para);
    para.argv = argv;
    cr_assert_eq(cjail_exec(&para, &result), 0);
    cr_expect_eq(result.info.si_code, CLD_EXITED);
    cr_expect_eq(result.info.si_status, EXIT_SUCCESS);
}
