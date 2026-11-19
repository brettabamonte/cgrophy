#include "sha1.h"
#include "sha256.h"
#include "test.h"

#include <stdio.h>

#define run(test) \
    do {\
        printf("\033[38;5;3m%s\033[0m\n\n", (test).name); \
        res = (test).run(); \
        printf("\n\033[32mPass: %d\033[0m\n", res.pass); \
        printf("\033[31mFail: %d\033[0m\n", res.fail); \
        printf("Total: %d\n\n", res.total); \
    }\
    while(0)

#ifdef SHA1_TEST
extern TestSuite sha1_test_suite;
#endif
#ifdef SHA256_TEST
extern TestSuite sha256_test_suite;
#endif
#ifdef HMAC_TEST
extern TestSuite hmac_test_suite;
#endif

int main(int argc, char argv)
{
    (void)argc;
    (void)argv;

    TestSuiteResult res;

    printf("\033[38;5;3mCgrophy Test Suite\033[0m\n\n");
#ifdef SHA1_TEST
    run(sha1_test_suite);
#endif
#ifdef SHA256_TEST
    run(sha256_test_suite);
#endif
#ifdef HMAC_TEST
    run(hmac_test_suite);
#endif
    return 0;
}
