#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <pkcs11.h>
#include "pkcs11_loader.h"
#include "pkcs11_utils.h"
#include <stdio.h>
#include <string.h>

/* Global test state */
typedef struct {
    PKCS11_Module  mod;
    CK_SLOT_ID     slot;
    CK_SESSION_HANDLE rw_session;
    CK_SESSION_HANDLE ro_session;
    char           so_pin[64];
    char           user_pin[64];
    int            pass;
    int            fail;
    int            skip;
} TestCtx;

extern TestCtx g_ctx;

/* Utility: (re)open persistent sessions and log in */
int restore_sessions(TestCtx *ctx);

/* Test registration */
typedef int (*TestFn)(TestCtx *ctx);

typedef struct {
    const char *name;
    const char *group;
    TestFn      fn;
} TestCase;

void test_register(const char *group, const char *name, TestFn fn);
int  test_run_all(int verbose);
int  test_run_group(const char *group, int verbose);

/* Assertion macros */
#define ASSERT_RV(rv, expected, msg) do { \
    if ((rv) != (expected)) { \
        log_fail("FAIL [%s:%d] %s: got %s (0x%lX), expected %s", \
                 __FILE__, __LINE__, msg, pkcs11_rv_str(rv), (unsigned long)(rv), \
                 pkcs11_rv_str(expected)); \
        return -1; \
    } \
} while(0)

#define ASSERT_RV_OK(rv, msg)   ASSERT_RV(rv, CKR_OK, msg)

#define ASSERT_TRUE(cond, msg) do { \
    if (!(cond)) { \
        log_fail("FAIL [%s:%d] %s: condition false", __FILE__, __LINE__, msg); \
        return -1; \
    } \
} while(0)

#define ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { \
        log_fail("FAIL [%s:%d] %s: %ld != %ld", __FILE__, __LINE__, msg, \
                 (long)(a), (long)(b)); \
        return -1; \
    } \
} while(0)

#define ASSERT_NE(a, b, msg) do { \
    if ((a) == (b)) { \
        log_fail("FAIL [%s:%d] %s: values are equal (%ld)", __FILE__, __LINE__, msg, (long)(a)); \
        return -1; \
    } \
} while(0)

#define ASSERT_MEM_EQ(a, b, len, msg) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        log_fail("FAIL [%s:%d] %s: memory mismatch", __FILE__, __LINE__, msg); \
        return -1; \
    } \
} while(0)

#define SKIP(reason) do { \
    log_warn("SKIP: %s", reason); \
    return 1; \
} while(0)

#define TEST_PASS() return 0

#define DECLARE_TESTS(group) void register_tests_##group(void)
#define BEGIN_TESTS(group)   void register_tests_##group(void) { \
    const char *_grp = #group;
#define ADD_TEST(name, fn)   test_register(_grp, name, fn)
#define END_TESTS()          }

#endif /* TEST_FRAMEWORK_H */
