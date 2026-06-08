#include "test_framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Global test context */
TestCtx g_ctx;

/* Test registry */
#define MAX_TESTS 512
static TestCase g_tests[MAX_TESTS];
static int      g_test_count = 0;

void test_register(const char *group, const char *name, TestFn fn)
{
    if (g_test_count >= MAX_TESTS) {
        fprintf(stderr, "Too many tests registered\n");
        return;
    }
    g_tests[g_test_count].group = group;
    g_tests[g_test_count].name  = name;
    g_tests[g_test_count].fn    = fn;
    g_test_count++;
}

static void abort_active_ops(CK_FUNCTION_LIST_PTR fn, CK_SESSION_HANDLE sess)
{
    if (sess == CK_INVALID_HANDLE) return;
    /* Attempt to abort any leftover active operations.
     * For multi-part ops, feed an empty update first so the state machine
     * accepts the Final call. If the operation isn't active the calls return
     * CKR_OPERATION_NOT_INITIALIZED (ignored). */
    unsigned char dummy[4096]; CK_ULONG dummy_len;
    unsigned char empty[1] = {0};
    /* Encrypt: try single-shot abort, then update+final */
    dummy_len = sizeof(dummy);
    if (fn->C_EncryptFinal(sess, dummy, &dummy_len) == CKR_OPERATION_ACTIVE) {
        dummy_len = sizeof(dummy);
        fn->C_EncryptUpdate(sess, empty, 0, dummy, &dummy_len);
        dummy_len = sizeof(dummy);
        fn->C_EncryptFinal(sess, dummy, &dummy_len);
    }
    /* Decrypt */
    dummy_len = sizeof(dummy);
    if (fn->C_DecryptFinal(sess, dummy, &dummy_len) == CKR_OPERATION_ACTIVE) {
        dummy_len = sizeof(dummy);
        fn->C_DecryptUpdate(sess, empty, 0, dummy, &dummy_len);
        dummy_len = sizeof(dummy);
        fn->C_DecryptFinal(sess, dummy, &dummy_len);
    }
    dummy_len = sizeof(dummy);
    fn->C_DigestFinal(sess, dummy, &dummy_len);
    dummy_len = sizeof(dummy);
    fn->C_SignFinal(sess, dummy, &dummy_len);
    fn->C_VerifyFinal(sess, dummy, 0);
    fn->C_FindObjectsFinal(sess);
}

static void run_test(TestCase *tc, int verbose)
{
    if (verbose) log_info("Running [%s] %s", tc->group, tc->name);

    /* Abort any operations left over by the previous test */
    abort_active_ops(g_ctx.mod.fn, g_ctx.rw_session);
    abort_active_ops(g_ctx.mod.fn, g_ctx.ro_session);

    int ret = tc->fn(&g_ctx);
    if (ret == 0) {
        g_ctx.pass++;
        log_ok("[%s] %s", tc->group, tc->name);
    } else if (ret == 1) {
        g_ctx.skip++;
        log_warn("SKIP [%s] %s", tc->group, tc->name);
    } else {
        g_ctx.fail++;
        log_fail("[%s] %s", tc->group, tc->name);
    }
}

int test_run_all(int verbose)
{
    for (int i = 0; i < g_test_count; i++) {
        run_test(&g_tests[i], verbose);
    }
    return g_ctx.fail;
}

int test_run_group(const char *group, int verbose)
{
    for (int i = 0; i < g_test_count; i++) {
        if (strcmp(g_tests[i].group, group) == 0) {
            run_test(&g_tests[i], verbose);
        }
    }
    return g_ctx.fail;
}

/* External test registration functions */
DECLARE_TESTS(init);
DECLARE_TESTS(slot_token);
DECLARE_TESTS(session);
DECLARE_TESTS(login);
DECLARE_TESTS(objects);
DECLARE_TESTS(crypto_sym);
DECLARE_TESTS(crypto_asym);
DECLARE_TESTS(digest);
DECLARE_TESTS(random);
DECLARE_TESTS(key_generation);
DECLARE_TESTS(wrap_unwrap);
DECLARE_TESTS(derive);
DECLARE_TESTS(dual_function);
DECLARE_TESTS(parallel);
DECLARE_TESTS(edge_cases);
DECLARE_TESTS(req_general);
DECLARE_TESTS(req_session);
DECLARE_TESTS(req_objects);
DECLARE_TESTS(req_crypto);

static void print_banner(void)
{
    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║          PKCS#11 Test Suite (SoftHSM2 target)        ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");
}

static void print_summary(void)
{
    int total = g_ctx.pass + g_ctx.fail + g_ctx.skip;
    printf("\n");
    printf("══════════════════════════════════════════════════════\n");
    printf("  Results:  PASS=%-4d  FAIL=%-4d  SKIP=%-4d  TOTAL=%-4d\n",
           g_ctx.pass, g_ctx.fail, g_ctx.skip, total);
    printf("══════════════════════════════════════════════════════\n\n");
}

static void usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("  -l <lib>      PKCS#11 library path (default: /usr/lib/softhsm/libsofthsm2.so)\n");
    printf("  -s <slot>     Slot index (default: 0)\n");
    printf("  -p <user_pin> User PIN (default: 1234)\n");
    printf("  -P <so_pin>   SO PIN (default: 1234)\n");
    printf("  -g <group>    Run only tests in <group>\n");
    printf("  -v            Verbose output\n");
    printf("  -h            Show help\n");
}

int main(int argc, char *argv[])
{
    const char *lib_path  = "/usr/lib/softhsm/libsofthsm2.so";
    const char *group     = NULL;
    int         verbose   = 0;
    int         opt;

    memset(&g_ctx, 0, sizeof(g_ctx));
    strncpy(g_ctx.so_pin,   "1234", sizeof(g_ctx.so_pin) - 1);
    strncpy(g_ctx.user_pin, "1234", sizeof(g_ctx.user_pin) - 1);

    while ((opt = getopt(argc, argv, "l:s:p:P:g:vh")) != -1) {
        switch (opt) {
            case 'l': lib_path = optarg; break;
            case 's': g_ctx.slot = (CK_SLOT_ID)atoi(optarg); break;
            case 'p': strncpy(g_ctx.user_pin, optarg, sizeof(g_ctx.user_pin) - 1); break;
            case 'P': strncpy(g_ctx.so_pin,   optarg, sizeof(g_ctx.so_pin)   - 1); break;
            case 'g': group = optarg; break;
            case 'v': verbose = 1; break;
            case 'h': usage(argv[0]); return 0;
            default:  usage(argv[0]); return 1;
        }
    }

    print_banner();

    /* Load library */
    log_info("Loading PKCS#11 library: %s", lib_path);
    if (pkcs11_load(&g_ctx.mod, lib_path) != 0) {
        log_error("Failed to load library");
        return 2;
    }
    log_ok("Library loaded");

    /* Register all test groups */
    register_tests_init();
    register_tests_slot_token();
    register_tests_session();
    register_tests_login();
    register_tests_objects();
    register_tests_crypto_sym();
    register_tests_crypto_asym();
    register_tests_digest();
    register_tests_random();
    register_tests_key_generation();
    register_tests_wrap_unwrap();
    register_tests_derive();
    register_tests_dual_function();
    register_tests_parallel();
    register_tests_edge_cases();
    register_tests_req_general();
    register_tests_req_session();
    register_tests_req_objects();
    register_tests_req_crypto();

    log_info("Registered %d tests", g_test_count);
    printf("\n");

    /* Run tests */
    if (group)
        test_run_group(group, verbose);
    else
        test_run_all(verbose);

    print_summary();

    pkcs11_unload(&g_ctx.mod);
    return g_ctx.fail > 0 ? 1 : 0;
}
