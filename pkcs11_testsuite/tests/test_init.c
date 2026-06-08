#include "test_framework.h"
#include <string.h>
#include <stdlib.h>

/* C_Initialize with NULL args */
static int test_initialize_null(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_Initialize(NULL_PTR);
    ASSERT_RV_OK(rv, "C_Initialize(NULL)");
    rv = ctx->mod.fn->C_Finalize(NULL_PTR);
    ASSERT_RV_OK(rv, "C_Finalize after Initialize(NULL)");
    TEST_PASS();
}

/* C_Initialize twice must return CKR_CRYPTOKI_ALREADY_INITIALIZED */
static int test_initialize_double(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_Initialize(NULL_PTR);
    ASSERT_RV_OK(rv, "First C_Initialize");
    rv = ctx->mod.fn->C_Initialize(NULL_PTR);
    ASSERT_RV(rv, CKR_CRYPTOKI_ALREADY_INITIALIZED, "Second C_Initialize");
    ctx->mod.fn->C_Finalize(NULL_PTR);
    TEST_PASS();
}

/* C_Finalize without Initialize */
static int test_finalize_without_init(TestCtx *ctx)
{
    /* Make sure we are NOT initialized */
    CK_RV rv = ctx->mod.fn->C_Finalize(NULL_PTR);
    ASSERT_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "C_Finalize without init");
    TEST_PASS();
}

/* C_Initialize with CKF_OS_LOCKING_OK flag */
static int test_initialize_os_locking(TestCtx *ctx)
{
    CK_C_INITIALIZE_ARGS args;
    memset(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;

    CK_RV rv = ctx->mod.fn->C_Initialize(&args);
    ASSERT_RV_OK(rv, "C_Initialize with CKF_OS_LOCKING_OK");
    rv = ctx->mod.fn->C_Finalize(NULL_PTR);
    ASSERT_RV_OK(rv, "C_Finalize");
    TEST_PASS();
}

/* C_GetInfo returns valid structure */
static int test_get_info(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_Initialize(NULL_PTR);
    ASSERT_RV_OK(rv, "C_Initialize");

    CK_INFO info;
    memset(&info, 0, sizeof(info));
    rv = ctx->mod.fn->C_GetInfo(&info);
    ASSERT_RV_OK(rv, "C_GetInfo");

    /* PKCS#11 version must be 2.x or 3.x */
    ASSERT_TRUE(info.cryptokiVersion.major >= 2, "cryptokiVersion.major >= 2");
    log_info("  cryptokiVersion: %d.%02d", info.cryptokiVersion.major, info.cryptokiVersion.minor);
    log_info("  manufacturerID: %.32s", info.manufacturerID);
    log_info("  libraryDescription: %.32s", info.libraryDescription);
    log_info("  libraryVersion: %d.%02d", info.libraryVersion.major, info.libraryVersion.minor);

    ctx->mod.fn->C_Finalize(NULL_PTR);
    TEST_PASS();
}

/* C_GetInfo without initialization */
static int test_get_info_not_initialized(TestCtx *ctx)
{
    CK_INFO info;
    CK_RV rv = ctx->mod.fn->C_GetInfo(&info);
    ASSERT_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "C_GetInfo before init");
    TEST_PASS();
}

/* C_GetInfo with NULL pointer */
static int test_get_info_null(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_Initialize(NULL_PTR);
    ASSERT_RV_OK(rv, "C_Initialize");
    rv = ctx->mod.fn->C_GetInfo(NULL_PTR);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "C_GetInfo(NULL)");
    ctx->mod.fn->C_Finalize(NULL_PTR);
    TEST_PASS();
}

/* C_GetFunctionList returns non-NULL list */
static int test_get_function_list(TestCtx *ctx)
{
    CK_FUNCTION_LIST_PTR fn_list = NULL;
    CK_RV rv = ctx->mod.fn->C_GetFunctionList(&fn_list);
    ASSERT_RV_OK(rv, "C_GetFunctionList");
    ASSERT_TRUE(fn_list != NULL, "function list not NULL");
    /* Spot-check a few function pointers */
    ASSERT_TRUE(fn_list->C_Initialize    != NULL, "C_Initialize present");
    ASSERT_TRUE(fn_list->C_OpenSession   != NULL, "C_OpenSession present");
    ASSERT_TRUE(fn_list->C_EncryptInit   != NULL, "C_EncryptInit present");
    ASSERT_TRUE(fn_list->C_SignInit      != NULL, "C_SignInit present");
    TEST_PASS();
}

/* C_GetFunctionList with NULL */
static int test_get_function_list_null(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_GetFunctionList(NULL_PTR);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "C_GetFunctionList(NULL)");
    TEST_PASS();
}

/* Public helper used by tests that close all sessions */
int restore_sessions(TestCtx *ctx);

/* Helper: open persistent sessions and login */
static int open_persistent_sessions(TestCtx *ctx)
{
    /* Close stale sessions if any */
    if (ctx->rw_session != CK_INVALID_HANDLE) {
        ctx->mod.fn->C_CloseSession(ctx->rw_session);
        ctx->rw_session = CK_INVALID_HANDLE;
    }
    if (ctx->ro_session != CK_INVALID_HANDLE) {
        ctx->mod.fn->C_CloseSession(ctx->ro_session);
        ctx->ro_session = CK_INVALID_HANDLE;
    }

    CK_RV rv = ctx->mod.fn->C_OpenSession(ctx->slot,
                                    CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                    NULL_PTR, NULL_PTR, &ctx->rw_session);
    if (rv != CKR_OK) { log_error("Open RW session: %s", pkcs11_rv_str(rv)); return -1; }

    rv = ctx->mod.fn->C_OpenSession(ctx->slot,
                                    CKF_SERIAL_SESSION,
                                    NULL_PTR, NULL_PTR, &ctx->ro_session);
    if (rv != CKR_OK) { log_error("Open RO session: %s", pkcs11_rv_str(rv)); return -1; }

    rv = ctx->mod.fn->C_Login(ctx->rw_session, CKU_USER,
                               (CK_UTF8CHAR_PTR)ctx->user_pin,
                               (CK_ULONG)strlen(ctx->user_pin));
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
        log_error("C_Login user: %s", pkcs11_rv_str(rv));
        return -1;
    }
    return 0;
}

/* Persistent initialization used by all following tests */
static int test_initialize_persistent(TestCtx *ctx)
{
    /* Use OS locking for multi-threaded tests */
    CK_C_INITIALIZE_ARGS args;
    memset(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    CK_RV rv = ctx->mod.fn->C_Initialize(&args);
    ASSERT_RV_OK(rv, "C_Initialize persistent");

    /* First try: find an INITIALIZED token slot */
    CK_ULONG slot_count = 0;
    rv = ctx->mod.fn->C_GetSlotList(CK_TRUE, NULL_PTR, &slot_count);
    if (rv == CKR_OK && slot_count > 0) {
        CK_SLOT_ID *slots = malloc(slot_count * sizeof(CK_SLOT_ID));
        rv = ctx->mod.fn->C_GetSlotList(CK_TRUE, slots, &slot_count);
        ASSERT_RV_OK(rv, "C_GetSlotList fill");

        /* Find an initialized token among the slots */
        ctx->slot = CK_UNAVAILABLE_INFORMATION;
        for (CK_ULONG i = 0; i < slot_count; i++) {
            CK_TOKEN_INFO ti;
            if (ctx->mod.fn->C_GetTokenInfo(slots[i], &ti) == CKR_OK &&
                (ti.flags & CKF_TOKEN_INITIALIZED)) {
                ctx->slot = slots[i];
                break;
            }
        }
        free(slots);

        if (ctx->slot == CK_UNAVAILABLE_INFORMATION) {
            /* All tokens are uninitialized — fall through to init */
            goto need_init;
        }
        log_info("Found existing initialized token on slot %lu", ctx->slot);
    } else {
need_init:;
        /* No initialized token — find a free slot and initialize one */
        rv = ctx->mod.fn->C_GetSlotList(CK_FALSE, NULL_PTR, &slot_count);
        ASSERT_RV_OK(rv, "C_GetSlotList all");
        ASSERT_TRUE(slot_count > 0, "At least one slot exists");

        CK_SLOT_ID *slots = malloc(slot_count * sizeof(CK_SLOT_ID));
        rv = ctx->mod.fn->C_GetSlotList(CK_FALSE, slots, &slot_count);
        ASSERT_RV_OK(rv, "C_GetSlotList fill");
        ctx->slot = slots[0];
        free(slots);

        if (pkcs11_init_token(ctx->mod.fn, ctx->slot, "TestToken",
                              ctx->so_pin, ctx->user_pin) != 0) {
            log_error("Failed to init token on slot %lu", ctx->slot);
            return -1;
        }
        log_info("Initialized token on slot %lu", ctx->slot);

        /* SoftHSM reassigns slot ID after init — re-read */
        slot_count = 0;
        rv = ctx->mod.fn->C_GetSlotList(CK_TRUE, NULL_PTR, &slot_count);
        ASSERT_RV_OK(rv, "C_GetSlotList after init");
        ASSERT_TRUE(slot_count > 0, "Token slot present");
        CK_SLOT_ID *tslots = malloc(slot_count * sizeof(CK_SLOT_ID));
        rv = ctx->mod.fn->C_GetSlotList(CK_TRUE, tslots, &slot_count);
        ASSERT_RV_OK(rv, "C_GetSlotList fill token");
        ctx->slot = tslots[0];
        free(tslots);
    }

    log_info("Using slot %lu for tests", ctx->slot);

    ASSERT_EQ(open_persistent_sessions(ctx), 0, "Open persistent sessions");
    log_ok("Persistent sessions ready (slot=%lu)", ctx->slot);
    TEST_PASS();
}

int restore_sessions(TestCtx *ctx)
{
    return open_persistent_sessions(ctx);
}

BEGIN_TESTS(init)
    ADD_TEST("C_Finalize_without_init",      test_finalize_without_init);
    ADD_TEST("C_GetFunctionList",            test_get_function_list);
    ADD_TEST("C_GetFunctionList_null",       test_get_function_list_null);
    ADD_TEST("C_Initialize_null",            test_initialize_null);
    ADD_TEST("C_Initialize_os_locking",      test_initialize_os_locking);
    ADD_TEST("C_Initialize_double",          test_initialize_double);
    ADD_TEST("C_GetInfo_not_initialized",    test_get_info_not_initialized);
    ADD_TEST("C_GetInfo",                    test_get_info);
    ADD_TEST("C_GetInfo_null",               test_get_info_null);
    /* This test must run last in the group — it leaves cryptoki initialized */
    ADD_TEST("Initialize_persistent_state", test_initialize_persistent);
END_TESTS()
