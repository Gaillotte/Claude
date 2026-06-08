#include "test_framework.h"
#include <string.h>

static int test_open_close_session(TestCtx *ctx)
{
    CK_SESSION_HANDLE sess;
    CK_RV rv = ctx->mod.fn->C_OpenSession(ctx->slot,
                                           CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                           NULL_PTR, NULL_PTR, &sess);
    ASSERT_RV_OK(rv, "C_OpenSession RW");
    ASSERT_NE(sess, CK_INVALID_HANDLE, "session handle valid");

    rv = ctx->mod.fn->C_CloseSession(sess);
    ASSERT_RV_OK(rv, "C_CloseSession");
    TEST_PASS();
}

static int test_open_ro_session(TestCtx *ctx)
{
    CK_SESSION_HANDLE sess;
    CK_RV rv = ctx->mod.fn->C_OpenSession(ctx->slot,
                                           CKF_SERIAL_SESSION,
                                           NULL_PTR, NULL_PTR, &sess);
    ASSERT_RV_OK(rv, "C_OpenSession RO");
    rv = ctx->mod.fn->C_CloseSession(sess);
    ASSERT_RV_OK(rv, "C_CloseSession RO");
    TEST_PASS();
}

static int test_open_session_invalid_slot(TestCtx *ctx)
{
    CK_SESSION_HANDLE sess;
    CK_RV rv = ctx->mod.fn->C_OpenSession(0xDEADBEEF,
                                           CKF_SERIAL_SESSION,
                                           NULL_PTR, NULL_PTR, &sess);
    ASSERT_RV(rv, CKR_SLOT_ID_INVALID, "C_OpenSession invalid slot");
    TEST_PASS();
}

static int test_open_session_null_handle(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_OpenSession(ctx->slot,
                                           CKF_SERIAL_SESSION,
                                           NULL_PTR, NULL_PTR, NULL_PTR);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "C_OpenSession NULL handle");
    TEST_PASS();
}

static int test_close_invalid_session(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_CloseSession(0xDEADBEEF);
    ASSERT_RV(rv, CKR_SESSION_HANDLE_INVALID, "C_CloseSession invalid handle");
    TEST_PASS();
}

static int test_close_all_sessions(TestCtx *ctx)
{
    /* Open a few extra sessions */
    CK_SESSION_HANDLE s1, s2;
    ctx->mod.fn->C_OpenSession(ctx->slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &s1);
    ctx->mod.fn->C_OpenSession(ctx->slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &s2);

    /* Mark persistent handles as invalid before closing */
    ctx->rw_session = CK_INVALID_HANDLE;
    ctx->ro_session = CK_INVALID_HANDLE;

    CK_RV rv = ctx->mod.fn->C_CloseAllSessions(ctx->slot);
    ASSERT_RV_OK(rv, "C_CloseAllSessions");

    /* Restore persistent sessions */
    ASSERT_EQ(restore_sessions(ctx), 0, "Re-open sessions after CloseAllSessions");
    TEST_PASS();
}

static int test_get_session_info(TestCtx *ctx)
{
    CK_SESSION_INFO info;
    CK_RV rv = ctx->mod.fn->C_GetSessionInfo(ctx->rw_session, &info);
    ASSERT_RV_OK(rv, "C_GetSessionInfo RW");
    ASSERT_EQ(info.slotID, ctx->slot, "slotID matches");
    ASSERT_TRUE(info.flags & CKF_RW_SESSION, "RW_SESSION flag set");
    ASSERT_TRUE(info.flags & CKF_SERIAL_SESSION, "SERIAL_SESSION flag set");
    log_info("  RW session state: %lu, flags: 0x%lX", info.state, info.flags);

    rv = ctx->mod.fn->C_GetSessionInfo(ctx->ro_session, &info);
    ASSERT_RV_OK(rv, "C_GetSessionInfo RO");
    ASSERT_TRUE(!(info.flags & CKF_RW_SESSION), "RO session not RW");
    TEST_PASS();
}

static int test_get_session_info_invalid(TestCtx *ctx)
{
    CK_SESSION_INFO info;
    CK_RV rv = ctx->mod.fn->C_GetSessionInfo(0xDEADBEEF, &info);
    ASSERT_RV(rv, CKR_SESSION_HANDLE_INVALID, "C_GetSessionInfo invalid session");
    TEST_PASS();
}

static int test_get_session_info_null(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_GetSessionInfo(ctx->rw_session, NULL_PTR);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "C_GetSessionInfo NULL");
    TEST_PASS();
}

static int test_get_operation_state(TestCtx *ctx)
{
    CK_ULONG state_len = 0;
    CK_RV rv = ctx->mod.fn->C_GetOperationState(ctx->rw_session, NULL_PTR, &state_len);
    /* Any return value is acceptable when no operation is active */
    log_info("  C_GetOperationState (idle): %s (0x%lX)", pkcs11_rv_str(rv), rv);
    TEST_PASS();
}

static int test_set_operation_state_invalid(TestCtx *ctx)
{
    unsigned char fake_state[16] = {0};
    CK_RV rv = ctx->mod.fn->C_SetOperationState(ctx->rw_session,
                                                  fake_state, sizeof(fake_state),
                                                  CK_INVALID_HANDLE, CK_INVALID_HANDLE);
    ASSERT_TRUE(rv != CKR_OK, "C_SetOperationState with fake state should fail");
    TEST_PASS();
}

BEGIN_TESTS(session)
    ADD_TEST("C_OpenSession_RW",            test_open_close_session);
    ADD_TEST("C_OpenSession_RO",            test_open_ro_session);
    ADD_TEST("C_OpenSession_invalid_slot",  test_open_session_invalid_slot);
    ADD_TEST("C_OpenSession_null_handle",   test_open_session_null_handle);
    ADD_TEST("C_CloseSession_invalid",      test_close_invalid_session);
    ADD_TEST("C_CloseAllSessions",          test_close_all_sessions);
    ADD_TEST("C_GetSessionInfo",            test_get_session_info);
    ADD_TEST("C_GetSessionInfo_invalid",    test_get_session_info_invalid);
    ADD_TEST("C_GetSessionInfo_null",       test_get_session_info_null);
    ADD_TEST("C_GetOperationState",         test_get_operation_state);
    ADD_TEST("C_SetOperationState_invalid", test_set_operation_state_invalid);
END_TESTS()
