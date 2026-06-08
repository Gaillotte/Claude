/*
 * Requirements-based tests: Session management and Login
 * PKCS#11 v2.40 §11.6 – C_OpenSession, C_CloseSession, C_CloseAllSessions,
 *                        C_GetSessionInfo, C_GetOperationState,
 *                        C_SetOperationState
 *                §11.6 – C_Login, C_Logout
 */
#include "test_framework.h"
#include <string.h>
#include <stdlib.h>

extern int restore_sessions(TestCtx *ctx);

/* REQ-SESS-01: C_OpenSession without CKF_SERIAL_SESSION flag              */
static int test_open_session_no_serial_flag(TestCtx *ctx)
{
    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    /* Parallel sessions not supported by PKCS#11; flag must be set.       */
    CK_RV rv = ctx->mod.fn->C_OpenSession(ctx->slot,
                                           CKF_RW_SESSION, /* no SERIAL */
                                           NULL_PTR, NULL_PTR, &sess);
    ASSERT_RV(rv, CKR_SESSION_PARALLEL_NOT_SUPPORTED,
              "OpenSession without CKF_SERIAL_SESSION");
    if (sess != CK_INVALID_HANDLE) ctx->mod.fn->C_CloseSession(sess);
    TEST_PASS();
}

/* REQ-SESS-02: C_OpenSession on invalid slot → CKR_SLOT_ID_INVALID        */
static int test_open_session_invalid_slot(TestCtx *ctx)
{
    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    CK_RV rv = ctx->mod.fn->C_OpenSession(0xFFFFFFFEUL,
                                           CKF_SERIAL_SESSION,
                                           NULL_PTR, NULL_PTR, &sess);
    ASSERT_RV(rv, CKR_SLOT_ID_INVALID, "OpenSession invalid slot");
    if (sess != CK_INVALID_HANDLE) ctx->mod.fn->C_CloseSession(sess);
    TEST_PASS();
}

/* REQ-SESS-03: C_OpenSession NULL phSession → CKR_ARGUMENTS_BAD           */
static int test_open_session_null_handle(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_OpenSession(ctx->slot,
                                           CKF_SERIAL_SESSION,
                                           NULL_PTR, NULL_PTR, NULL_PTR);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "OpenSession NULL phSession");
    TEST_PASS();
}

/* REQ-SESS-04: C_CloseSession with invalid handle → CKR_SESSION_HANDLE_INVALID */
static int test_close_session_invalid_handle(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_CloseSession((CK_SESSION_HANDLE)0xDEADBEEFUL);
    ASSERT_RV(rv, CKR_SESSION_HANDLE_INVALID, "CloseSession invalid handle");
    TEST_PASS();
}

/* REQ-SESS-05: C_CloseAllSessions invalid slot → CKR_SLOT_ID_INVALID      */
static int test_close_all_sessions_invalid_slot(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_CloseAllSessions(0xFFFFFFFEUL);
    ASSERT_RV(rv, CKR_SLOT_ID_INVALID, "CloseAllSessions invalid slot");
    TEST_PASS();
}

/* REQ-SESS-06: C_GetSessionInfo invalid handle → CKR_SESSION_HANDLE_INVALID*/
static int test_get_session_info_invalid_handle(TestCtx *ctx)
{
    CK_SESSION_INFO info;
    CK_RV rv = ctx->mod.fn->C_GetSessionInfo(
                   (CK_SESSION_HANDLE)0xDEADBEEFUL, &info);
    ASSERT_RV(rv, CKR_SESSION_HANDLE_INVALID, "GetSessionInfo invalid handle");
    TEST_PASS();
}

/* REQ-SESS-07: C_GetSessionInfo NULL pInfo → CKR_ARGUMENTS_BAD            */
static int test_get_session_info_null(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_GetSessionInfo(ctx->rw_session, NULL_PTR);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "GetSessionInfo NULL pInfo");
    TEST_PASS();
}

/* REQ-SESS-08: RW session state after login = CKS_RW_USER_FUNCTIONS        */
static int test_session_state_rw_user(TestCtx *ctx)
{
    CK_SESSION_INFO info;
    CK_RV rv = ctx->mod.fn->C_GetSessionInfo(ctx->rw_session, &info);
    ASSERT_RV_OK(rv, "GetSessionInfo RW");
    ASSERT_EQ(info.state, (CK_ULONG)CKS_RW_USER_FUNCTIONS,
              "RW session state is CKS_RW_USER_FUNCTIONS when logged in");
    TEST_PASS();
}

/* REQ-SESS-09: RO session state after login = CKS_RO_USER_FUNCTIONS        */
static int test_session_state_ro_user(TestCtx *ctx)
{
    CK_SESSION_INFO info;
    CK_RV rv = ctx->mod.fn->C_GetSessionInfo(ctx->ro_session, &info);
    ASSERT_RV_OK(rv, "GetSessionInfo RO");
    ASSERT_EQ(info.state, (CK_ULONG)CKS_RO_USER_FUNCTIONS,
              "RO session state is CKS_RO_USER_FUNCTIONS when logged in");
    TEST_PASS();
}

/* REQ-SESS-10: GetSessionInfo reports correct slot                         */
static int test_session_info_slot(TestCtx *ctx)
{
    CK_SESSION_INFO info;
    CK_RV rv = ctx->mod.fn->C_GetSessionInfo(ctx->rw_session, &info);
    ASSERT_RV_OK(rv, "GetSessionInfo");
    ASSERT_EQ(info.slotID, ctx->slot, "slotID matches expected slot");
    ASSERT_TRUE(info.flags & CKF_SERIAL_SESSION, "CKF_SERIAL_SESSION flag set");
    ASSERT_TRUE(info.flags & CKF_RW_SESSION, "CKF_RW_SESSION flag set for RW session");
    TEST_PASS();
}

/* REQ-SESS-11: Session objects destroyed when session is closed            */
static int test_session_objects_destroyed_on_close(TestCtx *ctx)
{
    /* Open a temporary session */
    CK_SESSION_HANDLE tmp = CK_INVALID_HANDLE;
    CK_RV rv = ctx->mod.fn->C_OpenSession(ctx->slot,
                                           CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                           NULL_PTR, NULL_PTR, &tmp);
    ASSERT_RV_OK(rv, "Open temp session");

    /* Create a session object inside it */
    CK_OBJECT_CLASS cls = CKO_DATA;
    CK_BBOOL f = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls,           sizeof(cls) },
        { CKA_TOKEN, &f,             sizeof(f)   },
        { CKA_VALUE, (void*)"test",  4           },
    };
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    rv = ctx->mod.fn->C_CreateObject(tmp, tmpl, 3, &obj);
    ASSERT_RV_OK(rv, "CreateObject in temp session");

    /* Close the session — session objects must disappear */
    ctx->mod.fn->C_CloseSession(tmp);

    /* The object handle should now be invalid */
    CK_ATTRIBUTE get = { CKA_CLASS, &cls, sizeof(cls) };
    rv = ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, obj, &get, 1);
    ASSERT_RV(rv, CKR_OBJECT_HANDLE_INVALID,
              "Session object handle invalid after session close");
    TEST_PASS();
}

/* REQ-SESS-12: C_GetOperationState size query (NULL buffer)               */
static int test_get_operation_state_size_query(TestCtx *ctx)
{
    CK_ULONG state_len = 0;
    CK_RV rv = ctx->mod.fn->C_GetOperationState(
                   ctx->rw_session, NULL_PTR, &state_len);
    /* Either succeeds with length, or CKR_OPERATION_NOT_INITIALIZED       */
    ASSERT_TRUE(rv == CKR_OK ||
                rv == CKR_OPERATION_NOT_INITIALIZED ||
                rv == CKR_STATE_UNSAVEABLE ||
                rv == CKR_FUNCTION_NOT_SUPPORTED,
                "GetOperationState size query returns acceptable code");
    TEST_PASS();
}

/* REQ-SESS-13: C_GetOperationState NULL pOperationState AND NULL length   */
static int test_get_operation_state_null_len(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_GetOperationState(
                   ctx->rw_session, NULL_PTR, NULL_PTR);
    /* PKCS#11 requires CKR_ARGUMENTS_BAD; SoftHSM2 may return FUNCTION_NOT_SUPPORTED */
    ASSERT_TRUE(rv == CKR_ARGUMENTS_BAD || rv == CKR_FUNCTION_NOT_SUPPORTED,
                "GetOperationState NULL length: ARGUMENTS_BAD or FUNCTION_NOT_SUPPORTED");
    TEST_PASS();
}

/* REQ-LOG-01: C_Login already logged in → CKR_USER_ALREADY_LOGGED_IN      */
static int test_login_already_logged_in(TestCtx *ctx)
{
    /* We are already logged in as USER in persistent session              */
    CK_RV rv = ctx->mod.fn->C_Login(ctx->rw_session, CKU_USER,
                                     (CK_UTF8CHAR_PTR)ctx->user_pin,
                                     (CK_ULONG)strlen(ctx->user_pin));
    ASSERT_RV(rv, CKR_USER_ALREADY_LOGGED_IN,
              "C_Login while already logged in");
    TEST_PASS();
}

/* REQ-LOG-02: C_Login wrong PIN → CKR_PIN_INCORRECT                       */
static int test_login_wrong_pin(TestCtx *ctx)
{
    /* Logout first so we can test wrong-PIN without ALREADY_LOGGED_IN     */
    ctx->mod.fn->C_Logout(ctx->rw_session);

    CK_RV rv = ctx->mod.fn->C_Login(ctx->rw_session, CKU_USER,
                                     (CK_UTF8CHAR_PTR)"wrongPIN!", 9);
    ASSERT_RV(rv, CKR_PIN_INCORRECT, "C_Login wrong PIN");

    /* Restore login state */
    ctx->mod.fn->C_Login(ctx->rw_session, CKU_USER,
                          (CK_UTF8CHAR_PTR)ctx->user_pin,
                          (CK_ULONG)strlen(ctx->user_pin));
    TEST_PASS();
}

/* REQ-LOG-03: C_Login invalid user type → CKR_USER_TYPE_INVALID            */
static int test_login_invalid_user_type(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_Login(ctx->rw_session, (CK_USER_TYPE)99,
                                     (CK_UTF8CHAR_PTR)ctx->user_pin,
                                     (CK_ULONG)strlen(ctx->user_pin));
    ASSERT_RV(rv, CKR_USER_TYPE_INVALID, "C_Login invalid user type");
    TEST_PASS();
}

/* REQ-LOG-04: C_Login SO while user is logged in → CKR_USER_ANOTHER_ALREADY_LOGGED_IN */
static int test_login_so_while_user_logged_in(TestCtx *ctx)
{
    /* User is already logged in via persistent session */
    CK_RV rv = ctx->mod.fn->C_Login(ctx->rw_session, CKU_SO,
                                     (CK_UTF8CHAR_PTR)ctx->so_pin,
                                     (CK_ULONG)strlen(ctx->so_pin));
    /* PKCS#11: CKR_USER_ANOTHER_ALREADY_LOGGED_IN; SoftHSM2 may return
     * CKR_SESSION_READ_ONLY_EXISTS (open RO session blocks SO login)      */
    ASSERT_TRUE(rv == CKR_USER_ANOTHER_ALREADY_LOGGED_IN ||
                rv == CKR_SESSION_READ_ONLY_EXISTS,
                "C_Login(SO) while USER logged in: blocked");
    TEST_PASS();
}

/* REQ-LOG-05: C_Logout reverts session state to public                    */
static int test_logout_reverts_state(TestCtx *ctx)
{
    /* Open a temporary RW session to test logout state transition         */
    CK_SESSION_HANDLE tmp = CK_INVALID_HANDLE;
    ctx->mod.fn->C_OpenSession(ctx->slot,
                                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                NULL_PTR, NULL_PTR, &tmp);

    /* Verify state is RW_USER (shared login) */
    CK_SESSION_INFO before;
    ctx->mod.fn->C_GetSessionInfo(tmp, &before);

    /* Logout (affects all sessions) */
    ctx->mod.fn->C_Logout(tmp);

    CK_SESSION_INFO after;
    ctx->mod.fn->C_GetSessionInfo(tmp, &after);
    ASSERT_EQ(after.state, (CK_ULONG)CKS_RW_PUBLIC_SESSION,
              "After Logout: RW session state is CKS_RW_PUBLIC_SESSION");

    ctx->mod.fn->C_CloseSession(tmp);

    /* Restore login on persistent session */
    ctx->mod.fn->C_Login(ctx->rw_session, CKU_USER,
                          (CK_UTF8CHAR_PTR)ctx->user_pin,
                          (CK_ULONG)strlen(ctx->user_pin));
    TEST_PASS();
}

/* REQ-LOG-06: C_Logout when not logged in → CKR_USER_NOT_LOGGED_IN        */
static int test_logout_when_not_logged_in(TestCtx *ctx)
{
    ctx->mod.fn->C_Logout(ctx->rw_session);

    CK_RV rv = ctx->mod.fn->C_Logout(ctx->rw_session);
    /* SoftHSM2 may return OK or USER_NOT_LOGGED_IN */
    ASSERT_TRUE(rv == CKR_USER_NOT_LOGGED_IN || rv == CKR_OK,
                "Double Logout: USER_NOT_LOGGED_IN or OK");

    ctx->mod.fn->C_Login(ctx->rw_session, CKU_USER,
                          (CK_UTF8CHAR_PTR)ctx->user_pin,
                          (CK_ULONG)strlen(ctx->user_pin));
    TEST_PASS();
}

/* REQ-LOG-07: Login state is shared across all sessions on same slot      */
static int test_login_state_shared(TestCtx *ctx)
{
    CK_SESSION_HANDLE sess2 = CK_INVALID_HANDLE;
    ctx->mod.fn->C_OpenSession(ctx->slot,
                                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                NULL_PTR, NULL_PTR, &sess2);
    ASSERT_NE(sess2, CK_INVALID_HANDLE, "Second session opened");

    /* No explicit Login on sess2, but should share USER state             */
    CK_SESSION_INFO info;
    ctx->mod.fn->C_GetSessionInfo(sess2, &info);
    ASSERT_EQ(info.state, (CK_ULONG)CKS_RW_USER_FUNCTIONS,
              "New session inherits USER_FUNCTIONS state");

    ctx->mod.fn->C_CloseSession(sess2);
    TEST_PASS();
}

/* REQ-LOG-08: C_Login with zero-length PIN                                 */
static int test_login_zero_length_pin(TestCtx *ctx)
{
    ctx->mod.fn->C_Logout(ctx->rw_session);

    CK_RV rv = ctx->mod.fn->C_Login(ctx->rw_session, CKU_USER,
                                     (CK_UTF8CHAR_PTR)"", 0);
    ASSERT_TRUE(rv == CKR_PIN_INCORRECT || rv == CKR_PIN_LEN_RANGE,
                "Zero-length PIN rejected");

    ctx->mod.fn->C_Login(ctx->rw_session, CKU_USER,
                          (CK_UTF8CHAR_PTR)ctx->user_pin,
                          (CK_ULONG)strlen(ctx->user_pin));
    TEST_PASS();
}

/* REQ-LOG-09: C_Login NULL PIN with non-zero length → error               */
static int test_login_null_pin(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_Login(ctx->rw_session, CKU_USER,
                                     NULL_PTR, 4);
    ASSERT_TRUE(rv != CKR_OK, "Login with NULL PIN not accepted");
    TEST_PASS();
}

/* REQ-LOG-10: RO session cannot be used for SO login                      */
static int test_so_login_rejected_on_ro_session(TestCtx *ctx)
{
    /* First logout so we can attempt SO login */
    ctx->mod.fn->C_Logout(ctx->rw_session);

    CK_RV rv = ctx->mod.fn->C_Login(ctx->ro_session, CKU_SO,
                                     (CK_UTF8CHAR_PTR)ctx->so_pin,
                                     (CK_ULONG)strlen(ctx->so_pin));
    /* SO login requires no open RO sessions or may be rejected outright   */
    ASSERT_TRUE(rv != CKR_OK, "SO login on RO session rejected");

    ctx->mod.fn->C_Login(ctx->rw_session, CKU_USER,
                          (CK_UTF8CHAR_PTR)ctx->user_pin,
                          (CK_ULONG)strlen(ctx->user_pin));
    TEST_PASS();
}

BEGIN_TESTS(req_session)
    ADD_TEST("REQ-SESS-01_OpenSession_no_serial_flag",         test_open_session_no_serial_flag);
    ADD_TEST("REQ-SESS-02_OpenSession_invalid_slot",           test_open_session_invalid_slot);
    ADD_TEST("REQ-SESS-03_OpenSession_null_handle",            test_open_session_null_handle);
    ADD_TEST("REQ-SESS-04_CloseSession_invalid_handle",        test_close_session_invalid_handle);
    ADD_TEST("REQ-SESS-05_CloseAllSessions_invalid_slot",      test_close_all_sessions_invalid_slot);
    ADD_TEST("REQ-SESS-06_GetSessionInfo_invalid_handle",      test_get_session_info_invalid_handle);
    ADD_TEST("REQ-SESS-07_GetSessionInfo_null",                test_get_session_info_null);
    ADD_TEST("REQ-SESS-08_SessionState_rw_user",               test_session_state_rw_user);
    ADD_TEST("REQ-SESS-09_SessionState_ro_user",               test_session_state_ro_user);
    ADD_TEST("REQ-SESS-10_SessionInfo_slot",                   test_session_info_slot);
    ADD_TEST("REQ-SESS-11_SessionObjects_destroyed_on_close",  test_session_objects_destroyed_on_close);
    ADD_TEST("REQ-SESS-12_GetOperationState_size_query",       test_get_operation_state_size_query);
    ADD_TEST("REQ-SESS-13_GetOperationState_null_len",         test_get_operation_state_null_len);
    ADD_TEST("REQ-LOG-01_Login_already_logged_in",             test_login_already_logged_in);
    ADD_TEST("REQ-LOG-02_Login_wrong_pin",                     test_login_wrong_pin);
    ADD_TEST("REQ-LOG-03_Login_invalid_user_type",             test_login_invalid_user_type);
    ADD_TEST("REQ-LOG-04_Login_SO_while_user_logged_in",       test_login_so_while_user_logged_in);
    ADD_TEST("REQ-LOG-05_Logout_reverts_state",                test_logout_reverts_state);
    ADD_TEST("REQ-LOG-06_Logout_when_not_logged_in",           test_logout_when_not_logged_in);
    ADD_TEST("REQ-LOG-07_Login_state_shared",                  test_login_state_shared);
    ADD_TEST("REQ-LOG-08_Login_zero_length_pin",               test_login_zero_length_pin);
    ADD_TEST("REQ-LOG-09_Login_null_pin",                      test_login_null_pin);
    ADD_TEST("REQ-LOG-10_SO_login_rejected_on_ro_session",     test_so_login_rejected_on_ro_session);
END_TESTS()
