#include "test_framework.h"
#include <string.h>

static int test_login_already_logged_in(TestCtx *ctx)
{
    /* g_ctx.rw_session is already logged in as user */
    CK_RV rv = ctx->mod.fn->C_Login(ctx->rw_session, CKU_USER,
                                     (CK_UTF8CHAR_PTR)ctx->user_pin,
                                     (CK_ULONG)strlen(ctx->user_pin));
    ASSERT_RV(rv, CKR_USER_ALREADY_LOGGED_IN, "Login when already logged in");
    TEST_PASS();
}

static int test_login_wrong_pin(TestCtx *ctx)
{
    /* Must log out first — PKCS#11 login state is per-token, not per-session */
    ctx->mod.fn->C_Logout(ctx->rw_session);

    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    int result = 0;
    CK_RV rv = ctx->mod.fn->C_OpenSession(ctx->slot,
                                           CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                           NULL_PTR, NULL_PTR, &sess);
    if (rv != CKR_OK) { log_fail("Open session: %s", pkcs11_rv_str(rv)); result = -1; goto restore; }

    rv = ctx->mod.fn->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR)"wrongpin", 8);
    if (rv != CKR_PIN_INCORRECT) {
        log_fail("Login wrong pin: got %s, expected CKR_PIN_INCORRECT", pkcs11_rv_str(rv));
        result = -1;
    }
    ctx->mod.fn->C_CloseSession(sess);

restore:
    ctx->mod.fn->C_Login(ctx->rw_session, CKU_USER,
                          (CK_UTF8CHAR_PTR)ctx->user_pin,
                          (CK_ULONG)strlen(ctx->user_pin));
    return result;
}

static int test_login_null_pin(TestCtx *ctx)
{
    ctx->mod.fn->C_Logout(ctx->rw_session);

    int result = 0;
    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    ctx->mod.fn->C_OpenSession(ctx->slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sess);
    CK_RV rv = ctx->mod.fn->C_Login(sess, CKU_USER, NULL_PTR, 0);
    if (rv == CKR_OK) { log_fail("Login with NULL pin should fail"); result = -1; }
    ctx->mod.fn->C_CloseSession(sess);

    ctx->mod.fn->C_Login(ctx->rw_session, CKU_USER,
                          (CK_UTF8CHAR_PTR)ctx->user_pin,
                          (CK_ULONG)strlen(ctx->user_pin));
    return result;
}

static int test_logout(TestCtx *ctx)
{
    /* Log out on rw_session and log back in */
    CK_RV rv = ctx->mod.fn->C_Logout(ctx->rw_session);
    ASSERT_RV_OK(rv, "C_Logout");

    rv = ctx->mod.fn->C_Login(ctx->rw_session, CKU_USER,
                               (CK_UTF8CHAR_PTR)ctx->user_pin,
                               (CK_ULONG)strlen(ctx->user_pin));
    ASSERT_RV_OK(rv, "Re-login after logout");
    TEST_PASS();
}

static int test_logout_not_logged_in(TestCtx *ctx)
{
    /* Logout global session first so token-wide state is logged out */
    ctx->mod.fn->C_Logout(ctx->rw_session);

    int result = 0;
    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    ctx->mod.fn->C_OpenSession(ctx->slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sess);
    CK_RV rv = ctx->mod.fn->C_Logout(sess);
    /* SoftHSM2 may return CKR_OK (no-op) or CKR_USER_NOT_LOGGED_IN */
    if (rv != CKR_USER_NOT_LOGGED_IN && rv != CKR_OK) {
        log_fail("C_Logout not-logged-in: unexpected %s", pkcs11_rv_str(rv));
        result = -1;
    } else {
        log_info("  C_Logout when not logged in returned: %s", pkcs11_rv_str(rv));
    }
    ctx->mod.fn->C_CloseSession(sess);

    ctx->mod.fn->C_Login(ctx->rw_session, CKU_USER,
                          (CK_UTF8CHAR_PTR)ctx->user_pin,
                          (CK_ULONG)strlen(ctx->user_pin));
    return result;
}

static int test_login_invalid_user_type(TestCtx *ctx)
{
    CK_SESSION_HANDLE sess;
    ctx->mod.fn->C_OpenSession(ctx->slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sess);
    CK_RV rv = ctx->mod.fn->C_Login(sess, 99,
                                     (CK_UTF8CHAR_PTR)ctx->user_pin, 4);
    ASSERT_RV(rv, CKR_USER_TYPE_INVALID, "Login with invalid user type");
    ctx->mod.fn->C_CloseSession(sess);
    TEST_PASS();
}

static int test_login_invalid_session(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_Login(0xDEADBEEF, CKU_USER,
                                     (CK_UTF8CHAR_PTR)ctx->user_pin, 4);
    ASSERT_RV(rv, CKR_SESSION_HANDLE_INVALID, "Login with invalid session");
    TEST_PASS();
}

static int test_set_pin(TestCtx *ctx)
{
    const char *new_pin = "5678";
    const char *old_pin = ctx->user_pin;

    int result = 0;
    CK_RV rv = ctx->mod.fn->C_SetPIN(ctx->rw_session,
                                      (CK_UTF8CHAR_PTR)old_pin, (CK_ULONG)strlen(old_pin),
                                      (CK_UTF8CHAR_PTR)new_pin, (CK_ULONG)strlen(new_pin));
    if (rv != CKR_OK) {
        log_fail("C_SetPIN change: %s", pkcs11_rv_str(rv));
        result = -1;
        /* Don't try to restore if we didn't change */
        return result;
    }

    /* Restore original — always do this even if earlier step failed */
    rv = ctx->mod.fn->C_SetPIN(ctx->rw_session,
                                (CK_UTF8CHAR_PTR)new_pin, (CK_ULONG)strlen(new_pin),
                                (CK_UTF8CHAR_PTR)old_pin, (CK_ULONG)strlen(old_pin));
    if (rv != CKR_OK) {
        log_fail("C_SetPIN restore: %s", pkcs11_rv_str(rv));
        result = -1;
    }
    return result;
}

static int test_set_pin_wrong_old(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_SetPIN(ctx->rw_session,
                                      (CK_UTF8CHAR_PTR)"badpin", 6,
                                      (CK_UTF8CHAR_PTR)"newpin", 6);
    ASSERT_RV(rv, CKR_PIN_INCORRECT, "C_SetPIN with wrong old PIN");
    TEST_PASS();
}

BEGIN_TESTS(login)
    ADD_TEST("C_Login_already_logged_in",    test_login_already_logged_in);
    ADD_TEST("C_Login_wrong_pin",            test_login_wrong_pin);
    ADD_TEST("C_Login_null_pin",             test_login_null_pin);
    ADD_TEST("C_Login_invalid_user_type",    test_login_invalid_user_type);
    ADD_TEST("C_Login_invalid_session",      test_login_invalid_session);
    ADD_TEST("C_Logout",                     test_logout);
    ADD_TEST("C_Logout_not_logged_in",       test_logout_not_logged_in);
    ADD_TEST("C_SetPIN",                     test_set_pin);
    ADD_TEST("C_SetPIN_wrong_old",           test_set_pin_wrong_old);
END_TESTS()
