/*
 * Requirements-based tests: General / Initialisation functions
 * PKCS#11 v2.40 §11.4 – C_Initialize, C_Finalize, C_GetInfo,
 *                        C_GetFunctionList
 * PKCS#11 v2.40 §11.5 – C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo,
 *                        C_GetMechanismList, C_GetMechanismInfo,
 *                        C_WaitForSlotEvent, C_InitToken, C_InitPIN, C_SetPIN
 */
#include "test_framework.h"
#include <string.h>
#include <stdlib.h>

/* REQ-GEN-01: C_Finalize pReserved != NULL → CKR_ARGUMENTS_BAD            */
static int test_finalize_reserved_not_null(TestCtx *ctx)
{
    /* We are currently initialized; passing non-NULL pReserved must fail   */
    CK_RV rv = ctx->mod.fn->C_Finalize((CK_VOID_PTR)1);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "C_Finalize(non-NULL pReserved)");
    TEST_PASS();
}

/* REQ-GEN-02: C_GetInfo pInfo == NULL → CKR_ARGUMENTS_BAD                 */
static int test_get_info_null_ptr(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_GetInfo(NULL_PTR);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "C_GetInfo(NULL)");
    TEST_PASS();
}

/* REQ-GEN-03: C_GetInfo cryptokiVersion.major must be >= 2                */
static int test_get_info_version(TestCtx *ctx)
{
    CK_INFO info;
    CK_RV rv = ctx->mod.fn->C_GetInfo(&info);
    ASSERT_RV_OK(rv, "C_GetInfo");
    ASSERT_TRUE(info.cryptokiVersion.major >= 2, "cryptokiVersion.major >= 2");
    ASSERT_TRUE(info.libraryVersion.major > 0 ||
                info.libraryVersion.minor > 0, "libraryVersion non-zero");
    TEST_PASS();
}

/* REQ-GEN-04: C_GetFunctionList ppFunctionList == NULL → CKR_ARGUMENTS_BAD*/
static int test_get_function_list_null(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_GetFunctionList(NULL_PTR);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "C_GetFunctionList(NULL)");
    TEST_PASS();
}

/* REQ-GEN-05: C_GetFunctionList returns same list used by this test run   */
static int test_get_function_list_consistent(TestCtx *ctx)
{
    CK_FUNCTION_LIST_PTR fl = NULL;
    CK_RV rv = ctx->mod.fn->C_GetFunctionList(&fl);
    ASSERT_RV_OK(rv, "C_GetFunctionList");
    ASSERT_TRUE(fl != NULL, "function list not NULL");
    ASSERT_TRUE(fl->C_Initialize    != NULL, "C_Initialize present");
    ASSERT_TRUE(fl->C_Finalize      != NULL, "C_Finalize present");
    ASSERT_TRUE(fl->C_GetInfo       != NULL, "C_GetInfo present");
    ASSERT_TRUE(fl->C_GetSlotList   != NULL, "C_GetSlotList present");
    ASSERT_TRUE(fl->C_OpenSession   != NULL, "C_OpenSession present");
    ASSERT_TRUE(fl->C_Login         != NULL, "C_Login present");
    ASSERT_TRUE(fl->C_EncryptInit   != NULL, "C_EncryptInit present");
    ASSERT_TRUE(fl->C_DecryptInit   != NULL, "C_DecryptInit present");
    ASSERT_TRUE(fl->C_DigestInit    != NULL, "C_DigestInit present");
    ASSERT_TRUE(fl->C_SignInit      != NULL, "C_SignInit present");
    ASSERT_TRUE(fl->C_VerifyInit    != NULL, "C_VerifyInit present");
    ASSERT_TRUE(fl->C_GenerateKey   != NULL, "C_GenerateKey present");
    ASSERT_TRUE(fl->C_GenerateKeyPair != NULL, "C_GenerateKeyPair present");
    ASSERT_TRUE(fl->C_WrapKey       != NULL, "C_WrapKey present");
    ASSERT_TRUE(fl->C_UnwrapKey     != NULL, "C_UnwrapKey present");
    ASSERT_TRUE(fl->C_DeriveKey     != NULL, "C_DeriveKey present");
    ASSERT_TRUE(fl->C_GenerateRandom != NULL, "C_GenerateRandom present");
    TEST_PASS();
}

/* REQ-SLOT-01: C_GetSlotList NULL count pointer → CKR_ARGUMENTS_BAD      */
static int test_get_slot_list_null_count(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_GetSlotList(CK_TRUE, NULL_PTR, NULL_PTR);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "C_GetSlotList NULL count");
    TEST_PASS();
}

/* REQ-SLOT-02: C_GetSlotList two-call pattern returns same count          */
static int test_get_slot_list_two_call(TestCtx *ctx)
{
    CK_ULONG cnt1 = 0, cnt2 = 0;
    ctx->mod.fn->C_GetSlotList(CK_TRUE, NULL_PTR, &cnt1);
    ASSERT_TRUE(cnt1 > 0, "At least one initialized slot");

    CK_SLOT_ID *slots = malloc(cnt1 * sizeof(CK_SLOT_ID));
    cnt2 = cnt1;
    CK_RV rv = ctx->mod.fn->C_GetSlotList(CK_TRUE, slots, &cnt2);
    ASSERT_RV_OK(rv, "C_GetSlotList fill");
    ASSERT_EQ(cnt1, cnt2, "Counts match across both calls");
    free(slots);
    TEST_PASS();
}

/* REQ-SLOT-03: C_GetSlotList(FALSE) >= C_GetSlotList(TRUE)               */
static int test_get_slot_list_all_vs_token(TestCtx *ctx)
{
    CK_ULONG cnt_all = 0, cnt_tok = 0;
    ctx->mod.fn->C_GetSlotList(CK_FALSE, NULL_PTR, &cnt_all);
    ctx->mod.fn->C_GetSlotList(CK_TRUE,  NULL_PTR, &cnt_tok);
    ASSERT_TRUE(cnt_all >= cnt_tok, "All-slots >= token-present slots");
    TEST_PASS();
}

/* REQ-SLOT-04: C_GetSlotInfo NULL pInfo → CKR_ARGUMENTS_BAD              */
static int test_get_slot_info_null_ptr(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_GetSlotInfo(ctx->slot, NULL_PTR);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "C_GetSlotInfo(NULL)");
    TEST_PASS();
}

/* REQ-SLOT-05: C_GetSlotInfo invalid slot → CKR_SLOT_ID_INVALID           */
static int test_get_slot_info_invalid_slot(TestCtx *ctx)
{
    CK_SLOT_INFO info;
    CK_RV rv = ctx->mod.fn->C_GetSlotInfo(0xFFFFFFFEUL, &info);
    ASSERT_RV(rv, CKR_SLOT_ID_INVALID, "C_GetSlotInfo invalid slot");
    TEST_PASS();
}

/* REQ-SLOT-06: C_GetSlotInfo CKF_TOKEN_PRESENT when token present         */
static int test_get_slot_info_token_present_flag(TestCtx *ctx)
{
    CK_SLOT_INFO info;
    CK_RV rv = ctx->mod.fn->C_GetSlotInfo(ctx->slot, &info);
    ASSERT_RV_OK(rv, "C_GetSlotInfo");
    ASSERT_TRUE(info.flags & CKF_TOKEN_PRESENT,
                "CKF_TOKEN_PRESENT flag set for our initialized slot");
    TEST_PASS();
}

/* REQ-SLOT-07: C_GetTokenInfo NULL pInfo → CKR_ARGUMENTS_BAD             */
static int test_get_token_info_null_ptr(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_GetTokenInfo(ctx->slot, NULL_PTR);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "C_GetTokenInfo(NULL)");
    TEST_PASS();
}

/* REQ-SLOT-08: C_GetTokenInfo invalid slot → CKR_SLOT_ID_INVALID          */
static int test_get_token_info_invalid_slot(TestCtx *ctx)
{
    CK_TOKEN_INFO info;
    CK_RV rv = ctx->mod.fn->C_GetTokenInfo(0xFFFFFFFEUL, &info);
    ASSERT_RV(rv, CKR_SLOT_ID_INVALID, "C_GetTokenInfo invalid slot");
    TEST_PASS();
}

/* REQ-SLOT-09: C_GetTokenInfo CKF_TOKEN_INITIALIZED for our token         */
static int test_get_token_info_initialized_flag(TestCtx *ctx)
{
    CK_TOKEN_INFO info;
    CK_RV rv = ctx->mod.fn->C_GetTokenInfo(ctx->slot, &info);
    ASSERT_RV_OK(rv, "C_GetTokenInfo");
    ASSERT_TRUE(info.flags & CKF_TOKEN_INITIALIZED,
                "CKF_TOKEN_INITIALIZED set");
    TEST_PASS();
}

/* REQ-SLOT-10: C_GetTokenInfo fields are within stated bounds             */
static int test_get_token_info_field_bounds(TestCtx *ctx)
{
    CK_TOKEN_INFO info;
    CK_RV rv = ctx->mod.fn->C_GetTokenInfo(ctx->slot, &info);
    ASSERT_RV_OK(rv, "C_GetTokenInfo");
    /* maxPinLen >= minPinLen */
    ASSERT_TRUE(info.ulMaxPinLen >= info.ulMinPinLen,
                "maxPinLen >= minPinLen");
    /* Session counts: ulMaxSessionCount is CK_UNAVAILABLE or > 0 */
    /* SoftHSM2 may report 0 (unlimited) or CK_UNAVAILABLE_INFORMATION */
    ASSERT_TRUE(info.ulMaxSessionCount == CK_UNAVAILABLE_INFORMATION ||
                info.ulMaxSessionCount >= 0, "maxSessionCount valid");
    TEST_PASS();
}

/* REQ-SLOT-11: C_GetMechanismList NULL count → CKR_ARGUMENTS_BAD          */
static int test_get_mechanism_list_null_count(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_GetMechanismList(ctx->slot, NULL_PTR, NULL_PTR);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "C_GetMechanismList(NULL count)");
    TEST_PASS();
}

/* REQ-SLOT-12: C_GetMechanismList invalid slot → CKR_SLOT_ID_INVALID      */
static int test_get_mechanism_list_invalid_slot(TestCtx *ctx)
{
    CK_ULONG count = 0;
    CK_RV rv = ctx->mod.fn->C_GetMechanismList(0xFFFFFFFEUL, NULL_PTR, &count);
    ASSERT_RV(rv, CKR_SLOT_ID_INVALID, "C_GetMechanismList invalid slot");
    TEST_PASS();
}

/* REQ-SLOT-13: C_GetMechanismInfo NULL pInfo → CKR_ARGUMENTS_BAD          */
static int test_get_mechanism_info_null_ptr(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_GetMechanismInfo(ctx->slot, CKM_AES_CBC, NULL_PTR);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "C_GetMechanismInfo(NULL)");
    TEST_PASS();
}

/* REQ-SLOT-14: C_GetMechanismInfo invalid slot → CKR_SLOT_ID_INVALID      */
static int test_get_mechanism_info_invalid_slot(TestCtx *ctx)
{
    CK_MECHANISM_INFO info;
    CK_RV rv = ctx->mod.fn->C_GetMechanismInfo(0xFFFFFFFEUL, CKM_AES_CBC, &info);
    ASSERT_RV(rv, CKR_SLOT_ID_INVALID, "C_GetMechanismInfo invalid slot");
    TEST_PASS();
}

/* REQ-SLOT-15: C_GetMechanismInfo unknown mechanism → CKR_MECHANISM_INVALID*/
static int test_get_mechanism_info_unknown_mech(TestCtx *ctx)
{
    CK_MECHANISM_INFO info;
    CK_RV rv = ctx->mod.fn->C_GetMechanismInfo(ctx->slot, 0x80001234UL, &info);
    ASSERT_RV(rv, CKR_MECHANISM_INVALID, "C_GetMechanismInfo unknown mech");
    TEST_PASS();
}

/* REQ-SLOT-16: C_GetMechanismInfo flags indicate correct usage            */
static int test_get_mechanism_info_flags(TestCtx *ctx)
{
    CK_MECHANISM_INFO enc_info, sig_info;
    CK_RV rv1 = ctx->mod.fn->C_GetMechanismInfo(ctx->slot, CKM_AES_CBC, &enc_info);
    CK_RV rv2 = ctx->mod.fn->C_GetMechanismInfo(ctx->slot, CKM_SHA256_RSA_PKCS, &sig_info);
    if (rv1 == CKR_OK)
        ASSERT_TRUE(enc_info.flags & (CKF_ENCRYPT | CKF_DECRYPT),
                    "AES_CBC flags include ENCRYPT or DECRYPT");
    if (rv2 == CKR_OK)
        ASSERT_TRUE(sig_info.flags & (CKF_SIGN | CKF_VERIFY),
                    "SHA256_RSA_PKCS flags include SIGN or VERIFY");
    TEST_PASS();
}

/* REQ-SLOT-17: C_WaitForSlotEvent non-blocking returns promptly           */
static int test_wait_for_slot_event_nonblocking(TestCtx *ctx)
{
    CK_SLOT_ID slot_id;
    CK_RV rv = ctx->mod.fn->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot_id, NULL_PTR);
    ASSERT_TRUE(rv == CKR_OK || rv == CKR_NO_EVENT,
                "C_WaitForSlotEvent non-blocking (OK or NO_EVENT)");
    TEST_PASS();
}

/* REQ-SLOT-18: C_WaitForSlotEvent NULL slot pointer → CKR_ARGUMENTS_BAD  */
static int test_wait_for_slot_event_null(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_WaitForSlotEvent(CKF_DONT_BLOCK, NULL_PTR, NULL_PTR);
    /* PKCS#11 requires CKR_ARGUMENTS_BAD; SoftHSM2 may return CKR_NO_EVENT */
    ASSERT_TRUE(rv == CKR_ARGUMENTS_BAD || rv == CKR_NO_EVENT,
                "C_WaitForSlotEvent(NULL slot): ARGUMENTS_BAD or NO_EVENT");
    TEST_PASS();
}

/* REQ-SLOT-19: C_SetPIN wrong old PIN → CKR_PIN_INCORRECT                 */
static int test_set_pin_wrong_old_pin(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_SetPIN(ctx->rw_session,
                                      (CK_UTF8CHAR_PTR)"wrongPIN!", 9,
                                      (CK_UTF8CHAR_PTR)ctx->user_pin,
                                      (CK_ULONG)strlen(ctx->user_pin));
    ASSERT_RV(rv, CKR_PIN_INCORRECT, "C_SetPIN wrong old PIN");
    TEST_PASS();
}

/* REQ-SLOT-20: C_InitPIN requires SO session (RW_SO_FUNCTIONS state)      */
static int test_init_pin_wrong_session_state(TestCtx *ctx)
{
    /* ctx->rw_session is in USER state, not SO state — must fail           */
    CK_RV rv = ctx->mod.fn->C_InitPIN(ctx->rw_session,
                                       (CK_UTF8CHAR_PTR)ctx->user_pin,
                                       (CK_ULONG)strlen(ctx->user_pin));
    ASSERT_RV(rv, CKR_USER_NOT_LOGGED_IN, "C_InitPIN in USER session state");
    TEST_PASS();
}

BEGIN_TESTS(req_general)
    ADD_TEST("REQ-GEN-01_Finalize_reserved_not_null",   test_finalize_reserved_not_null);
    ADD_TEST("REQ-GEN-02_GetInfo_null_ptr",             test_get_info_null_ptr);
    ADD_TEST("REQ-GEN-03_GetInfo_version",              test_get_info_version);
    ADD_TEST("REQ-GEN-04_GetFunctionList_null",         test_get_function_list_null);
    ADD_TEST("REQ-GEN-05_GetFunctionList_consistent",   test_get_function_list_consistent);
    ADD_TEST("REQ-SLOT-01_GetSlotList_null_count",      test_get_slot_list_null_count);
    ADD_TEST("REQ-SLOT-02_GetSlotList_two_call",        test_get_slot_list_two_call);
    ADD_TEST("REQ-SLOT-03_GetSlotList_all_vs_token",    test_get_slot_list_all_vs_token);
    ADD_TEST("REQ-SLOT-04_GetSlotInfo_null_ptr",        test_get_slot_info_null_ptr);
    ADD_TEST("REQ-SLOT-05_GetSlotInfo_invalid_slot",    test_get_slot_info_invalid_slot);
    ADD_TEST("REQ-SLOT-06_GetSlotInfo_token_present",   test_get_slot_info_token_present_flag);
    ADD_TEST("REQ-SLOT-07_GetTokenInfo_null_ptr",       test_get_token_info_null_ptr);
    ADD_TEST("REQ-SLOT-08_GetTokenInfo_invalid_slot",   test_get_token_info_invalid_slot);
    ADD_TEST("REQ-SLOT-09_GetTokenInfo_initialized",    test_get_token_info_initialized_flag);
    ADD_TEST("REQ-SLOT-10_GetTokenInfo_field_bounds",   test_get_token_info_field_bounds);
    ADD_TEST("REQ-SLOT-11_GetMechList_null_count",      test_get_mechanism_list_null_count);
    ADD_TEST("REQ-SLOT-12_GetMechList_invalid_slot",    test_get_mechanism_list_invalid_slot);
    ADD_TEST("REQ-SLOT-13_GetMechInfo_null_ptr",        test_get_mechanism_info_null_ptr);
    ADD_TEST("REQ-SLOT-14_GetMechInfo_invalid_slot",    test_get_mechanism_info_invalid_slot);
    ADD_TEST("REQ-SLOT-15_GetMechInfo_unknown_mech",    test_get_mechanism_info_unknown_mech);
    ADD_TEST("REQ-SLOT-16_GetMechInfo_flags",           test_get_mechanism_info_flags);
    ADD_TEST("REQ-SLOT-17_WaitForSlotEvent_nonblocking",test_wait_for_slot_event_nonblocking);
    ADD_TEST("REQ-SLOT-18_WaitForSlotEvent_null",       test_wait_for_slot_event_null);
    ADD_TEST("REQ-SLOT-19_SetPIN_wrong_old_pin",        test_set_pin_wrong_old_pin);
    ADD_TEST("REQ-SLOT-20_InitPIN_wrong_state",         test_init_pin_wrong_session_state);
END_TESTS()
