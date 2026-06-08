#include "test_framework.h"
#include <string.h>
#include <stdlib.h>

static int test_get_slot_list_token_present(TestCtx *ctx)
{
    CK_ULONG count = 0;
    CK_RV rv = ctx->mod.fn->C_GetSlotList(CK_TRUE, NULL_PTR, &count);
    ASSERT_RV_OK(rv, "C_GetSlotList(token_present=true, NULL)");
    ASSERT_TRUE(count > 0, "At least one slot with token");

    CK_SLOT_ID *slots = malloc(count * sizeof(CK_SLOT_ID));
    rv = ctx->mod.fn->C_GetSlotList(CK_TRUE, slots, &count);
    ASSERT_RV_OK(rv, "C_GetSlotList fill");
    log_info("  Slots with token: %lu", count);
    free(slots);
    TEST_PASS();
}

static int test_get_slot_list_all(TestCtx *ctx)
{
    CK_ULONG count = 0;
    CK_RV rv = ctx->mod.fn->C_GetSlotList(CK_FALSE, NULL_PTR, &count);
    ASSERT_RV_OK(rv, "C_GetSlotList(all)");
    ASSERT_TRUE(count >= 1, "At least one slot total");
    log_info("  Total slots: %lu", count);
    TEST_PASS();
}

static int test_get_slot_list_buffer_too_small(TestCtx *ctx)
{
    CK_ULONG count = 0;
    ctx->mod.fn->C_GetSlotList(CK_TRUE, NULL_PTR, &count);
    if (count == 0) SKIP("No slots available");

    CK_ULONG small = 0;
    CK_SLOT_ID dummy;
    CK_RV rv = ctx->mod.fn->C_GetSlotList(CK_TRUE, &dummy, &small);
    ASSERT_RV(rv, CKR_BUFFER_TOO_SMALL, "C_GetSlotList buffer too small");
    TEST_PASS();
}

static int test_get_slot_info(TestCtx *ctx)
{
    CK_SLOT_INFO info;
    memset(&info, 0, sizeof(info));
    CK_RV rv = ctx->mod.fn->C_GetSlotInfo(ctx->slot, &info);
    ASSERT_RV_OK(rv, "C_GetSlotInfo");
    log_info("  slotDescription: %.64s", info.slotDescription);
    log_info("  manufacturerID:  %.32s", info.manufacturerID);
    log_info("  flags: 0x%lX (token_present=%s)", info.flags,
             (info.flags & CKF_TOKEN_PRESENT) ? "yes" : "no");
    ASSERT_TRUE(info.flags & CKF_TOKEN_PRESENT, "Token is present");
    TEST_PASS();
}

static int test_get_slot_info_invalid(TestCtx *ctx)
{
    CK_SLOT_INFO info;
    CK_RV rv = ctx->mod.fn->C_GetSlotInfo(0xDEADBEEF, &info);
    ASSERT_RV(rv, CKR_SLOT_ID_INVALID, "C_GetSlotInfo invalid slot");
    TEST_PASS();
}

static int test_get_slot_info_null(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_GetSlotInfo(ctx->slot, NULL_PTR);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "C_GetSlotInfo NULL");
    TEST_PASS();
}

static int test_get_token_info(TestCtx *ctx)
{
    CK_TOKEN_INFO info;
    memset(&info, 0, sizeof(info));
    CK_RV rv = ctx->mod.fn->C_GetTokenInfo(ctx->slot, &info);
    ASSERT_RV_OK(rv, "C_GetTokenInfo");
    log_info("  label:           %.32s", info.label);
    log_info("  manufacturerID:  %.32s", info.manufacturerID);
    log_info("  model:           %.16s", info.model);
    log_info("  serialNumber:    %.16s", info.serialNumber);
    log_info("  flags:           0x%lX", info.flags);
    log_info("  maxSessionCount: %lu", info.ulMaxSessionCount);
    log_info("  sessionCount:    %lu", info.ulSessionCount);
    log_info("  maxPinLen:       %lu", info.ulMaxPinLen);
    log_info("  minPinLen:       %lu", info.ulMinPinLen);
    log_info("  totalPublicMem:  %lu", info.ulTotalPublicMemory);
    log_info("  totalPrivateMem: %lu", info.ulTotalPrivateMemory);
    ASSERT_TRUE(info.flags & CKF_TOKEN_INITIALIZED, "Token is initialized");
    TEST_PASS();
}

static int test_get_token_info_invalid_slot(TestCtx *ctx)
{
    CK_TOKEN_INFO info;
    CK_RV rv = ctx->mod.fn->C_GetTokenInfo(0xDEADBEEF, &info);
    ASSERT_RV(rv, CKR_SLOT_ID_INVALID, "C_GetTokenInfo invalid slot");
    TEST_PASS();
}

static int test_get_token_info_null(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_GetTokenInfo(ctx->slot, NULL_PTR);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "C_GetTokenInfo NULL");
    TEST_PASS();
}

static int test_get_mechanism_list(TestCtx *ctx)
{
    CK_ULONG count = 0;
    CK_RV rv = ctx->mod.fn->C_GetMechanismList(ctx->slot, NULL_PTR, &count);
    ASSERT_RV_OK(rv, "C_GetMechanismList get count");
    ASSERT_TRUE(count > 0, "At least one mechanism");
    log_info("  Supported mechanisms: %lu", count);

    CK_MECHANISM_TYPE *mechs = malloc(count * sizeof(CK_MECHANISM_TYPE));
    rv = ctx->mod.fn->C_GetMechanismList(ctx->slot, mechs, &count);
    ASSERT_RV_OK(rv, "C_GetMechanismList fill");

    /* Check for common expected mechanisms */
    int has_aes = 0, has_rsa = 0, has_sha = 0;
    for (CK_ULONG i = 0; i < count; i++) {
        if (mechs[i] == CKM_AES_CBC) has_aes = 1;
        if (mechs[i] == CKM_RSA_PKCS) has_rsa = 1;
        if (mechs[i] == CKM_SHA256)   has_sha = 1;
    }
    log_info("  AES_CBC: %s, RSA_PKCS: %s, SHA256: %s",
             has_aes ? "yes" : "no", has_rsa ? "yes" : "no", has_sha ? "yes" : "no");
    free(mechs);
    TEST_PASS();
}

static int test_get_mechanism_list_buffer_too_small(TestCtx *ctx)
{
    CK_ULONG count = 0;
    ctx->mod.fn->C_GetMechanismList(ctx->slot, NULL_PTR, &count);
    if (count == 0) SKIP("No mechanisms");

    CK_ULONG small = 0;
    CK_MECHANISM_TYPE dummy;
    CK_RV rv = ctx->mod.fn->C_GetMechanismList(ctx->slot, &dummy, &small);
    ASSERT_RV(rv, CKR_BUFFER_TOO_SMALL, "C_GetMechanismList buffer too small");
    TEST_PASS();
}

static int test_get_mechanism_info(TestCtx *ctx)
{
    CK_MECHANISM_INFO info;
    CK_RV rv = ctx->mod.fn->C_GetMechanismInfo(ctx->slot, CKM_AES_CBC, &info);
    if (rv == CKR_MECHANISM_INVALID) SKIP("AES_CBC not supported");
    ASSERT_RV_OK(rv, "C_GetMechanismInfo(AES_CBC)");
    log_info("  AES_CBC: minKeySize=%lu maxKeySize=%lu flags=0x%lX",
             info.ulMinKeySize, info.ulMaxKeySize, info.flags);
    TEST_PASS();
}

static int test_get_mechanism_info_invalid(TestCtx *ctx)
{
    CK_MECHANISM_INFO info;
    CK_RV rv = ctx->mod.fn->C_GetMechanismInfo(ctx->slot, 0x80000999UL, &info);
    ASSERT_RV(rv, CKR_MECHANISM_INVALID, "C_GetMechanismInfo invalid mechanism");
    TEST_PASS();
}

static int test_wait_for_slot_event_no_block(TestCtx *ctx)
{
    CK_SLOT_ID slot;
    CK_RV rv = ctx->mod.fn->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot, NULL_PTR);
    /* Expect either no event or an event */
    ASSERT_TRUE(rv == CKR_OK || rv == CKR_NO_EVENT, "C_WaitForSlotEvent no-block");
    TEST_PASS();
}

BEGIN_TESTS(slot_token)
    ADD_TEST("C_GetSlotList_token_present",        test_get_slot_list_token_present);
    ADD_TEST("C_GetSlotList_all",                  test_get_slot_list_all);
    ADD_TEST("C_GetSlotList_buffer_too_small",     test_get_slot_list_buffer_too_small);
    ADD_TEST("C_GetSlotInfo",                      test_get_slot_info);
    ADD_TEST("C_GetSlotInfo_invalid",              test_get_slot_info_invalid);
    ADD_TEST("C_GetSlotInfo_null",                 test_get_slot_info_null);
    ADD_TEST("C_GetTokenInfo",                     test_get_token_info);
    ADD_TEST("C_GetTokenInfo_invalid_slot",        test_get_token_info_invalid_slot);
    ADD_TEST("C_GetTokenInfo_null",                test_get_token_info_null);
    ADD_TEST("C_GetMechanismList",                 test_get_mechanism_list);
    ADD_TEST("C_GetMechanismList_buffer_too_small",test_get_mechanism_list_buffer_too_small);
    ADD_TEST("C_GetMechanismInfo",                 test_get_mechanism_info);
    ADD_TEST("C_GetMechanismInfo_invalid",         test_get_mechanism_info_invalid);
    ADD_TEST("C_WaitForSlotEvent_no_block",        test_wait_for_slot_event_no_block);
END_TESTS()
