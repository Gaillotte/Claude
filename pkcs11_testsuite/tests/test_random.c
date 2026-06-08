#include "test_framework.h"
#include <string.h>
#include <stdlib.h>

static int test_generate_random_basic(TestCtx *ctx)
{
    unsigned char buf[32];
    CK_RV rv = ctx->mod.fn->C_GenerateRandom(ctx->rw_session, buf, sizeof(buf));
    ASSERT_RV_OK(rv, "C_GenerateRandom 32 bytes");
    TEST_PASS();
}

static int test_generate_random_not_all_zero(TestCtx *ctx)
{
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));
    CK_RV rv = ctx->mod.fn->C_GenerateRandom(ctx->rw_session, buf, sizeof(buf));
    ASSERT_RV_OK(rv, "C_GenerateRandom 64 bytes");

    int all_zero = 1;
    for (size_t i = 0; i < sizeof(buf); i++) {
        if (buf[i] != 0) { all_zero = 0; break; }
    }
    ASSERT_TRUE(!all_zero, "Random bytes are not all zero");
    TEST_PASS();
}

static int test_generate_random_unique(TestCtx *ctx)
{
    unsigned char buf1[32], buf2[32];
    ctx->mod.fn->C_GenerateRandom(ctx->rw_session, buf1, sizeof(buf1));
    ctx->mod.fn->C_GenerateRandom(ctx->rw_session, buf2, sizeof(buf2));
    ASSERT_TRUE(memcmp(buf1, buf2, sizeof(buf1)) != 0, "Two random buffers differ");
    TEST_PASS();
}

static int test_generate_random_1_byte(TestCtx *ctx)
{
    unsigned char byte;
    CK_RV rv = ctx->mod.fn->C_GenerateRandom(ctx->rw_session, &byte, 1);
    ASSERT_RV_OK(rv, "C_GenerateRandom 1 byte");
    TEST_PASS();
}

static int test_generate_random_1024_bytes(TestCtx *ctx)
{
    unsigned char *buf = malloc(1024);
    CK_RV rv = ctx->mod.fn->C_GenerateRandom(ctx->rw_session, buf, 1024);
    ASSERT_RV_OK(rv, "C_GenerateRandom 1024 bytes");
    free(buf);
    TEST_PASS();
}

static int test_generate_random_null(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_GenerateRandom(ctx->rw_session, NULL_PTR, 16);
    ASSERT_TRUE(rv != CKR_OK, "C_GenerateRandom NULL buffer should fail");
    TEST_PASS();
}

static int test_seed_random(TestCtx *ctx)
{
    unsigned char seed[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
    CK_RV rv = ctx->mod.fn->C_SeedRandom(ctx->rw_session, seed, sizeof(seed));
    /* SoftHSM may or may not support seeding */
    ASSERT_TRUE(rv == CKR_OK || rv == CKR_RANDOM_SEED_NOT_SUPPORTED,
                "C_SeedRandom ok or not supported");
    TEST_PASS();
}

static int test_generate_random_invalid_session(TestCtx *ctx)
{
    unsigned char buf[16];
    CK_RV rv = ctx->mod.fn->C_GenerateRandom(0xDEADBEEF, buf, sizeof(buf));
    ASSERT_RV(rv, CKR_SESSION_HANDLE_INVALID, "C_GenerateRandom invalid session");
    TEST_PASS();
}

BEGIN_TESTS(random)
    ADD_TEST("GenerateRandom_basic",          test_generate_random_basic);
    ADD_TEST("GenerateRandom_not_all_zero",   test_generate_random_not_all_zero);
    ADD_TEST("GenerateRandom_unique",         test_generate_random_unique);
    ADD_TEST("GenerateRandom_1_byte",         test_generate_random_1_byte);
    ADD_TEST("GenerateRandom_1024_bytes",     test_generate_random_1024_bytes);
    ADD_TEST("GenerateRandom_null",           test_generate_random_null);
    ADD_TEST("SeedRandom",                    test_seed_random);
    ADD_TEST("GenerateRandom_invalid_session",test_generate_random_invalid_session);
END_TESTS()
