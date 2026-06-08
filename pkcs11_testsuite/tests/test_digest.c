#include "test_framework.h"
#include <string.h>
#include <stdlib.h>

/* Known SHA-256 of "" (empty string) */
static const unsigned char SHA256_EMPTY[] = {
    0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
    0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
};

static int do_digest(TestCtx *ctx, CK_MECHANISM_TYPE mtype,
                     const unsigned char *data, CK_ULONG data_len,
                     unsigned char *digest, CK_ULONG *digest_len)
{
    CK_MECHANISM m = { mtype, NULL_PTR, 0 };
    CK_RV rv = ctx->mod.fn->C_DigestInit(ctx->rw_session, &m);
    if (rv != CKR_OK) return (int)rv;
    rv = ctx->mod.fn->C_Digest(ctx->rw_session, (CK_BYTE_PTR)data, data_len,
                                digest, digest_len);
    return (rv == CKR_OK) ? 0 : (int)rv;
}

static int test_sha1(TestCtx *ctx)
{
    const char *msg = "abc";
    unsigned char digest[20];
    CK_ULONG len = sizeof(digest);
    int rc = do_digest(ctx, CKM_SHA_1, (const unsigned char*)msg, 3, digest, &len);
    if (rc == (int)CKR_MECHANISM_INVALID) SKIP("SHA-1 not supported");
    ASSERT_EQ(rc, 0, "SHA-1 digest");
    ASSERT_EQ(len, 20UL, "SHA-1 output length");
    hex_print("SHA-1(abc)", digest, len);
    TEST_PASS();
}

static int test_sha256(TestCtx *ctx)
{
    unsigned char digest[32];
    CK_ULONG len = sizeof(digest);
    int rc = do_digest(ctx, CKM_SHA256, (const unsigned char*)"", 0, digest, &len);
    if (rc == (int)CKR_MECHANISM_INVALID) SKIP("SHA-256 not supported");
    ASSERT_EQ(rc, 0, "SHA-256 digest");
    ASSERT_EQ(len, 32UL, "SHA-256 output length");
    ASSERT_MEM_EQ(digest, SHA256_EMPTY, 32, "SHA-256 of empty string matches");
    TEST_PASS();
}

static int test_sha384(TestCtx *ctx)
{
    const char *msg = "hello";
    unsigned char digest[48];
    CK_ULONG len = sizeof(digest);
    int rc = do_digest(ctx, CKM_SHA384, (const unsigned char*)msg, 5, digest, &len);
    if (rc == (int)CKR_MECHANISM_INVALID) SKIP("SHA-384 not supported");
    ASSERT_EQ(rc, 0, "SHA-384 digest");
    ASSERT_EQ(len, 48UL, "SHA-384 output length");
    TEST_PASS();
}

static int test_sha512(TestCtx *ctx)
{
    const char *msg = "hello";
    unsigned char digest[64];
    CK_ULONG len = sizeof(digest);
    int rc = do_digest(ctx, CKM_SHA512, (const unsigned char*)msg, 5, digest, &len);
    if (rc == (int)CKR_MECHANISM_INVALID) SKIP("SHA-512 not supported");
    ASSERT_EQ(rc, 0, "SHA-512 digest");
    ASSERT_EQ(len, 64UL, "SHA-512 output length");
    TEST_PASS();
}

static int test_sha3_256(TestCtx *ctx)
{
    /* CKM_SHA3_256 = 0x000002B0 (PKCS#11 v2.40+) */
    const CK_MECHANISM_TYPE CKM_SHA3_256_VAL = 0x000002B0UL;
    const char *msg = "test";
    unsigned char digest[32];
    CK_ULONG len = sizeof(digest);
    CK_MECHANISM m = { CKM_SHA3_256_VAL, NULL_PTR, 0 };
    CK_RV rv = ctx->mod.fn->C_DigestInit(ctx->rw_session, &m);
    if (rv == CKR_MECHANISM_INVALID) {
        /* Ensure no operation is left pending */
        unsigned char ab[64]; CK_ULONG al = sizeof(ab);
        ctx->mod.fn->C_DigestFinal(ctx->rw_session, ab, &al);
        SKIP("SHA3-256 not supported");
    }
    ASSERT_RV_OK(rv, "DigestInit SHA3-256");
    rv = ctx->mod.fn->C_Digest(ctx->rw_session, (CK_BYTE_PTR)msg, 4, digest, &len);
    ASSERT_RV_OK(rv, "Digest SHA3-256");
    ASSERT_EQ(len, 32UL, "SHA3-256 length");
    TEST_PASS();
}

/* Multipart digest */
static int test_digest_multipart(TestCtx *ctx)
{
    /* Digest("abc") should equal Digest("a" + "b" + "c") */
    CK_MECHANISM m = { CKM_SHA256, NULL_PTR, 0 };
    unsigned char ref[32], multi[32];
    CK_ULONG ref_len = sizeof(ref), multi_len = sizeof(multi);

    /* Reference: one-shot */
    CK_RV rv = ctx->mod.fn->C_DigestInit(ctx->rw_session, &m);
    ASSERT_RV_OK(rv, "DigestInit ref");
    rv = ctx->mod.fn->C_Digest(ctx->rw_session, (CK_BYTE_PTR)"abc", 3, ref, &ref_len);
    ASSERT_RV_OK(rv, "Digest ref");

    /* Multipart */
    rv = ctx->mod.fn->C_DigestInit(ctx->rw_session, &m);
    ASSERT_RV_OK(rv, "DigestInit multi");
    rv = ctx->mod.fn->C_DigestUpdate(ctx->rw_session, (CK_BYTE_PTR)"a", 1);
    ASSERT_RV_OK(rv, "DigestUpdate a");
    rv = ctx->mod.fn->C_DigestUpdate(ctx->rw_session, (CK_BYTE_PTR)"b", 1);
    ASSERT_RV_OK(rv, "DigestUpdate b");
    rv = ctx->mod.fn->C_DigestUpdate(ctx->rw_session, (CK_BYTE_PTR)"c", 1);
    ASSERT_RV_OK(rv, "DigestUpdate c");
    rv = ctx->mod.fn->C_DigestFinal(ctx->rw_session, multi, &multi_len);
    ASSERT_RV_OK(rv, "DigestFinal");

    ASSERT_MEM_EQ(ref, multi, 32, "One-shot and multipart SHA-256 match");
    TEST_PASS();
}

/* Digest Key — add the key value into the running hash */
static int test_digest_key(TestCtx *ctx)
{
    /* Generate an AES key */
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG klen = 16;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &f,    sizeof(f)    },
        { CKA_ENCRYPT,   &t,    sizeof(t)    },
        { CKA_VALUE_LEN, &klen, sizeof(klen) },
    };
    CK_MECHANISM gen_m = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ctx->mod.fn->C_GenerateKey(ctx->rw_session, &gen_m, tmpl, 3, &key);
    ASSERT_NE(key, CK_INVALID_HANDLE, "AES key generated");

    CK_MECHANISM m = { CKM_SHA256, NULL_PTR, 0 };
    CK_RV rv = ctx->mod.fn->C_DigestInit(ctx->rw_session, &m);
    ASSERT_RV_OK(rv, "DigestInit for key digest");
    rv = ctx->mod.fn->C_DigestKey(ctx->rw_session, key);
    if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
        SKIP("C_DigestKey not supported");
    }
    ASSERT_RV_OK(rv, "C_DigestKey");

    unsigned char digest[32]; CK_ULONG dlen = sizeof(digest);
    rv = ctx->mod.fn->C_DigestFinal(ctx->rw_session, digest, &dlen);
    ASSERT_RV_OK(rv, "DigestFinal after DigestKey");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

/* Digest without init */
static int test_digest_no_init(TestCtx *ctx)
{
    unsigned char digest[32]; CK_ULONG dlen = sizeof(digest);
    CK_RV rv = ctx->mod.fn->C_Digest(ctx->rw_session, (CK_BYTE_PTR)"x", 1, digest, &dlen);
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "Digest without init");
    TEST_PASS();
}

/* DigestUpdate without init */
static int test_digest_update_no_init(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_DigestUpdate(ctx->rw_session, (CK_BYTE_PTR)"x", 1);
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "DigestUpdate without init");
    TEST_PASS();
}

/* DigestFinal without init */
static int test_digest_final_no_init(TestCtx *ctx)
{
    unsigned char digest[32]; CK_ULONG dlen = sizeof(digest);
    CK_RV rv = ctx->mod.fn->C_DigestFinal(ctx->rw_session, digest, &dlen);
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "DigestFinal without init");
    TEST_PASS();
}

/* Digest buffer too small */
static int test_digest_buffer_too_small(TestCtx *ctx)
{
    CK_MECHANISM m = { CKM_SHA256, NULL_PTR, 0 };
    CK_RV rv = ctx->mod.fn->C_DigestInit(ctx->rw_session, &m);
    ASSERT_RV_OK(rv, "DigestInit");
    unsigned char tiny[1]; CK_ULONG tlen = sizeof(tiny);
    rv = ctx->mod.fn->C_Digest(ctx->rw_session, (CK_BYTE_PTR)"test", 4, tiny, &tlen);
    int result = 0;
    if (rv != CKR_BUFFER_TOO_SMALL) {
        log_fail("Digest buffer too small: expected CKR_BUFFER_TOO_SMALL, got %s", pkcs11_rv_str(rv));
        result = -1;
    }
    /* Abort the pending operation no matter what */
    unsigned char abort_buf[64]; CK_ULONG abort_len = sizeof(abort_buf);
    ctx->mod.fn->C_DigestFinal(ctx->rw_session, abort_buf, &abort_len);
    return result;
}

/* HMAC SHA256 sign/verify */
static int test_hmac_sha256(TestCtx *ctx)
{
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG klen = 32;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &f,    sizeof(f)    },
        { CKA_SIGN,      &t,    sizeof(t)    },
        { CKA_VERIFY,    &t,    sizeof(t)    },
        { CKA_VALUE_LEN, &klen, sizeof(klen) },
    };
    CK_MECHANISM gen_m = { CKM_GENERIC_SECRET_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_RV rv = ctx->mod.fn->C_GenerateKey(ctx->rw_session, &gen_m, tmpl, 4, &key);
    if (rv != CKR_OK) SKIP("GENERIC_SECRET_KEY_GEN not available");

    const char *msg = "HMAC test message";
    unsigned char mac[32]; CK_ULONG mac_len = sizeof(mac);

    CK_MECHANISM m = { CKM_SHA256_HMAC, NULL_PTR, 0 };
    rv = ctx->mod.fn->C_SignInit(ctx->rw_session, &m, key);
    if (rv == CKR_MECHANISM_INVALID) {
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
        SKIP("HMAC-SHA256 not supported");
    }
    ASSERT_RV_OK(rv, "SignInit HMAC-SHA256");
    rv = ctx->mod.fn->C_Sign(ctx->rw_session, (CK_BYTE_PTR)msg, (CK_ULONG)strlen(msg), mac, &mac_len);
    ASSERT_RV_OK(rv, "Sign HMAC-SHA256");

    rv = ctx->mod.fn->C_VerifyInit(ctx->rw_session, &m, key);
    ASSERT_RV_OK(rv, "VerifyInit HMAC-SHA256");
    rv = ctx->mod.fn->C_Verify(ctx->rw_session, (CK_BYTE_PTR)msg, (CK_ULONG)strlen(msg), mac, mac_len);
    if (rv != CKR_OK) {
        /* Abort any pending Verify */
        ctx->mod.fn->C_VerifyFinal(ctx->rw_session, NULL_PTR, 0);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
        ASSERT_RV_OK(rv, "Verify HMAC-SHA256");
    }

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

BEGIN_TESTS(digest)
    ADD_TEST("SHA1",                   test_sha1);
    ADD_TEST("SHA256",                 test_sha256);
    ADD_TEST("SHA384",                 test_sha384);
    ADD_TEST("SHA512",                 test_sha512);
    ADD_TEST("SHA3_256",               test_sha3_256);
    ADD_TEST("Digest_multipart",       test_digest_multipart);
    ADD_TEST("DigestKey",              test_digest_key);
    ADD_TEST("Digest_no_init",         test_digest_no_init);
    ADD_TEST("DigestUpdate_no_init",   test_digest_update_no_init);
    ADD_TEST("DigestFinal_no_init",    test_digest_final_no_init);
    ADD_TEST("Digest_buffer_too_small",test_digest_buffer_too_small);
    ADD_TEST("HMAC_SHA256",            test_hmac_sha256);
END_TESTS()
