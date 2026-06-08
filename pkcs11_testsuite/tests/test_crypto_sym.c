#include "test_framework.h"
#include <string.h>
#include <stdlib.h>

/* ---- Key generation helpers (local to this file) ---- */
static CK_OBJECT_HANDLE make_aes_key(TestCtx *ctx, CK_ULONG bits)
{
    CK_BBOOL t   = CK_TRUE;
    CK_BBOOL tok = CK_FALSE;
    CK_ULONG klen = bits / 8;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &tok,  sizeof(tok)  },
        { CKA_ENCRYPT,   &t,    sizeof(t)    },
        { CKA_DECRYPT,   &t,    sizeof(t)    },
        { CKA_VALUE_LEN, &klen, sizeof(klen) },
    };
    CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ctx->mod.fn->C_GenerateKey(ctx->rw_session, &m, tmpl, 4, &key);
    return key;
}

/* ---- AES-CBC encrypt/decrypt round-trip ---- */
static int aes_cbc_roundtrip(TestCtx *ctx, CK_ULONG bits)
{
    CK_OBJECT_HANDLE key = make_aes_key(ctx, bits);
    ASSERT_NE(key, CK_INVALID_HANDLE, "AES key generated");

    unsigned char iv[16]       = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                                   0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10 };
    unsigned char plain[32]    = "Hello PKCS11 AES-CBC test data!!";
    unsigned char cipher[48]   = {0};
    unsigned char decrypted[48]= {0};
    CK_ULONG cipher_len  = sizeof(cipher);
    CK_ULONG decrypt_len = sizeof(decrypted);

    CK_MECHANISM m = { CKM_AES_CBC_PAD, iv, sizeof(iv) };

    CK_RV rv = ctx->mod.fn->C_EncryptInit(ctx->rw_session, &m, key);
    ASSERT_RV_OK(rv, "C_EncryptInit AES-CBC");
    rv = ctx->mod.fn->C_Encrypt(ctx->rw_session, plain, sizeof(plain), cipher, &cipher_len);
    ASSERT_RV_OK(rv, "C_Encrypt AES-CBC");

    rv = ctx->mod.fn->C_DecryptInit(ctx->rw_session, &m, key);
    ASSERT_RV_OK(rv, "C_DecryptInit AES-CBC");
    rv = ctx->mod.fn->C_Decrypt(ctx->rw_session, cipher, cipher_len, decrypted, &decrypt_len);
    ASSERT_RV_OK(rv, "C_Decrypt AES-CBC");

    ASSERT_EQ(decrypt_len, sizeof(plain), "Decrypted length matches");
    ASSERT_MEM_EQ(decrypted, plain, sizeof(plain), "Decrypted content matches plaintext");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

static int test_aes128_cbc(TestCtx *ctx) { return aes_cbc_roundtrip(ctx, 128); }
static int test_aes192_cbc(TestCtx *ctx) { return aes_cbc_roundtrip(ctx, 192); }
static int test_aes256_cbc(TestCtx *ctx) { return aes_cbc_roundtrip(ctx, 256); }

/* ---- AES-ECB ---- */
static int test_aes_ecb_roundtrip(TestCtx *ctx)
{
    CK_OBJECT_HANDLE key = make_aes_key(ctx, 128);
    ASSERT_NE(key, CK_INVALID_HANDLE, "AES key generated");

    unsigned char plain[16]    = { 0 };  /* one block */
    unsigned char cipher[16]   = { 0 };
    unsigned char dec[16]      = { 0 };
    CK_ULONG clen = sizeof(cipher), dlen = sizeof(dec);

    CK_MECHANISM m = { CKM_AES_ECB, NULL_PTR, 0 };

    CK_RV rv = ctx->mod.fn->C_EncryptInit(ctx->rw_session, &m, key);
    ASSERT_RV_OK(rv, "EncryptInit AES-ECB");
    rv = ctx->mod.fn->C_Encrypt(ctx->rw_session, plain, sizeof(plain), cipher, &clen);
    ASSERT_RV_OK(rv, "Encrypt AES-ECB");

    rv = ctx->mod.fn->C_DecryptInit(ctx->rw_session, &m, key);
    ASSERT_RV_OK(rv, "DecryptInit AES-ECB");
    rv = ctx->mod.fn->C_Decrypt(ctx->rw_session, cipher, clen, dec, &dlen);
    ASSERT_RV_OK(rv, "Decrypt AES-ECB");
    ASSERT_MEM_EQ(dec, plain, sizeof(plain), "AES-ECB roundtrip");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

/* ---- AES-GCM ---- */
static int test_aes_gcm_roundtrip(TestCtx *ctx)
{
    CK_OBJECT_HANDLE key = make_aes_key(ctx, 256);
    ASSERT_NE(key, CK_INVALID_HANDLE, "AES-256 key generated");

    unsigned char iv[12]  = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                               0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
    unsigned char aad[4]  = { 0xfe, 0xed, 0xfa, 0xce };
    unsigned char plain[32] = "AES-GCM authenticated encrypt!!";
    unsigned char cipher[64] = {0};
    unsigned char dec[64]    = {0};
    CK_ULONG clen = sizeof(cipher), dlen = sizeof(dec);

    CK_GCM_PARAMS gcm = {
        .iv_ptr    = iv,
        .iv_len    = sizeof(iv),
        .iv_bits   = sizeof(iv) * 8,
        .aad_ptr   = aad,
        .aad_len   = sizeof(aad),
        .tag_bits  = 128,
    };
    CK_MECHANISM m = { CKM_AES_GCM, &gcm, sizeof(gcm) };

    CK_RV rv = ctx->mod.fn->C_EncryptInit(ctx->rw_session, &m, key);
    if (rv == CKR_MECHANISM_INVALID) { ctx->mod.fn->C_DestroyObject(ctx->rw_session, key); SKIP("AES-GCM not supported"); }
    ASSERT_RV_OK(rv, "EncryptInit AES-GCM");
    rv = ctx->mod.fn->C_Encrypt(ctx->rw_session, plain, sizeof(plain), cipher, &clen);
    ASSERT_RV_OK(rv, "Encrypt AES-GCM");
    ASSERT_TRUE(clen > sizeof(plain), "Ciphertext includes GCM tag");

    rv = ctx->mod.fn->C_DecryptInit(ctx->rw_session, &m, key);
    ASSERT_RV_OK(rv, "DecryptInit AES-GCM");
    rv = ctx->mod.fn->C_Decrypt(ctx->rw_session, cipher, clen, dec, &dlen);
    ASSERT_RV_OK(rv, "Decrypt AES-GCM");
    ASSERT_EQ(dlen, (CK_ULONG)sizeof(plain), "GCM decrypted length");
    ASSERT_MEM_EQ(dec, plain, sizeof(plain), "GCM roundtrip");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

/* ---- AES-CTR ---- */
static int test_aes_ctr_roundtrip(TestCtx *ctx)
{
    CK_OBJECT_HANDLE key = make_aes_key(ctx, 128);
    ASSERT_NE(key, CK_INVALID_HANDLE, "AES key");

    CK_AES_CTR_PARAMS ctr;
    ctr.counter_bits = 128;
    memset(ctr.cb, 0, 16);

    unsigned char plain[32]  = "CTR mode encryption test 123456!";
    unsigned char enc[32]    = {0};
    unsigned char dec[32]    = {0};
    CK_ULONG elen = sizeof(enc), dlen = sizeof(dec);

    CK_MECHANISM m = { CKM_AES_CTR, &ctr, sizeof(ctr) };

    CK_RV rv = ctx->mod.fn->C_EncryptInit(ctx->rw_session, &m, key);
    if (rv == CKR_MECHANISM_INVALID) { ctx->mod.fn->C_DestroyObject(ctx->rw_session, key); SKIP("AES-CTR not supported"); }
    ASSERT_RV_OK(rv, "EncryptInit AES-CTR");
    rv = ctx->mod.fn->C_Encrypt(ctx->rw_session, plain, sizeof(plain), enc, &elen);
    ASSERT_RV_OK(rv, "Encrypt AES-CTR");

    rv = ctx->mod.fn->C_DecryptInit(ctx->rw_session, &m, key);
    ASSERT_RV_OK(rv, "DecryptInit AES-CTR");
    rv = ctx->mod.fn->C_Decrypt(ctx->rw_session, enc, elen, dec, &dlen);
    ASSERT_RV_OK(rv, "Decrypt AES-CTR");
    ASSERT_MEM_EQ(dec, plain, sizeof(plain), "CTR roundtrip");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

/* ---- Multi-part encrypt/decrypt ---- */
static int test_aes_multipart_encrypt(TestCtx *ctx)
{
    CK_OBJECT_HANDLE key = make_aes_key(ctx, 128);
    ASSERT_NE(key, CK_INVALID_HANDLE, "AES key");

    unsigned char iv[16]    = {0};
    unsigned char plain1[16] = "First block....";
    unsigned char plain2[16] = "Second block....";
    unsigned char cipher[64] = {0};
    unsigned char out1[32]   = {0};
    unsigned char out2[32]   = {0};
    unsigned char final[32]  = {0};
    CK_ULONG out1_len = sizeof(out1), out2_len = sizeof(out2), final_len = sizeof(final);

    CK_MECHANISM m = { CKM_AES_CBC_PAD, iv, sizeof(iv) };

    CK_RV rv = ctx->mod.fn->C_EncryptInit(ctx->rw_session, &m, key);
    ASSERT_RV_OK(rv, "EncryptInit multi");
    rv = ctx->mod.fn->C_EncryptUpdate(ctx->rw_session, plain1, sizeof(plain1), out1, &out1_len);
    ASSERT_RV_OK(rv, "EncryptUpdate 1");
    rv = ctx->mod.fn->C_EncryptUpdate(ctx->rw_session, plain2, sizeof(plain2), out2, &out2_len);
    ASSERT_RV_OK(rv, "EncryptUpdate 2");
    rv = ctx->mod.fn->C_EncryptFinal(ctx->rw_session, final, &final_len);
    ASSERT_RV_OK(rv, "EncryptFinal");

    /* Build full ciphertext */
    CK_ULONG total_cipher = out1_len + out2_len + final_len;
    memcpy(cipher, out1, out1_len);
    memcpy(cipher + out1_len, out2, out2_len);
    memcpy(cipher + out1_len + out2_len, final, final_len);

    /* Now decrypt in one shot and compare */
    unsigned char dec[64]  = {0};
    CK_ULONG dec_len = sizeof(dec);
    rv = ctx->mod.fn->C_DecryptInit(ctx->rw_session, &m, key);
    ASSERT_RV_OK(rv, "DecryptInit");
    rv = ctx->mod.fn->C_Decrypt(ctx->rw_session, cipher, total_cipher, dec, &dec_len);
    ASSERT_RV_OK(rv, "Decrypt multi result");
    ASSERT_EQ(dec_len, (CK_ULONG)(sizeof(plain1) + sizeof(plain2)), "Decrypted length");
    ASSERT_MEM_EQ(dec, plain1, sizeof(plain1), "First block matches");
    ASSERT_MEM_EQ(dec + sizeof(plain1), plain2, sizeof(plain2), "Second block matches");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

/* ---- Encrypt without init ---- */
static int test_encrypt_no_init(TestCtx *ctx)
{
    unsigned char plain[16] = {0};
    unsigned char cipher[32]= {0};
    CK_ULONG clen = sizeof(cipher);
    CK_RV rv = ctx->mod.fn->C_Encrypt(ctx->rw_session, plain, sizeof(plain), cipher, &clen);
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "Encrypt without EncryptInit");
    TEST_PASS();
}

/* ---- EncryptUpdate without init ---- */
static int test_encrypt_update_no_init(TestCtx *ctx)
{
    unsigned char plain[16] = {0};
    unsigned char out[32]   = {0};
    CK_ULONG olen = sizeof(out);
    CK_RV rv = ctx->mod.fn->C_EncryptUpdate(ctx->rw_session, plain, sizeof(plain), out, &olen);
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "EncryptUpdate without init");
    TEST_PASS();
}

/* ---- Buffer too small ---- */
static int test_encrypt_buffer_too_small(TestCtx *ctx)
{
    CK_OBJECT_HANDLE key = make_aes_key(ctx, 128);
    ASSERT_NE(key, CK_INVALID_HANDLE, "AES key");

    unsigned char iv[16]    = {0};
    unsigned char plain[16] = "test buffer size";
    unsigned char tiny[1]   = {0};
    CK_ULONG tiny_len = sizeof(tiny);

    CK_MECHANISM m = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    CK_RV rv = ctx->mod.fn->C_EncryptInit(ctx->rw_session, &m, key);
    ASSERT_RV_OK(rv, "EncryptInit");
    rv = ctx->mod.fn->C_Encrypt(ctx->rw_session, plain, sizeof(plain), tiny, &tiny_len);
    int result = 0;
    if (rv != CKR_BUFFER_TOO_SMALL) {
        log_fail("Expected CKR_BUFFER_TOO_SMALL, got %s", pkcs11_rv_str(rv));
        result = -1;
    } else if (tiny_len <= 1) {
        log_fail("Required length not returned");
        result = -1;
    }
    /* Complete the operation with the proper size to avoid OPERATION_ACTIVE */
    unsigned char *proper = malloc(tiny_len + 16);
    CK_ULONG proper_len = tiny_len + 16;
    ctx->mod.fn->C_Encrypt(ctx->rw_session, plain, sizeof(plain), proper, &proper_len);
    free(proper);

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    return result;
}

/* ---- Get output length first ---- */
static int test_encrypt_get_output_length(TestCtx *ctx)
{
    CK_OBJECT_HANDLE key = make_aes_key(ctx, 128);
    ASSERT_NE(key, CK_INVALID_HANDLE, "AES key");

    unsigned char iv[16]    = {0};
    unsigned char plain[32] = "length query test input data!!!";
    CK_ULONG needed = 0;

    CK_MECHANISM m = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    CK_RV rv = ctx->mod.fn->C_EncryptInit(ctx->rw_session, &m, key);
    ASSERT_RV_OK(rv, "EncryptInit");
    /* NULL output: op stays active, returns required length */
    rv = ctx->mod.fn->C_Encrypt(ctx->rw_session, plain, sizeof(plain), NULL_PTR, &needed);
    ASSERT_RV_OK(rv, "Encrypt get length");
    ASSERT_TRUE(needed > 0, "Required length > 0");

    /* Second call with proper buffer — does NOT need re-init */
    unsigned char *cipher = malloc(needed);
    rv = ctx->mod.fn->C_Encrypt(ctx->rw_session, plain, sizeof(plain), cipher, &needed);
    ASSERT_RV_OK(rv, "Encrypt with correct length");
    free(cipher);

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

BEGIN_TESTS(crypto_sym)
    ADD_TEST("AES_128_CBC",             test_aes128_cbc);
    ADD_TEST("AES_192_CBC",             test_aes192_cbc);
    ADD_TEST("AES_256_CBC",             test_aes256_cbc);
    ADD_TEST("AES_ECB",                 test_aes_ecb_roundtrip);
    ADD_TEST("AES_GCM",                 test_aes_gcm_roundtrip);
    ADD_TEST("AES_CTR",                 test_aes_ctr_roundtrip);
    ADD_TEST("AES_multipart_encrypt",   test_aes_multipart_encrypt);
    ADD_TEST("Encrypt_no_init",         test_encrypt_no_init);
    ADD_TEST("EncryptUpdate_no_init",   test_encrypt_update_no_init);
    ADD_TEST("Encrypt_buffer_too_small",test_encrypt_buffer_too_small);
    ADD_TEST("Encrypt_get_output_len",  test_encrypt_get_output_length);
END_TESTS()
