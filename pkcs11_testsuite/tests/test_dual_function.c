#include "test_framework.h"
#include <string.h>
#include <stdlib.h>

/*
 * Dual-function cryptography: C_DigestEncryptUpdate / C_DecryptDigestUpdate
 * and C_SignEncryptUpdate / C_DecryptVerifyUpdate.
 * SoftHSM may not support all of these; we skip gracefully.
 */

static CK_OBJECT_HANDLE gen_aes(TestCtx *ctx, CK_ULONG bits)
{
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG klen = bits / 8;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &f,    sizeof(f)    },
        { CKA_ENCRYPT,   &t,    sizeof(t)    },
        { CKA_DECRYPT,   &t,    sizeof(t)    },
        { CKA_VALUE_LEN, &klen, sizeof(klen) },
    };
    CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ctx->mod.fn->C_GenerateKey(ctx->rw_session, &m, tmpl, 4, &key);
    return key;
}

/* DigestEncryptUpdate */
static int test_digest_encrypt_update(TestCtx *ctx)
{
    CK_OBJECT_HANDLE key = gen_aes(ctx, 128);
    ASSERT_NE(key, CK_INVALID_HANDLE, "AES key");

    unsigned char iv[16]   = {0};
    CK_MECHANISM enc_m = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    CK_MECHANISM dig_m = { CKM_SHA256, NULL_PTR, 0 };

    unsigned char plain[32] = "dual function test data 1234567";
    unsigned char out[64]   = {0};
    CK_ULONG out_len = sizeof(out);

    CK_RV rv = ctx->mod.fn->C_EncryptInit(ctx->rw_session, &enc_m, key);
    if (rv != CKR_OK) { ctx->mod.fn->C_DestroyObject(ctx->rw_session, key); SKIP("EncryptInit failed"); }

    rv = ctx->mod.fn->C_DigestInit(ctx->rw_session, &dig_m);
    if (rv != CKR_OK) {
        /* SoftHSM2 doesn't allow concurrent Encrypt+Digest — drain Encrypt and skip */
        ctx->mod.fn->C_Encrypt(ctx->rw_session, plain, sizeof(plain), out, &out_len);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
        SKIP("DigestInit while EncryptInit active not supported");
    }

    rv = ctx->mod.fn->C_DigestEncryptUpdate(ctx->rw_session, plain, sizeof(plain), out, &out_len);
    int skip_flag = (rv == CKR_FUNCTION_NOT_SUPPORTED);
    int result = (rv == CKR_OK || rv == CKR_FUNCTION_NOT_SUPPORTED) ? 0 : -1;
    if (result != 0) log_fail("C_DigestEncryptUpdate: %s", pkcs11_rv_str(rv));

    /* Always abort both operations regardless of outcome */
    unsigned char final_enc[128]; CK_ULONG flen = sizeof(final_enc);
    ctx->mod.fn->C_EncryptFinal(ctx->rw_session, final_enc, &flen);
    unsigned char digest[64]; CK_ULONG dlen = sizeof(digest);
    ctx->mod.fn->C_DigestFinal(ctx->rw_session, digest, &dlen);

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    if (skip_flag) SKIP("C_DigestEncryptUpdate not supported");
    return result;
}

/* DecryptDigestUpdate */
static int test_decrypt_digest_update(TestCtx *ctx)
{
    CK_OBJECT_HANDLE key = gen_aes(ctx, 128);
    ASSERT_NE(key, CK_INVALID_HANDLE, "AES key");

    unsigned char iv[16] = {0};
    /* First encrypt some data */
    CK_MECHANISM enc_m = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    unsigned char plain[32]  = "decrypt-digest test data .......";
    unsigned char cipher[64] = {0};
    CK_ULONG clen = sizeof(cipher);

    ctx->mod.fn->C_EncryptInit(ctx->rw_session, &enc_m, key);
    ctx->mod.fn->C_Encrypt(ctx->rw_session, plain, sizeof(plain), cipher, &clen);

    /* Now DecryptDigestUpdate — ensure no leftover ops from prep encrypt */
    unsigned char tmp_clr[64]; CK_ULONG tmp_cl = sizeof(tmp_clr);
    ctx->mod.fn->C_EncryptFinal(ctx->rw_session, tmp_clr, &tmp_cl);
    tmp_cl = sizeof(tmp_clr);
    ctx->mod.fn->C_DigestFinal(ctx->rw_session, tmp_clr, &tmp_cl);

    CK_MECHANISM dig_m = { CKM_SHA256, NULL_PTR, 0 };
    CK_RV rv = ctx->mod.fn->C_DecryptInit(ctx->rw_session, &enc_m, key);
    if (rv != CKR_OK) { ctx->mod.fn->C_DestroyObject(ctx->rw_session, key); SKIP("DecryptInit failed"); }

    rv = ctx->mod.fn->C_DigestInit(ctx->rw_session, &dig_m);
    if (rv != CKR_OK) {
        unsigned char drain[64]; CK_ULONG dl = sizeof(drain);
        ctx->mod.fn->C_Decrypt(ctx->rw_session, cipher, clen, drain, &dl);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
        SKIP("DigestInit while DecryptInit active not supported");
    }

    unsigned char dec_out[64] = {0};
    CK_ULONG dec_out_len = sizeof(dec_out);
    rv = ctx->mod.fn->C_DecryptDigestUpdate(ctx->rw_session, cipher, clen, dec_out, &dec_out_len);
    int skip_flag2 = (rv == CKR_FUNCTION_NOT_SUPPORTED);
    int result2 = (rv == CKR_OK || rv == CKR_FUNCTION_NOT_SUPPORTED) ? 0 : -1;
    if (result2 != 0) log_fail("C_DecryptDigestUpdate: %s", pkcs11_rv_str(rv));

    unsigned char final_dec[64]; CK_ULONG fdlen = sizeof(final_dec);
    ctx->mod.fn->C_DecryptFinal(ctx->rw_session, final_dec, &fdlen);
    unsigned char digest[64]; CK_ULONG dglen = sizeof(digest);
    ctx->mod.fn->C_DigestFinal(ctx->rw_session, digest, &dglen);

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    if (skip_flag2) SKIP("C_DecryptDigestUpdate not supported");
    return result2;
}

/* SignEncryptUpdate */
static int test_sign_encrypt_update(TestCtx *ctx)
{
    /* Generate HMAC key */
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG klen = 32;
    CK_ATTRIBUTE hmac_tmpl[] = {
        { CKA_TOKEN,     &f,    sizeof(f)    },
        { CKA_SIGN,      &t,    sizeof(t)    },
        { CKA_VALUE_LEN, &klen, sizeof(klen) },
    };
    CK_MECHANISM gen_m = { CKM_GENERIC_SECRET_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE hmac_key = CK_INVALID_HANDLE;
    CK_RV rv = ctx->mod.fn->C_GenerateKey(ctx->rw_session, &gen_m, hmac_tmpl, 3, &hmac_key);
    if (rv != CKR_OK) SKIP("GENERIC_SECRET_KEY_GEN not available");

    CK_OBJECT_HANDLE enc_key = gen_aes(ctx, 128);
    ASSERT_NE(enc_key, CK_INVALID_HANDLE, "AES enc key");

    unsigned char iv[16] = {0};
    CK_MECHANISM enc_m = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    CK_MECHANISM sig_m = { CKM_SHA256_HMAC, NULL_PTR, 0 };

    rv = ctx->mod.fn->C_SignInit(ctx->rw_session, &sig_m, hmac_key);
    if (rv != CKR_OK) {
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, hmac_key);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, enc_key);
        SKIP("HMAC_SHA256 sign not supported");
    }
    rv = ctx->mod.fn->C_EncryptInit(ctx->rw_session, &enc_m, enc_key);
    if (rv != CKR_OK) {
        /* SoftHSM2 can't have Sign+Encrypt active simultaneously — drain Sign and skip */
        unsigned char sbuf[128]; CK_ULONG sbl = sizeof(sbuf);
        ctx->mod.fn->C_SignFinal(ctx->rw_session, sbuf, &sbl);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, hmac_key);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, enc_key);
        SKIP("EncryptInit while SignInit active not supported");
    }

    unsigned char plain[32] = "sign-encrypt dual function test!";
    unsigned char out[64]   = {0};
    CK_ULONG out_len = sizeof(out);
    rv = ctx->mod.fn->C_SignEncryptUpdate(ctx->rw_session, plain, sizeof(plain), out, &out_len);
    if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
        unsigned char sbuf[128]; CK_ULONG sbl = sizeof(sbuf);
        unsigned char ebuf[128]; CK_ULONG ebl = sizeof(ebuf);
        ctx->mod.fn->C_Encrypt(ctx->rw_session, plain, sizeof(plain), ebuf, &ebl);
        ctx->mod.fn->C_EncryptFinal(ctx->rw_session, ebuf, &ebl);
        ctx->mod.fn->C_SignFinal(ctx->rw_session, sbuf, &sbl);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, hmac_key);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, enc_key);
        SKIP("C_SignEncryptUpdate not supported");
    }
    ASSERT_RV_OK(rv, "C_SignEncryptUpdate");

    unsigned char sig[64]; CK_ULONG slen = sizeof(sig);
    unsigned char enc_final[32]; CK_ULONG elen = sizeof(enc_final);
    ctx->mod.fn->C_SignFinal(ctx->rw_session, sig, &slen);
    ctx->mod.fn->C_EncryptFinal(ctx->rw_session, enc_final, &elen);

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, hmac_key);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, enc_key);
    TEST_PASS();
}

BEGIN_TESTS(dual_function)
    ADD_TEST("DigestEncryptUpdate",   test_digest_encrypt_update);
    ADD_TEST("DecryptDigestUpdate",   test_decrypt_digest_update);
    ADD_TEST("SignEncryptUpdate",      test_sign_encrypt_update);
END_TESTS()
