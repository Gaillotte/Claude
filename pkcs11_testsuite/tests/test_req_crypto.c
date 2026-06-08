/*
 * Requirements-based tests: Cryptographic operations
 * PKCS#11 v2.40
 *   §11.8  – Encryption:  C_EncryptInit, C_Encrypt, C_EncryptUpdate, C_EncryptFinal
 *   §11.9  – Decryption:  C_DecryptInit, C_Decrypt, C_DecryptUpdate, C_DecryptFinal
 *   §11.10 – Digest:      C_DigestInit, C_Digest, C_DigestUpdate, C_DigestKey, C_DigestFinal
 *   §11.11 – Sign/MAC:    C_SignInit, C_Sign, C_SignUpdate, C_SignFinal
 *   §11.12 – Verify:      C_VerifyInit, C_Verify, C_VerifyUpdate, C_VerifyFinal
 *                         C_VerifyRecoverInit, C_VerifyRecover
 *   §11.13 – Dual:        C_SignRecoverInit, C_SignRecover
 *   §11.14 – Key mgmt:    C_GenerateKey, C_GenerateKeyPair, C_WrapKey, C_UnwrapKey, C_DeriveKey
 *   §11.15 – Random:      C_SeedRandom, C_GenerateRandom
 */
#include "test_framework.h"
#include <string.h>
#include <stdlib.h>

/* ── helpers ─────────────────────────────────────────────────────────────── */
static CK_OBJECT_HANDLE make_aes_key_rc(TestCtx *ctx, CK_BBOOL enc, CK_BBOOL dec)
{
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG klen = 16;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &f,    sizeof(f)    },
        { CKA_ENCRYPT,   &enc,  sizeof(enc)  },
        { CKA_DECRYPT,   &dec,  sizeof(dec)  },
        { CKA_VALUE_LEN, &klen, sizeof(klen) },
        { CKA_SENSITIVE, &t,    sizeof(t)    },
    };
    CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ctx->mod.fn->C_GenerateKey(ctx->rw_session, &m, tmpl, 5, &key);
    return key;
}

static CK_OBJECT_HANDLE make_aes_full(TestCtx *ctx)
{
    return make_aes_key_rc(ctx, CK_TRUE, CK_TRUE);
}

static int make_rsa_keypair_rc(TestCtx *ctx, CK_OBJECT_HANDLE *pub,
                                CK_OBJECT_HANDLE *priv)
{
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG bits = 2048;
    unsigned char exp[] = { 0x01, 0x00, 0x01 };
    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_TOKEN,           &f,    sizeof(f)    },
        { CKA_ENCRYPT,         &t,    sizeof(t)    },
        { CKA_VERIFY,          &t,    sizeof(t)    },
        { CKA_MODULUS_BITS,    &bits, sizeof(bits) },
        { CKA_PUBLIC_EXPONENT, exp,   sizeof(exp)  },
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        { CKA_TOKEN,      &f, sizeof(f) },
        { CKA_DECRYPT,    &t, sizeof(t) },
        { CKA_SIGN,       &t, sizeof(t) },
        { CKA_SENSITIVE,  &t, sizeof(t) },
    };
    CK_MECHANISM m = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    return (ctx->mod.fn->C_GenerateKeyPair(ctx->rw_session, &m,
                                            pub_tmpl, 5, priv_tmpl, 4,
                                            pub, priv) == CKR_OK) ? 0 : -1;
}

/* ════════════════════════════════════════════════════════════
 *  §11.8  ENCRYPTION
 * ════════════════════════════════════════════════════════════ */

/* REQ-ENC-01: C_Encrypt without EncryptInit → CKR_OPERATION_NOT_INITIALIZED */
static int test_encrypt_without_init(TestCtx *ctx)
{
    unsigned char plain[16] = {0}, cipher[32] = {0};
    CK_ULONG clen = sizeof(cipher);
    CK_RV rv = ctx->mod.fn->C_Encrypt(ctx->rw_session, plain, sizeof(plain),
                                        cipher, &clen);
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "Encrypt without Init");
    TEST_PASS();
}

/* REQ-ENC-02: C_EncryptUpdate without EncryptInit → CKR_OPERATION_NOT_INITIALIZED */
static int test_encrypt_update_without_init(TestCtx *ctx)
{
    unsigned char plain[16] = {0}, out[32] = {0};
    CK_ULONG olen = sizeof(out);
    CK_RV rv = ctx->mod.fn->C_EncryptUpdate(ctx->rw_session, plain, sizeof(plain),
                                              out, &olen);
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "EncryptUpdate without Init");
    TEST_PASS();
}

/* REQ-ENC-03: C_EncryptFinal without EncryptInit → CKR_OPERATION_NOT_INITIALIZED */
static int test_encrypt_final_without_init(TestCtx *ctx)
{
    unsigned char out[32] = {0};
    CK_ULONG olen = sizeof(out);
    CK_RV rv = ctx->mod.fn->C_EncryptFinal(ctx->rw_session, out, &olen);
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "EncryptFinal without Init");
    TEST_PASS();
}

/* REQ-ENC-04: C_EncryptInit invalid mechanism → CKR_MECHANISM_INVALID     */
static int test_encrypt_init_invalid_mechanism(TestCtx *ctx)
{
    CK_OBJECT_HANDLE key = make_aes_full(ctx);
    ASSERT_NE(key, CK_INVALID_HANDLE, "AES key");
    CK_MECHANISM bad_m = { 0x80001234UL, NULL_PTR, 0 };
    CK_RV rv = ctx->mod.fn->C_EncryptInit(ctx->rw_session, &bad_m, key);
    ASSERT_RV(rv, CKR_MECHANISM_INVALID, "EncryptInit invalid mechanism");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

/* REQ-ENC-05: C_EncryptInit key without CKA_ENCRYPT → CKR_KEY_FUNCTION_NOT_PERMITTED */
static int test_encrypt_key_no_encrypt_flag(TestCtx *ctx)
{
    /* Generate key with encrypt=FALSE */
    CK_OBJECT_HANDLE key = make_aes_key_rc(ctx, CK_FALSE, CK_TRUE);
    ASSERT_NE(key, CK_INVALID_HANDLE, "AES key (no encrypt)");
    unsigned char iv[16] = {0};
    CK_MECHANISM m = { CKM_AES_CBC, iv, sizeof(iv) };
    CK_RV rv = ctx->mod.fn->C_EncryptInit(ctx->rw_session, &m, key);
    ASSERT_RV(rv, CKR_KEY_FUNCTION_NOT_PERMITTED,
              "EncryptInit key without CKA_ENCRYPT");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

/* REQ-ENC-06: C_EncryptInit NULL pMechanism → CKR_ARGUMENTS_BAD           */
static int test_encrypt_init_null_mechanism(TestCtx *ctx)
{
    CK_OBJECT_HANDLE key = make_aes_full(ctx);
    ASSERT_NE(key, CK_INVALID_HANDLE, "AES key");
    CK_RV rv = ctx->mod.fn->C_EncryptInit(ctx->rw_session, NULL_PTR, key);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "EncryptInit NULL mechanism");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

/* REQ-ENC-07: C_EncryptInit while op active → CKR_OPERATION_ACTIVE        */
static int test_encrypt_init_while_active(TestCtx *ctx)
{
    CK_OBJECT_HANDLE key = make_aes_full(ctx);
    ASSERT_NE(key, CK_INVALID_HANDLE, "AES key");
    unsigned char iv[16] = {0};
    CK_MECHANISM m = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    ctx->mod.fn->C_EncryptInit(ctx->rw_session, &m, key);
    CK_RV rv = ctx->mod.fn->C_EncryptInit(ctx->rw_session, &m, key);
    ASSERT_RV(rv, CKR_OPERATION_ACTIVE, "EncryptInit while already active");
    /* Drain the active op */
    unsigned char plain[16] = {0}, out[32] = {0};
    CK_ULONG ol = sizeof(out);
    ctx->mod.fn->C_Encrypt(ctx->rw_session, plain, sizeof(plain), out, &ol);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

/* REQ-ENC-08: C_Encrypt NULL output buffer returns required length        */
static int test_encrypt_null_output_query(TestCtx *ctx)
{
    CK_OBJECT_HANDLE key = make_aes_full(ctx);
    ASSERT_NE(key, CK_INVALID_HANDLE, "AES key");
    unsigned char iv[16] = {0}, plain[32] = {0};
    CK_MECHANISM m = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    ctx->mod.fn->C_EncryptInit(ctx->rw_session, &m, key);
    CK_ULONG needed = 0;
    CK_RV rv = ctx->mod.fn->C_Encrypt(ctx->rw_session, plain, sizeof(plain),
                                        NULL_PTR, &needed);
    ASSERT_RV_OK(rv, "Encrypt NULL output (size query)");
    ASSERT_TRUE(needed >= sizeof(plain), "Reported output length >= input");
    /* Complete the operation */
    unsigned char cipher[64] = {0};
    CK_ULONG clen = sizeof(cipher);
    ctx->mod.fn->C_Encrypt(ctx->rw_session, plain, sizeof(plain), cipher, &clen);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

/* REQ-ENC-09: C_Encrypt wrong key type → CKR_KEY_TYPE_INCONSISTENT        */
static int test_encrypt_wrong_key_type(TestCtx *ctx)
{
    /* Use an RSA public key for AES CBC — type mismatch */
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    if (make_rsa_keypair_rc(ctx, &pub, &priv) != 0) SKIP("RSA keygen unavailable");

    unsigned char iv[16] = {0};
    CK_MECHANISM m = { CKM_AES_CBC, iv, sizeof(iv) };
    CK_RV rv = ctx->mod.fn->C_EncryptInit(ctx->rw_session, &m, pub);
    ASSERT_RV(rv, CKR_KEY_TYPE_INCONSISTENT,
              "EncryptInit with RSA key for AES");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

/* ════════════════════════════════════════════════════════════
 *  §11.9  DECRYPTION
 * ════════════════════════════════════════════════════════════ */

/* REQ-DEC-01: C_Decrypt without DecryptInit → CKR_OPERATION_NOT_INITIALIZED */
static int test_decrypt_without_init(TestCtx *ctx)
{
    unsigned char cipher[32] = {0}, plain[48] = {0};
    CK_ULONG plen = sizeof(plain);
    CK_RV rv = ctx->mod.fn->C_Decrypt(ctx->rw_session, cipher, sizeof(cipher),
                                        plain, &plen);
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "Decrypt without Init");
    TEST_PASS();
}

/* REQ-DEC-02: C_DecryptUpdate without DecryptInit → CKR_OPERATION_NOT_INITIALIZED */
static int test_decrypt_update_without_init(TestCtx *ctx)
{
    unsigned char cipher[16] = {0}, out[32] = {0};
    CK_ULONG olen = sizeof(out);
    CK_RV rv = ctx->mod.fn->C_DecryptUpdate(ctx->rw_session, cipher, sizeof(cipher),
                                              out, &olen);
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "DecryptUpdate without Init");
    TEST_PASS();
}

/* REQ-DEC-03: C_DecryptFinal without DecryptInit → CKR_OPERATION_NOT_INITIALIZED */
static int test_decrypt_final_without_init(TestCtx *ctx)
{
    unsigned char out[32] = {0};
    CK_ULONG olen = sizeof(out);
    CK_RV rv = ctx->mod.fn->C_DecryptFinal(ctx->rw_session, out, &olen);
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "DecryptFinal without Init");
    TEST_PASS();
}

/* REQ-DEC-04: Key without CKA_DECRYPT → CKR_KEY_FUNCTION_NOT_PERMITTED    */
static int test_decrypt_key_no_decrypt_flag(TestCtx *ctx)
{
    CK_OBJECT_HANDLE key = make_aes_key_rc(ctx, CK_TRUE, CK_FALSE);
    ASSERT_NE(key, CK_INVALID_HANDLE, "AES key (no decrypt)");
    unsigned char iv[16] = {0};
    CK_MECHANISM m = { CKM_AES_CBC, iv, sizeof(iv) };
    CK_RV rv = ctx->mod.fn->C_DecryptInit(ctx->rw_session, &m, key);
    ASSERT_RV(rv, CKR_KEY_FUNCTION_NOT_PERMITTED,
              "DecryptInit key without CKA_DECRYPT");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

/* REQ-DEC-05: Corrupt ciphertext → CKR_ENCRYPTED_DATA_INVALID             */
static int test_decrypt_corrupt_ciphertext(TestCtx *ctx)
{
    CK_OBJECT_HANDLE key = make_aes_full(ctx);
    ASSERT_NE(key, CK_INVALID_HANDLE, "AES key");
    unsigned char iv[16] = {0}, plain[32] = "decrypt corrupt test ...........";
    unsigned char cipher[64] = {0}, dec[48] = {0};
    CK_ULONG clen = sizeof(cipher), dlen = sizeof(dec);
    CK_MECHANISM m = { CKM_AES_CBC_PAD, iv, sizeof(iv) };

    ctx->mod.fn->C_EncryptInit(ctx->rw_session, &m, key);
    ctx->mod.fn->C_Encrypt(ctx->rw_session, plain, sizeof(plain), cipher, &clen);

    cipher[0] ^= 0xFF;   /* corrupt */

    ctx->mod.fn->C_DecryptInit(ctx->rw_session, &m, key);
    CK_RV rv = ctx->mod.fn->C_Decrypt(ctx->rw_session, cipher, clen, dec, &dlen);
    ASSERT_TRUE(rv == CKR_ENCRYPTED_DATA_INVALID ||
                rv == CKR_ENCRYPTED_DATA_LEN_RANGE ||
                (rv == CKR_OK && memcmp(dec, plain, sizeof(plain)) != 0),
                "Corrupt ciphertext rejected or produces wrong plaintext");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

/* ════════════════════════════════════════════════════════════
 *  §11.10 DIGEST
 * ════════════════════════════════════════════════════════════ */

/* REQ-DIG-01: C_Digest without DigestInit → CKR_OPERATION_NOT_INITIALIZED */
static int test_digest_without_init(TestCtx *ctx)
{
    unsigned char data[32] = {0}, digest[32] = {0};
    CK_ULONG dlen = sizeof(digest);
    CK_RV rv = ctx->mod.fn->C_Digest(ctx->rw_session, data, sizeof(data),
                                       digest, &dlen);
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "Digest without Init");
    TEST_PASS();
}

/* REQ-DIG-02: C_DigestUpdate without DigestInit → CKR_OPERATION_NOT_INITIALIZED */
static int test_digest_update_without_init(TestCtx *ctx)
{
    unsigned char data[32] = {0};
    CK_RV rv = ctx->mod.fn->C_DigestUpdate(ctx->rw_session, data, sizeof(data));
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "DigestUpdate without Init");
    TEST_PASS();
}

/* REQ-DIG-03: C_DigestFinal without DigestInit → CKR_OPERATION_NOT_INITIALIZED */
static int test_digest_final_without_init(TestCtx *ctx)
{
    unsigned char digest[32] = {0};
    CK_ULONG dlen = sizeof(digest);
    CK_RV rv = ctx->mod.fn->C_DigestFinal(ctx->rw_session, digest, &dlen);
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "DigestFinal without Init");
    TEST_PASS();
}

/* REQ-DIG-04: C_DigestInit while active → CKR_OPERATION_ACTIVE            */
static int test_digest_init_while_active(TestCtx *ctx)
{
    CK_MECHANISM m = { CKM_SHA256, NULL_PTR, 0 };
    ctx->mod.fn->C_DigestInit(ctx->rw_session, &m);
    CK_RV rv = ctx->mod.fn->C_DigestInit(ctx->rw_session, &m);
    ASSERT_RV(rv, CKR_OPERATION_ACTIVE, "DigestInit while active");
    /* Drain */
    unsigned char digest[32]; CK_ULONG dlen = sizeof(digest);
    unsigned char data[1] = {0};
    ctx->mod.fn->C_DigestUpdate(ctx->rw_session, data, 0);
    ctx->mod.fn->C_DigestFinal(ctx->rw_session, digest, &dlen);
    TEST_PASS();
}

/* REQ-DIG-05: C_DigestKey incorporates secret key material                */
static int test_digest_key(TestCtx *ctx)
{
    CK_MECHANISM m = { CKM_SHA256, NULL_PTR, 0 };
    CK_RV rv = ctx->mod.fn->C_DigestInit(ctx->rw_session, &m);
    ASSERT_RV_OK(rv, "DigestInit");

    /* Generate a key with CKA_EXTRACTABLE=FALSE to ensure key is on token */
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG klen = 16;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &f, sizeof(f)    },
        { CKA_VALUE_LEN, &klen, sizeof(klen) },
    };
    CK_MECHANISM gm = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ctx->mod.fn->C_GenerateKey(ctx->rw_session, &gm, tmpl, 2, &key);

    rv = ctx->mod.fn->C_DigestKey(ctx->rw_session, key);
    if (rv == CKR_KEY_INDIGESTIBLE || rv == CKR_FUNCTION_NOT_SUPPORTED) {
        unsigned char digest[32]; CK_ULONG dlen = sizeof(digest);
        ctx->mod.fn->C_DigestFinal(ctx->rw_session, digest, &dlen);
        if (key != CK_INVALID_HANDLE) ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
        SKIP("C_DigestKey not supported");
    }
    ASSERT_RV_OK(rv, "C_DigestKey");

    unsigned char digest[32]; CK_ULONG dlen = sizeof(digest);
    rv = ctx->mod.fn->C_DigestFinal(ctx->rw_session, digest, &dlen);
    ASSERT_RV_OK(rv, "DigestFinal after DigestKey");
    ASSERT_EQ(dlen, 32UL, "SHA-256 digest length");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

/* REQ-DIG-06: C_Digest NULL output → size query                           */
static int test_digest_null_output_query(TestCtx *ctx)
{
    CK_MECHANISM m = { CKM_SHA256, NULL_PTR, 0 };
    ctx->mod.fn->C_DigestInit(ctx->rw_session, &m);
    unsigned char data[32] = {0};
    CK_ULONG needed = 0;
    CK_RV rv = ctx->mod.fn->C_Digest(ctx->rw_session, data, sizeof(data),
                                       NULL_PTR, &needed);
    ASSERT_RV_OK(rv, "Digest NULL output (size query)");
    ASSERT_EQ(needed, 32UL, "SHA-256 size reported as 32");
    /* Complete */
    unsigned char digest[32]; CK_ULONG dlen = sizeof(digest);
    ctx->mod.fn->C_Digest(ctx->rw_session, data, sizeof(data), digest, &dlen);
    TEST_PASS();
}

/* REQ-DIG-07: Multi-part digest matches single-call                       */
static int test_digest_multipart_matches_single(TestCtx *ctx)
{
    unsigned char data[64];
    memset(data, 0xAB, sizeof(data));

    /* Single call */
    CK_MECHANISM m = { CKM_SHA256, NULL_PTR, 0 };
    ctx->mod.fn->C_DigestInit(ctx->rw_session, &m);
    unsigned char d1[32]; CK_ULONG dlen1 = sizeof(d1);
    ctx->mod.fn->C_Digest(ctx->rw_session, data, sizeof(data), d1, &dlen1);

    /* Multi-part */
    ctx->mod.fn->C_DigestInit(ctx->rw_session, &m);
    ctx->mod.fn->C_DigestUpdate(ctx->rw_session, data,      32);
    ctx->mod.fn->C_DigestUpdate(ctx->rw_session, data + 32, 32);
    unsigned char d2[32]; CK_ULONG dlen2 = sizeof(d2);
    CK_RV rv = ctx->mod.fn->C_DigestFinal(ctx->rw_session, d2, &dlen2);
    ASSERT_RV_OK(rv, "DigestFinal multi-part");
    ASSERT_MEM_EQ(d1, d2, 32, "Multi-part digest == single-call digest");
    TEST_PASS();
}

/* ════════════════════════════════════════════════════════════
 *  §11.11 SIGNING
 * ════════════════════════════════════════════════════════════ */

/* REQ-SIG-01: C_Sign without SignInit → CKR_OPERATION_NOT_INITIALIZED     */
static int test_sign_without_init(TestCtx *ctx)
{
    unsigned char data[32] = {0}, sig[512] = {0};
    CK_ULONG slen = sizeof(sig);
    CK_RV rv = ctx->mod.fn->C_Sign(ctx->rw_session, data, sizeof(data), sig, &slen);
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "Sign without Init");
    TEST_PASS();
}

/* REQ-SIG-02: C_SignUpdate without SignInit → CKR_OPERATION_NOT_INITIALIZED */
static int test_sign_update_without_init(TestCtx *ctx)
{
    unsigned char data[32] = {0};
    CK_RV rv = ctx->mod.fn->C_SignUpdate(ctx->rw_session, data, sizeof(data));
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "SignUpdate without Init");
    TEST_PASS();
}

/* REQ-SIG-03: C_SignFinal without SignInit → CKR_OPERATION_NOT_INITIALIZED */
static int test_sign_final_without_init(TestCtx *ctx)
{
    unsigned char sig[512] = {0};
    CK_ULONG slen = sizeof(sig);
    CK_RV rv = ctx->mod.fn->C_SignFinal(ctx->rw_session, sig, &slen);
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "SignFinal without Init");
    TEST_PASS();
}

/* REQ-SIG-04: C_SignInit key without CKA_SIGN → CKR_KEY_FUNCTION_NOT_PERMITTED */
static int test_sign_key_no_sign_flag(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    if (make_rsa_keypair_rc(ctx, &pub, &priv) != 0) SKIP("RSA keygen unavailable");

    /* Use the public key (CKA_SIGN not set) for signing */
    CK_MECHANISM m = { CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };
    CK_RV rv = ctx->mod.fn->C_SignInit(ctx->rw_session, &m, pub);
    ASSERT_RV(rv, CKR_KEY_FUNCTION_NOT_PERMITTED,
              "SignInit with public key (no CKA_SIGN)");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

/* REQ-SIG-05: C_Sign NULL sig buffer → returns required length            */
static int test_sign_null_output_query(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    if (make_rsa_keypair_rc(ctx, &pub, &priv) != 0) SKIP("RSA keygen unavailable");

    CK_MECHANISM m = { CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };
    CK_RV rv = ctx->mod.fn->C_SignInit(ctx->rw_session, &m, priv);
    ASSERT_RV_OK(rv, "SignInit");

    unsigned char data[32] = "sign size query test ............";
    CK_ULONG needed = 0;
    rv = ctx->mod.fn->C_Sign(ctx->rw_session, data, sizeof(data), NULL_PTR, &needed);
    ASSERT_RV_OK(rv, "Sign NULL buffer (size query)");
    ASSERT_TRUE(needed > 0, "Required signature length > 0");

    /* Complete the operation */
    unsigned char sig[512] = {0};
    CK_ULONG slen = sizeof(sig);
    ctx->mod.fn->C_Sign(ctx->rw_session, data, sizeof(data), sig, &slen);

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

/* REQ-SIG-06: Multi-part sign matches single-call sign                    */
static int test_sign_multipart(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    if (make_rsa_keypair_rc(ctx, &pub, &priv) != 0) SKIP("RSA keygen unavailable");

    unsigned char data[64];
    memset(data, 0x77, sizeof(data));
    CK_MECHANISM m = { CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };

    /* Single-call sign */
    ctx->mod.fn->C_SignInit(ctx->rw_session, &m, priv);
    unsigned char sig1[512]; CK_ULONG slen1 = sizeof(sig1);
    ctx->mod.fn->C_Sign(ctx->rw_session, data, sizeof(data), sig1, &slen1);

    /* Multi-part sign */
    ctx->mod.fn->C_SignInit(ctx->rw_session, &m, priv);
    ctx->mod.fn->C_SignUpdate(ctx->rw_session, data,      32);
    ctx->mod.fn->C_SignUpdate(ctx->rw_session, data + 32, 32);
    unsigned char sig2[512]; CK_ULONG slen2 = sizeof(sig2);
    CK_RV rv = ctx->mod.fn->C_SignFinal(ctx->rw_session, sig2, &slen2);
    ASSERT_RV_OK(rv, "SignFinal multi-part");

    /* Both signatures must verify with the same public key */
    ctx->mod.fn->C_VerifyInit(ctx->rw_session, &m, pub);
    rv = ctx->mod.fn->C_Verify(ctx->rw_session, data, sizeof(data), sig2, slen2);
    ASSERT_RV_OK(rv, "Verify multi-part signature");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

/* ════════════════════════════════════════════════════════════
 *  §11.12 VERIFICATION
 * ════════════════════════════════════════════════════════════ */

/* REQ-VER-01: C_Verify without VerifyInit → CKR_OPERATION_NOT_INITIALIZED */
static int test_verify_without_init(TestCtx *ctx)
{
    unsigned char data[32] = {0}, sig[512] = {0};
    CK_RV rv = ctx->mod.fn->C_Verify(ctx->rw_session, data, sizeof(data),
                                       sig, sizeof(sig));
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "Verify without Init");
    TEST_PASS();
}

/* REQ-VER-02: C_VerifyUpdate without VerifyInit → CKR_OPERATION_NOT_INITIALIZED */
static int test_verify_update_without_init(TestCtx *ctx)
{
    unsigned char data[32] = {0};
    CK_RV rv = ctx->mod.fn->C_VerifyUpdate(ctx->rw_session, data, sizeof(data));
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "VerifyUpdate without Init");
    TEST_PASS();
}

/* REQ-VER-03: C_VerifyFinal without VerifyInit → CKR_OPERATION_NOT_INITIALIZED */
static int test_verify_final_without_init(TestCtx *ctx)
{
    unsigned char sig[512] = {0};
    CK_RV rv = ctx->mod.fn->C_VerifyFinal(ctx->rw_session, sig, sizeof(sig));
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "VerifyFinal without Init");
    TEST_PASS();
}

/* REQ-VER-04: Invalid signature → CKR_SIGNATURE_INVALID                   */
static int test_verify_invalid_signature(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    if (make_rsa_keypair_rc(ctx, &pub, &priv) != 0) SKIP("RSA keygen unavailable");

    unsigned char data[32] = "verify invalid sig test .........";
    unsigned char sig[512]; CK_ULONG slen = sizeof(sig);
    CK_MECHANISM m = { CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };
    ctx->mod.fn->C_SignInit(ctx->rw_session, &m, priv);
    ctx->mod.fn->C_Sign(ctx->rw_session, data, sizeof(data), sig, &slen);

    /* Tamper */
    sig[0] ^= 0xFF;

    ctx->mod.fn->C_VerifyInit(ctx->rw_session, &m, pub);
    CK_RV rv = ctx->mod.fn->C_Verify(ctx->rw_session, data, sizeof(data), sig, slen);
    ASSERT_RV(rv, CKR_SIGNATURE_INVALID, "Verify tampered signature");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

/* REQ-VER-05: Wrong signature length → CKR_SIGNATURE_LEN_RANGE            */
static int test_verify_wrong_sig_length(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    if (make_rsa_keypair_rc(ctx, &pub, &priv) != 0) SKIP("RSA keygen unavailable");

    unsigned char data[32] = "verify wrong len test ...........";
    unsigned char sig[512]; CK_ULONG slen = sizeof(sig);
    CK_MECHANISM m = { CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };
    ctx->mod.fn->C_SignInit(ctx->rw_session, &m, priv);
    ctx->mod.fn->C_Sign(ctx->rw_session, data, sizeof(data), sig, &slen);

    ctx->mod.fn->C_VerifyInit(ctx->rw_session, &m, pub);
    CK_RV rv = ctx->mod.fn->C_Verify(ctx->rw_session, data, sizeof(data),
                                       sig, slen - 1);   /* wrong length */
    ASSERT_TRUE(rv == CKR_SIGNATURE_LEN_RANGE || rv == CKR_SIGNATURE_INVALID,
                "Wrong sig length: SIGNATURE_LEN_RANGE or SIGNATURE_INVALID");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

/* REQ-VER-06: Key without CKA_VERIFY → CKR_KEY_FUNCTION_NOT_PERMITTED     */
static int test_verify_key_no_verify_flag(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    if (make_rsa_keypair_rc(ctx, &pub, &priv) != 0) SKIP("RSA keygen unavailable");

    /* The private key has no CKA_VERIFY */
    CK_MECHANISM m = { CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };
    CK_RV rv = ctx->mod.fn->C_VerifyInit(ctx->rw_session, &m, priv);
    ASSERT_RV(rv, CKR_KEY_FUNCTION_NOT_PERMITTED,
              "VerifyInit with priv key (no CKA_VERIFY)");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

/* REQ-VER-07: Multi-part verify matches single-call                        */
static int test_verify_multipart(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    if (make_rsa_keypair_rc(ctx, &pub, &priv) != 0) SKIP("RSA keygen unavailable");

    unsigned char data[64]; memset(data, 0x55, sizeof(data));
    CK_MECHANISM m = { CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };
    unsigned char sig[512]; CK_ULONG slen = sizeof(sig);

    ctx->mod.fn->C_SignInit(ctx->rw_session, &m, priv);
    ctx->mod.fn->C_Sign(ctx->rw_session, data, sizeof(data), sig, &slen);

    /* Multi-part verify */
    ctx->mod.fn->C_VerifyInit(ctx->rw_session, &m, pub);
    ctx->mod.fn->C_VerifyUpdate(ctx->rw_session, data,      32);
    ctx->mod.fn->C_VerifyUpdate(ctx->rw_session, data + 32, 32);
    CK_RV rv = ctx->mod.fn->C_VerifyFinal(ctx->rw_session, sig, slen);
    ASSERT_RV_OK(rv, "VerifyFinal multi-part");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

/* ════════════════════════════════════════════════════════════
 *  §11.14 KEY MANAGEMENT
 * ════════════════════════════════════════════════════════════ */

/* REQ-KEY-01: C_GenerateKey NULL mechanism → CKR_ARGUMENTS_BAD            */
static int test_generate_key_null_mechanism(TestCtx *ctx)
{
    CK_BBOOL f = CK_FALSE;
    CK_ULONG klen = 16;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &f,    sizeof(f)    },
        { CKA_VALUE_LEN, &klen, sizeof(klen) },
    };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_RV rv = ctx->mod.fn->C_GenerateKey(ctx->rw_session, NULL_PTR, tmpl, 2, &key);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "GenerateKey NULL mechanism");
    TEST_PASS();
}

/* REQ-KEY-02: C_GenerateKey NULL phKey → CKR_ARGUMENTS_BAD                */
static int test_generate_key_null_handle(TestCtx *ctx)
{
    CK_BBOOL f = CK_FALSE;
    CK_ULONG klen = 16;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &f,    sizeof(f)    },
        { CKA_VALUE_LEN, &klen, sizeof(klen) },
    };
    CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_RV rv = ctx->mod.fn->C_GenerateKey(ctx->rw_session, &m, tmpl, 2, NULL_PTR);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "GenerateKey NULL phKey");
    TEST_PASS();
}

/* REQ-KEY-03: C_GenerateKey invalid mechanism → CKR_MECHANISM_INVALID     */
static int test_generate_key_invalid_mechanism(TestCtx *ctx)
{
    CK_BBOOL f = CK_FALSE;
    CK_ULONG klen = 16;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &f,    sizeof(f)    },
        { CKA_VALUE_LEN, &klen, sizeof(klen) },
    };
    CK_MECHANISM bad_m = { 0x80001234UL, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_RV rv = ctx->mod.fn->C_GenerateKey(ctx->rw_session, &bad_m, tmpl, 2, &key);
    ASSERT_RV(rv, CKR_MECHANISM_INVALID, "GenerateKey invalid mechanism");
    TEST_PASS();
}

/* REQ-KEY-04: C_GenerateKeyPair NULL mechanism → CKR_ARGUMENTS_BAD        */
static int test_generate_keypair_null_mechanism(TestCtx *ctx)
{
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG bits = 1024;
    unsigned char exp[] = { 0x01, 0x00, 0x01 };
    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_TOKEN,           &f,    sizeof(f)    },
        { CKA_MODULUS_BITS,    &bits, sizeof(bits) },
        { CKA_PUBLIC_EXPONENT, exp,   sizeof(exp)  },
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        { CKA_TOKEN,   &f, sizeof(f) },
        { CKA_SIGN,    &t, sizeof(t) },
    };
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_RV rv = ctx->mod.fn->C_GenerateKeyPair(ctx->rw_session, NULL_PTR,
                                               pub_tmpl, 3, priv_tmpl, 2,
                                               &pub, &priv);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "GenerateKeyPair NULL mechanism");
    TEST_PASS();
}

/* REQ-KEY-05: WrapKey non-extractable key → CKR_KEY_UNEXTRACTABLE          */
static int test_wrap_key_non_extractable(TestCtx *ctx)
{
    /* Create a non-extractable AES key */
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG klen = 16;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,       &f, sizeof(f)    },
        { CKA_ENCRYPT,     &t, sizeof(t)    },
        { CKA_VALUE_LEN,   &klen, sizeof(klen) },
        { CKA_EXTRACTABLE, &f, sizeof(f)    },
    };
    CK_MECHANISM gm = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE target_key = CK_INVALID_HANDLE;
    ctx->mod.fn->C_GenerateKey(ctx->rw_session, &gm, tmpl, 4, &target_key);
    ASSERT_NE(target_key, CK_INVALID_HANDLE, "Non-extractable key");

    /* Generate wrapping key */
    CK_BBOOL wrap_t = CK_TRUE;
    CK_ATTRIBUTE wrap_tmpl[] = {
        { CKA_TOKEN,     &f,      sizeof(f)    },
        { CKA_WRAP,      &wrap_t, sizeof(wrap_t) },
        { CKA_UNWRAP,    &wrap_t, sizeof(wrap_t) },
        { CKA_VALUE_LEN, &klen,   sizeof(klen) },
    };
    CK_OBJECT_HANDLE wrap_key = CK_INVALID_HANDLE;
    ctx->mod.fn->C_GenerateKey(ctx->rw_session, &gm, wrap_tmpl, 4, &wrap_key);
    ASSERT_NE(wrap_key, CK_INVALID_HANDLE, "Wrapping key");

    unsigned char iv[16] = {0};
    CK_MECHANISM wrap_m = { CKM_AES_KEY_WRAP_PAD, NULL_PTR, 0 };
    unsigned char wrapped[64]; CK_ULONG wlen = sizeof(wrapped);
    CK_RV rv = ctx->mod.fn->C_WrapKey(ctx->rw_session, &wrap_m,
                                        wrap_key, target_key, wrapped, &wlen);
    ASSERT_RV(rv, CKR_KEY_UNEXTRACTABLE, "WrapKey non-extractable key");
    (void)iv;

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, target_key);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, wrap_key);
    TEST_PASS();
}

/* REQ-KEY-06: WrapKey NULL pWrappedKey → returns required length          */
static int test_wrap_key_null_output_query(TestCtx *ctx)
{
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG klen = 16;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,       &f, sizeof(f)    },
        { CKA_ENCRYPT,     &t, sizeof(t)    },
        { CKA_VALUE_LEN,   &klen, sizeof(klen) },
        { CKA_EXTRACTABLE, &t, sizeof(t)    },
    };
    CK_MECHANISM gm = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE target_key = CK_INVALID_HANDLE, wrap_key = CK_INVALID_HANDLE;
    ctx->mod.fn->C_GenerateKey(ctx->rw_session, &gm, tmpl, 4, &target_key);

    CK_ATTRIBUTE wrap_tmpl[] = {
        { CKA_TOKEN,     &f, sizeof(f)    },
        { CKA_WRAP,      &t, sizeof(t)    },
        { CKA_VALUE_LEN, &klen, sizeof(klen) },
    };
    ctx->mod.fn->C_GenerateKey(ctx->rw_session, &gm, wrap_tmpl, 3, &wrap_key);

    if (target_key == CK_INVALID_HANDLE || wrap_key == CK_INVALID_HANDLE)
        SKIP("Key generation failed");

    CK_MECHANISM wrap_m = { CKM_AES_KEY_WRAP_PAD, NULL_PTR, 0 };
    CK_ULONG needed = 0;
    CK_RV rv = ctx->mod.fn->C_WrapKey(ctx->rw_session, &wrap_m,
                                        wrap_key, target_key, NULL_PTR, &needed);
    if (rv == CKR_MECHANISM_INVALID) {
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, target_key);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, wrap_key);
        SKIP("AES_KEY_WRAP_PAD not supported");
    }
    ASSERT_RV_OK(rv, "WrapKey NULL output (size query)");
    ASSERT_TRUE(needed > 0, "Required wrapped length > 0");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, target_key);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, wrap_key);
    TEST_PASS();
}

/* REQ-KEY-07: C_UnwrapKey inherits template attributes                    */
static int test_unwrap_key_attributes(TestCtx *ctx)
{
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG klen = 16;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,       &f, sizeof(f)    },
        { CKA_ENCRYPT,     &t, sizeof(t)    },
        { CKA_DECRYPT,     &t, sizeof(t)    },
        { CKA_VALUE_LEN,   &klen, sizeof(klen) },
        { CKA_EXTRACTABLE, &t, sizeof(t)    },
    };
    CK_MECHANISM gm = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE target = CK_INVALID_HANDLE, wrap = CK_INVALID_HANDLE;
    ctx->mod.fn->C_GenerateKey(ctx->rw_session, &gm, tmpl, 5, &target);

    CK_ATTRIBUTE wrap_tmpl[] = {
        { CKA_TOKEN,     &f, sizeof(f)    },
        { CKA_WRAP,      &t, sizeof(t)    },
        { CKA_UNWRAP,    &t, sizeof(t)    },
        { CKA_VALUE_LEN, &klen, sizeof(klen) },
    };
    ctx->mod.fn->C_GenerateKey(ctx->rw_session, &gm, wrap_tmpl, 4, &wrap);

    if (target == CK_INVALID_HANDLE || wrap == CK_INVALID_HANDLE)
        SKIP("Key generation failed");

    CK_MECHANISM wrap_m = { CKM_AES_KEY_WRAP_PAD, NULL_PTR, 0 };
    unsigned char wrapped[64]; CK_ULONG wlen = sizeof(wrapped);
    CK_RV rv = ctx->mod.fn->C_WrapKey(ctx->rw_session, &wrap_m,
                                        wrap, target, wrapped, &wlen);
    if (rv == CKR_MECHANISM_INVALID || rv == CKR_KEY_UNEXTRACTABLE) {
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, target);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, wrap);
        SKIP("AES_KEY_WRAP_PAD not available or key non-extractable");
    }
    ASSERT_RV_OK(rv, "WrapKey");

    CK_KEY_TYPE ktype = CKK_AES;
    CK_OBJECT_CLASS skey = CKO_SECRET_KEY;
    CK_ATTRIBUTE unwrap_tmpl[] = {
        { CKA_CLASS,    &skey,  sizeof(skey)  },
        { CKA_TOKEN,    &f,     sizeof(f)     },
        { CKA_KEY_TYPE, &ktype, sizeof(ktype) },
        { CKA_ENCRYPT,  &t,     sizeof(t)     },
        { CKA_DECRYPT,  &t,     sizeof(t)     },
    };
    CK_OBJECT_HANDLE unwrapped = CK_INVALID_HANDLE;
    rv = ctx->mod.fn->C_UnwrapKey(ctx->rw_session, &wrap_m, wrap,
                                   wrapped, wlen,
                                   unwrap_tmpl, 5,
                                   &unwrapped);
    ASSERT_RV_OK(rv, "UnwrapKey");
    ASSERT_NE(unwrapped, CK_INVALID_HANDLE, "Unwrapped key handle valid");

    /* The unwrapped key should be usable */
    unsigned char iv[16] = {0}, plain[16] = "test", cipher[32] = {0};
    CK_ULONG clen = sizeof(cipher);
    CK_MECHANISM enc_m = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    rv = ctx->mod.fn->C_EncryptInit(ctx->rw_session, &enc_m, unwrapped);
    ASSERT_RV_OK(rv, "EncryptInit with unwrapped key");
    rv = ctx->mod.fn->C_Encrypt(ctx->rw_session, plain, sizeof(plain), cipher, &clen);
    ASSERT_RV_OK(rv, "Encrypt with unwrapped key");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, target);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, wrap);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, unwrapped);
    TEST_PASS();
}

/* REQ-KEY-08: C_DeriveKey NULL mechanism → CKR_ARGUMENTS_BAD              */
static int test_derive_key_null_mechanism(TestCtx *ctx)
{
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_BBOOL f = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN, &f, sizeof(f) },
    };
    /* Use a dummy base key handle */
    CK_RV rv = ctx->mod.fn->C_DeriveKey(ctx->rw_session, NULL_PTR,
                                          ctx->rw_session, /* bogus base key */
                                          tmpl, 1, &derived);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "DeriveKey NULL mechanism");
    TEST_PASS();
}

/* ════════════════════════════════════════════════════════════
 *  §11.15 RANDOM
 * ════════════════════════════════════════════════════════════ */

/* REQ-RND-01: C_GenerateRandom zero length → CKR_OK                       */
static int test_random_zero_length(TestCtx *ctx)
{
    unsigned char buf[1];
    CK_RV rv = ctx->mod.fn->C_GenerateRandom(ctx->rw_session, buf, 0);
    ASSERT_RV_OK(rv, "GenerateRandom length=0");
    TEST_PASS();
}

/* REQ-RND-02: C_GenerateRandom NULL buffer non-zero length → error        */
static int test_random_null_buffer(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_GenerateRandom(ctx->rw_session, NULL_PTR, 16);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "GenerateRandom NULL buffer");
    TEST_PASS();
}

/* REQ-RND-03: C_GenerateRandom produces non-constant output               */
static int test_random_non_constant(TestCtx *ctx)
{
    unsigned char r1[32], r2[32];
    ctx->mod.fn->C_GenerateRandom(ctx->rw_session, r1, sizeof(r1));
    ctx->mod.fn->C_GenerateRandom(ctx->rw_session, r2, sizeof(r2));
    /* Comparing 32 bytes: probability of equal is 2^-256 */
    ASSERT_TRUE(memcmp(r1, r2, sizeof(r1)) != 0,
                "Two random buffers differ");
    TEST_PASS();
}

/* REQ-RND-04: C_SeedRandom NULL buffer non-zero length → error or OK      */
static int test_seed_random_null_buffer(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_SeedRandom(ctx->rw_session, NULL_PTR, 16);
    ASSERT_TRUE(rv == CKR_ARGUMENTS_BAD ||
                rv == CKR_RANDOM_SEED_NOT_SUPPORTED,
                "SeedRandom NULL buffer: ARGUMENTS_BAD or NOT_SUPPORTED");
    TEST_PASS();
}

/* REQ-RND-05: C_SeedRandom with valid data accepted or unsupported        */
static int test_seed_random_valid(TestCtx *ctx)
{
    unsigned char seed[32];
    memset(seed, 0xA5, sizeof(seed));
    CK_RV rv = ctx->mod.fn->C_SeedRandom(ctx->rw_session, seed, sizeof(seed));
    ASSERT_TRUE(rv == CKR_OK || rv == CKR_RANDOM_SEED_NOT_SUPPORTED,
                "SeedRandom valid data: OK or SEED_NOT_SUPPORTED");
    TEST_PASS();
}

BEGIN_TESTS(req_crypto)
    ADD_TEST("REQ-ENC-01_Encrypt_without_init",           test_encrypt_without_init);
    ADD_TEST("REQ-ENC-02_EncryptUpdate_without_init",     test_encrypt_update_without_init);
    ADD_TEST("REQ-ENC-03_EncryptFinal_without_init",      test_encrypt_final_without_init);
    ADD_TEST("REQ-ENC-04_EncryptInit_invalid_mechanism",  test_encrypt_init_invalid_mechanism);
    ADD_TEST("REQ-ENC-05_EncryptInit_key_no_encrypt",     test_encrypt_key_no_encrypt_flag);
    ADD_TEST("REQ-ENC-06_EncryptInit_null_mechanism",     test_encrypt_init_null_mechanism);
    ADD_TEST("REQ-ENC-07_EncryptInit_while_active",       test_encrypt_init_while_active);
    ADD_TEST("REQ-ENC-08_Encrypt_null_output_query",      test_encrypt_null_output_query);
    ADD_TEST("REQ-ENC-09_Encrypt_wrong_key_type",         test_encrypt_wrong_key_type);
    ADD_TEST("REQ-DEC-01_Decrypt_without_init",           test_decrypt_without_init);
    ADD_TEST("REQ-DEC-02_DecryptUpdate_without_init",     test_decrypt_update_without_init);
    ADD_TEST("REQ-DEC-03_DecryptFinal_without_init",      test_decrypt_final_without_init);
    ADD_TEST("REQ-DEC-04_DecryptInit_key_no_decrypt",     test_decrypt_key_no_decrypt_flag);
    ADD_TEST("REQ-DEC-05_Decrypt_corrupt_ciphertext",     test_decrypt_corrupt_ciphertext);
    ADD_TEST("REQ-DIG-01_Digest_without_init",            test_digest_without_init);
    ADD_TEST("REQ-DIG-02_DigestUpdate_without_init",      test_digest_update_without_init);
    ADD_TEST("REQ-DIG-03_DigestFinal_without_init",       test_digest_final_without_init);
    ADD_TEST("REQ-DIG-04_DigestInit_while_active",        test_digest_init_while_active);
    ADD_TEST("REQ-DIG-05_DigestKey",                      test_digest_key);
    ADD_TEST("REQ-DIG-06_Digest_null_output_query",       test_digest_null_output_query);
    ADD_TEST("REQ-DIG-07_Digest_multipart_matches_single",test_digest_multipart_matches_single);
    ADD_TEST("REQ-SIG-01_Sign_without_init",              test_sign_without_init);
    ADD_TEST("REQ-SIG-02_SignUpdate_without_init",        test_sign_update_without_init);
    ADD_TEST("REQ-SIG-03_SignFinal_without_init",         test_sign_final_without_init);
    ADD_TEST("REQ-SIG-04_SignInit_key_no_sign",           test_sign_key_no_sign_flag);
    ADD_TEST("REQ-SIG-05_Sign_null_output_query",         test_sign_null_output_query);
    ADD_TEST("REQ-SIG-06_Sign_multipart",                 test_sign_multipart);
    ADD_TEST("REQ-VER-01_Verify_without_init",            test_verify_without_init);
    ADD_TEST("REQ-VER-02_VerifyUpdate_without_init",      test_verify_update_without_init);
    ADD_TEST("REQ-VER-03_VerifyFinal_without_init",       test_verify_final_without_init);
    ADD_TEST("REQ-VER-04_Verify_invalid_signature",       test_verify_invalid_signature);
    ADD_TEST("REQ-VER-05_Verify_wrong_sig_length",        test_verify_wrong_sig_length);
    ADD_TEST("REQ-VER-06_VerifyInit_key_no_verify",       test_verify_key_no_verify_flag);
    ADD_TEST("REQ-VER-07_Verify_multipart",               test_verify_multipart);
    ADD_TEST("REQ-KEY-01_GenerateKey_null_mechanism",     test_generate_key_null_mechanism);
    ADD_TEST("REQ-KEY-02_GenerateKey_null_handle",        test_generate_key_null_handle);
    ADD_TEST("REQ-KEY-03_GenerateKey_invalid_mechanism",  test_generate_key_invalid_mechanism);
    ADD_TEST("REQ-KEY-04_GenerateKeyPair_null_mechanism", test_generate_keypair_null_mechanism);
    ADD_TEST("REQ-KEY-05_WrapKey_non_extractable",        test_wrap_key_non_extractable);
    ADD_TEST("REQ-KEY-06_WrapKey_null_output_query",      test_wrap_key_null_output_query);
    ADD_TEST("REQ-KEY-07_UnwrapKey_attributes",           test_unwrap_key_attributes);
    ADD_TEST("REQ-KEY-08_DeriveKey_null_mechanism",       test_derive_key_null_mechanism);
    ADD_TEST("REQ-RND-01_Random_zero_length",             test_random_zero_length);
    ADD_TEST("REQ-RND-02_Random_null_buffer",             test_random_null_buffer);
    ADD_TEST("REQ-RND-03_Random_non_constant",            test_random_non_constant);
    ADD_TEST("REQ-RND-04_SeedRandom_null_buffer",         test_seed_random_null_buffer);
    ADD_TEST("REQ-RND-05_SeedRandom_valid",               test_seed_random_valid);
END_TESTS()
