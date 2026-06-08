#include "test_framework.h"
#include <string.h>
#include <stdlib.h>

/* ---- Helpers ---- */
static int make_rsa_keypair(TestCtx *ctx, CK_ULONG bits,
                             CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv)
{
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG mod_bits = bits;
    unsigned char exp[] = { 0x01, 0x00, 0x01 };

    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_TOKEN,           &f,       sizeof(f)        },
        { CKA_ENCRYPT,         &t,       sizeof(t)        },
        { CKA_VERIFY,          &t,       sizeof(t)        },
        { CKA_MODULUS_BITS,    &mod_bits,sizeof(mod_bits) },
        { CKA_PUBLIC_EXPONENT, exp,      sizeof(exp)      },
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        { CKA_TOKEN,      &f, sizeof(f) },
        { CKA_DECRYPT,    &t, sizeof(t) },
        { CKA_SIGN,       &t, sizeof(t) },
        { CKA_SENSITIVE,  &t, sizeof(t) },
        { CKA_EXTRACTABLE,&f, sizeof(f) },
    };

    CK_MECHANISM m = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    return (ctx->mod.fn->C_GenerateKeyPair(ctx->rw_session, &m,
                                            pub_tmpl, 5, priv_tmpl, 5,
                                            pub, priv) == CKR_OK) ? 0 : -1;
}

static const unsigned char P256_OID[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
                                           0x3d, 0x03, 0x01, 0x07 };

static int make_ec_keypair(TestCtx *ctx, CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv)
{
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_TOKEN,     &f,              sizeof(f)              },
        { CKA_VERIFY,    &t,              sizeof(t)              },
        { CKA_EC_PARAMS, (void*)P256_OID, sizeof(P256_OID)       },
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        { CKA_TOKEN,   &f, sizeof(f) },
        { CKA_SIGN,    &t, sizeof(t) },
        { CKA_SENSITIVE,&t,sizeof(t) },
    };
    CK_MECHANISM m = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
    return (ctx->mod.fn->C_GenerateKeyPair(ctx->rw_session, &m,
                                            pub_tmpl, 3, priv_tmpl, 3,
                                            pub, priv) == CKR_OK) ? 0 : -1;
}

/* ---- RSA PKCS#1 v1.5 sign/verify ---- */
static int test_rsa_sign_verify_pkcs1(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub, priv;
    ASSERT_EQ(make_rsa_keypair(ctx, 2048, &pub, &priv), 0, "Gen RSA-2048");

    unsigned char data[32] = "Data to be signed by RSA PKCS1!!";
    unsigned char sig[512] = {0};
    CK_ULONG sig_len = sizeof(sig);

    CK_MECHANISM m = { CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };

    CK_RV rv = ctx->mod.fn->C_SignInit(ctx->rw_session, &m, priv);
    ASSERT_RV_OK(rv, "SignInit RSA_PKCS");
    rv = ctx->mod.fn->C_Sign(ctx->rw_session, data, sizeof(data), sig, &sig_len);
    ASSERT_RV_OK(rv, "Sign RSA_PKCS");
    ASSERT_TRUE(sig_len > 0, "Signature has content");

    rv = ctx->mod.fn->C_VerifyInit(ctx->rw_session, &m, pub);
    ASSERT_RV_OK(rv, "VerifyInit RSA_PKCS");
    rv = ctx->mod.fn->C_Verify(ctx->rw_session, data, sizeof(data), sig, sig_len);
    ASSERT_RV_OK(rv, "Verify RSA_PKCS");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

/* ---- RSA PKCS#1 v1.5 verify tampered signature ---- */
static int test_rsa_verify_tampered(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub, priv;
    ASSERT_EQ(make_rsa_keypair(ctx, 2048, &pub, &priv), 0, "Gen RSA-2048");

    unsigned char data[32] = "Sign tamper test data .........."; /* 32 chars */
    unsigned char sig[512] = {0};
    CK_ULONG sig_len = sizeof(sig);

    CK_MECHANISM m = { CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };
    ctx->mod.fn->C_SignInit(ctx->rw_session, &m, priv);
    ctx->mod.fn->C_Sign(ctx->rw_session, data, sizeof(data), sig, &sig_len);

    sig[0] ^= 0xFF; /* tamper */

    CK_RV rv = ctx->mod.fn->C_VerifyInit(ctx->rw_session, &m, pub);
    ASSERT_RV_OK(rv, "VerifyInit");
    rv = ctx->mod.fn->C_Verify(ctx->rw_session, data, sizeof(data), sig, sig_len);
    ASSERT_RV(rv, CKR_SIGNATURE_INVALID, "Tampered signature rejected");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

/* ---- RSA PSS ---- */
static int test_rsa_sign_verify_pss(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub, priv;
    ASSERT_EQ(make_rsa_keypair(ctx, 2048, &pub, &priv), 0, "Gen RSA-2048");

    unsigned char data[32] = "RSA PSS signature test data ....";
    unsigned char sig[512] = {0};
    CK_ULONG sig_len = sizeof(sig);

    CK_RSA_PKCS_PSS_PARAMS pss = {
        .hash_alg   = CKM_SHA256,
        .mgf        = CKG_MGF1_SHA256,
        .s_len      = 32,
    };
    CK_MECHANISM m = { CKM_SHA256_RSA_PKCS_PSS, &pss, sizeof(pss) };

    CK_RV rv = ctx->mod.fn->C_SignInit(ctx->rw_session, &m, priv);
    if (rv == CKR_MECHANISM_INVALID) {
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
        SKIP("RSA-PSS not supported");
    }
    ASSERT_RV_OK(rv, "SignInit RSA-PSS");
    rv = ctx->mod.fn->C_Sign(ctx->rw_session, data, sizeof(data), sig, &sig_len);
    ASSERT_RV_OK(rv, "Sign RSA-PSS");

    rv = ctx->mod.fn->C_VerifyInit(ctx->rw_session, &m, pub);
    ASSERT_RV_OK(rv, "VerifyInit RSA-PSS");
    rv = ctx->mod.fn->C_Verify(ctx->rw_session, data, sizeof(data), sig, sig_len);
    ASSERT_RV_OK(rv, "Verify RSA-PSS");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

/* ---- RSA OAEP encrypt/decrypt ---- */
static int test_rsa_oaep_encrypt_decrypt(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub, priv;
    ASSERT_EQ(make_rsa_keypair(ctx, 2048, &pub, &priv), 0, "Gen RSA-2048");

    unsigned char plain[32]  = "RSA OAEP encrypt test payload...";
    unsigned char cipher[512]= {0};
    unsigned char dec[512]   = {0};
    CK_ULONG clen = sizeof(cipher), dlen = sizeof(dec);

    unsigned char empty_label[1] = {0};
    CK_RSA_PKCS_OAEP_PARAMS oaep = {
        .hash_alg        = CKM_SHA_1,
        .mgf             = CKG_MGF1_SHA1,
        .source          = CKZ_DATA_SPECIFIED,
        .source_data     = empty_label,
        .source_data_len = 0,
    };
    CK_MECHANISM m = { CKM_RSA_PKCS_OAEP, &oaep, sizeof(oaep) };

    CK_RV rv = ctx->mod.fn->C_EncryptInit(ctx->rw_session, &m, pub);
    if (rv == CKR_MECHANISM_INVALID || rv == CKR_ARGUMENTS_BAD) {
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
        SKIP("RSA-OAEP not supported");
    }
    ASSERT_RV_OK(rv, "EncryptInit RSA-OAEP");
    rv = ctx->mod.fn->C_Encrypt(ctx->rw_session, plain, sizeof(plain), cipher, &clen);
    ASSERT_RV_OK(rv, "Encrypt RSA-OAEP");

    rv = ctx->mod.fn->C_DecryptInit(ctx->rw_session, &m, priv);
    ASSERT_RV_OK(rv, "DecryptInit RSA-OAEP");
    rv = ctx->mod.fn->C_Decrypt(ctx->rw_session, cipher, clen, dec, &dlen);
    ASSERT_RV_OK(rv, "Decrypt RSA-OAEP");
    ASSERT_EQ(dlen, (CK_ULONG)sizeof(plain), "OAEP decrypted length");
    ASSERT_MEM_EQ(dec, plain, sizeof(plain), "OAEP roundtrip");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

/* ---- EC ECDSA sign/verify ---- */
static int test_ecdsa_sign_verify(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub, priv;
    ASSERT_EQ(make_ec_keypair(ctx, &pub, &priv), 0, "Gen EC P-256");

    unsigned char hash[32];
    memset(hash, 0xAB, sizeof(hash)); /* fake pre-computed hash */
    unsigned char sig[128] = {0};
    CK_ULONG sig_len = sizeof(sig);

    CK_MECHANISM m = { CKM_ECDSA, NULL_PTR, 0 };

    CK_RV rv = ctx->mod.fn->C_SignInit(ctx->rw_session, &m, priv);
    ASSERT_RV_OK(rv, "SignInit ECDSA");
    rv = ctx->mod.fn->C_Sign(ctx->rw_session, hash, sizeof(hash), sig, &sig_len);
    ASSERT_RV_OK(rv, "Sign ECDSA");

    rv = ctx->mod.fn->C_VerifyInit(ctx->rw_session, &m, pub);
    ASSERT_RV_OK(rv, "VerifyInit ECDSA");
    rv = ctx->mod.fn->C_Verify(ctx->rw_session, hash, sizeof(hash), sig, sig_len);
    ASSERT_RV_OK(rv, "Verify ECDSA");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

/* ---- ECDSA with hash ---- */
static int test_ecdsa_sha256_sign_verify(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub, priv;
    ASSERT_EQ(make_ec_keypair(ctx, &pub, &priv), 0, "Gen EC P-256");

    unsigned char data[64] = "ECDSA with SHA256 sign/verify test data for coverage purposes!";
    unsigned char sig[128] = {0};
    CK_ULONG sig_len = sizeof(sig);

    CK_MECHANISM m = { CKM_ECDSA_SHA256, NULL_PTR, 0 };

    CK_RV rv = ctx->mod.fn->C_SignInit(ctx->rw_session, &m, priv);
    if (rv == CKR_MECHANISM_INVALID) {
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
        SKIP("ECDSA_SHA256 not supported");
    }
    ASSERT_RV_OK(rv, "SignInit ECDSA_SHA256");
    rv = ctx->mod.fn->C_Sign(ctx->rw_session, data, sizeof(data), sig, &sig_len);
    ASSERT_RV_OK(rv, "Sign ECDSA_SHA256");

    rv = ctx->mod.fn->C_VerifyInit(ctx->rw_session, &m, pub);
    ASSERT_RV_OK(rv, "VerifyInit ECDSA_SHA256");
    rv = ctx->mod.fn->C_Verify(ctx->rw_session, data, sizeof(data), sig, sig_len);
    ASSERT_RV_OK(rv, "Verify ECDSA_SHA256");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

/* ---- Multipart sign ---- */
static int test_rsa_sign_multipart(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub, priv;
    ASSERT_EQ(make_rsa_keypair(ctx, 2048, &pub, &priv), 0, "Gen RSA-2048");

    unsigned char part1[] = "First part of the message ......";
    unsigned char part2[] = "Second part of message .........";
    unsigned char sig[512] = {0};
    CK_ULONG sig_len = sizeof(sig);

    CK_MECHANISM m = { CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };

    CK_RV rv = ctx->mod.fn->C_SignInit(ctx->rw_session, &m, priv);
    ASSERT_RV_OK(rv, "SignInit multipart");
    rv = ctx->mod.fn->C_SignUpdate(ctx->rw_session, part1, sizeof(part1) - 1);
    ASSERT_RV_OK(rv, "SignUpdate 1");
    rv = ctx->mod.fn->C_SignUpdate(ctx->rw_session, part2, sizeof(part2) - 1);
    ASSERT_RV_OK(rv, "SignUpdate 2");
    rv = ctx->mod.fn->C_SignFinal(ctx->rw_session, sig, &sig_len);
    ASSERT_RV_OK(rv, "SignFinal");

    /* Verify multipart */
    rv = ctx->mod.fn->C_VerifyInit(ctx->rw_session, &m, pub);
    ASSERT_RV_OK(rv, "VerifyInit multipart");
    rv = ctx->mod.fn->C_VerifyUpdate(ctx->rw_session, part1, sizeof(part1) - 1);
    ASSERT_RV_OK(rv, "VerifyUpdate 1");
    rv = ctx->mod.fn->C_VerifyUpdate(ctx->rw_session, part2, sizeof(part2) - 1);
    ASSERT_RV_OK(rv, "VerifyUpdate 2");
    rv = ctx->mod.fn->C_VerifyFinal(ctx->rw_session, sig, sig_len);
    ASSERT_RV_OK(rv, "VerifyFinal");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

/* ---- Sign without init ---- */
static int test_sign_no_init(TestCtx *ctx)
{
    unsigned char data[16] = {0};
    unsigned char sig[512] = {0};
    CK_ULONG sig_len = sizeof(sig);
    CK_RV rv = ctx->mod.fn->C_Sign(ctx->rw_session, data, sizeof(data), sig, &sig_len);
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "Sign without SignInit");
    TEST_PASS();
}

/* ---- Verify without init ---- */
static int test_verify_no_init(TestCtx *ctx)
{
    unsigned char data[16] = {0};
    unsigned char sig[16]  = {0};
    CK_RV rv = ctx->mod.fn->C_Verify(ctx->rw_session, data, sizeof(data), sig, sizeof(sig));
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "Verify without VerifyInit");
    TEST_PASS();
}

/* ---- SignRecover/VerifyRecover ---- */
static int test_rsa_sign_recover(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub, priv;
    ASSERT_EQ(make_rsa_keypair(ctx, 2048, &pub, &priv), 0, "Gen RSA-2048");

    unsigned char data[32] = "Sign-recover test data .........";
    unsigned char sig[512] = {0};
    unsigned char rec[512] = {0};
    CK_ULONG sig_len = sizeof(sig), rec_len = sizeof(rec);

    CK_MECHANISM m = { CKM_RSA_PKCS, NULL_PTR, 0 };

    CK_RV rv = ctx->mod.fn->C_SignRecoverInit(ctx->rw_session, &m, priv);
    if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
        SKIP("SignRecover not supported");
    }
    ASSERT_RV_OK(rv, "SignRecoverInit");
    rv = ctx->mod.fn->C_SignRecover(ctx->rw_session, data, sizeof(data), sig, &sig_len);
    ASSERT_RV_OK(rv, "SignRecover");

    rv = ctx->mod.fn->C_VerifyRecoverInit(ctx->rw_session, &m, pub);
    ASSERT_RV_OK(rv, "VerifyRecoverInit");
    rv = ctx->mod.fn->C_VerifyRecover(ctx->rw_session, sig, sig_len, rec, &rec_len);
    ASSERT_RV_OK(rv, "VerifyRecover");
    ASSERT_EQ(rec_len, (CK_ULONG)sizeof(data), "Recovered length");
    ASSERT_MEM_EQ(rec, data, sizeof(data), "Recovered content matches");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

BEGIN_TESTS(crypto_asym)
    ADD_TEST("RSA_sign_verify_pkcs1",     test_rsa_sign_verify_pkcs1);
    ADD_TEST("RSA_verify_tampered",        test_rsa_verify_tampered);
    ADD_TEST("RSA_sign_verify_pss",        test_rsa_sign_verify_pss);
    ADD_TEST("RSA_oaep_encrypt_decrypt",   test_rsa_oaep_encrypt_decrypt);
    ADD_TEST("ECDSA_sign_verify",          test_ecdsa_sign_verify);
    ADD_TEST("ECDSA_SHA256_sign_verify",   test_ecdsa_sha256_sign_verify);
    ADD_TEST("RSA_sign_multipart",         test_rsa_sign_multipart);
    ADD_TEST("Sign_no_init",               test_sign_no_init);
    ADD_TEST("Verify_no_init",             test_verify_no_init);
    ADD_TEST("RSA_sign_recover",           test_rsa_sign_recover);
END_TESTS()
