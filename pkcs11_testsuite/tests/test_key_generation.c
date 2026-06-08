#include "test_framework.h"
#include <string.h>
#include <stdlib.h>

/* ---- Helper: generate AES key ---- */
static CK_OBJECT_HANDLE gen_aes_key(TestCtx *ctx, CK_ULONG bits, CK_BBOOL token)
{
    CK_BBOOL     ck_true  = CK_TRUE;
    CK_BBOOL     ck_false = CK_FALSE;
    CK_ULONG     key_len  = bits / 8;

    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &token,    sizeof(token)   },
        { CKA_ENCRYPT,   &ck_true,  sizeof(ck_true) },
        { CKA_DECRYPT,   &ck_true,  sizeof(ck_true) },
        { CKA_VALUE_LEN, &key_len,  sizeof(key_len) },
    };

    CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ctx->mod.fn->C_GenerateKey(ctx->rw_session, &m, tmpl, 4, &key);
    return key;
}

/* ---- Helper: generate RSA key pair ---- */
static int gen_rsa_keypair(TestCtx *ctx, CK_ULONG bits,
                            CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv)
{
    CK_BBOOL ck_true  = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;
    CK_ULONG mod_bits = bits;
    unsigned char exp[] = { 0x01, 0x00, 0x01 };

    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_TOKEN,           &ck_false, sizeof(ck_false) },
        { CKA_ENCRYPT,         &ck_true,  sizeof(ck_true)  },
        { CKA_VERIFY,          &ck_true,  sizeof(ck_true)  },
        { CKA_MODULUS_BITS,    &mod_bits, sizeof(mod_bits) },
        { CKA_PUBLIC_EXPONENT, exp,       sizeof(exp)      },
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        { CKA_TOKEN,   &ck_false, sizeof(ck_false) },
        { CKA_DECRYPT, &ck_true,  sizeof(ck_true)  },
        { CKA_SIGN,    &ck_true,  sizeof(ck_true)  },
        { CKA_SENSITIVE,    &ck_true, sizeof(ck_true) },
        { CKA_EXTRACTABLE,  &ck_false, sizeof(ck_false) },
    };

    CK_MECHANISM m = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_RV rv = ctx->mod.fn->C_GenerateKeyPair(ctx->rw_session, &m,
                                               pub_tmpl, 5,
                                               priv_tmpl, 5,
                                               pub, priv);
    return (rv == CKR_OK) ? 0 : -1;
}

/* ---- Helper: generate EC key pair ---- */
static int gen_ec_keypair(TestCtx *ctx, const unsigned char *oid, CK_ULONG oid_len,
                           CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv)
{
    CK_BBOOL ck_true  = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;

    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_TOKEN,    &ck_false,    sizeof(ck_false)  },
        { CKA_VERIFY,   &ck_true,     sizeof(ck_true)   },
        { CKA_EC_PARAMS,(void*)oid,   oid_len           },
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        { CKA_TOKEN,    &ck_false,    sizeof(ck_false)  },
        { CKA_SIGN,     &ck_true,     sizeof(ck_true)   },
        { CKA_SENSITIVE,&ck_true,     sizeof(ck_true)   },
    };

    CK_MECHANISM m = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_RV rv = ctx->mod.fn->C_GenerateKeyPair(ctx->rw_session, &m,
                                               pub_tmpl, 3,
                                               priv_tmpl, 3,
                                               pub, priv);
    return (rv == CKR_OK) ? 0 : -1;
}

/* ============================================================ */

static int test_gen_aes_128(TestCtx *ctx)
{
    CK_OBJECT_HANDLE key = gen_aes_key(ctx, 128, CK_FALSE);
    ASSERT_NE(key, CK_INVALID_HANDLE, "Generate AES-128 key");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

static int test_gen_aes_192(TestCtx *ctx)
{
    CK_OBJECT_HANDLE key = gen_aes_key(ctx, 192, CK_FALSE);
    ASSERT_NE(key, CK_INVALID_HANDLE, "Generate AES-192 key");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

static int test_gen_aes_256(TestCtx *ctx)
{
    CK_OBJECT_HANDLE key = gen_aes_key(ctx, 256, CK_FALSE);
    ASSERT_NE(key, CK_INVALID_HANDLE, "Generate AES-256 key");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

static int test_gen_aes_token_persistent(TestCtx *ctx)
{
    const char *label = "PersistentAES";
    CK_BBOOL tok = CK_TRUE;
    CK_BBOOL t = CK_TRUE;
    CK_ULONG klen = 32;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &tok, sizeof(tok) },
        { CKA_ENCRYPT,   &t,   sizeof(t)   },
        { CKA_DECRYPT,   &t,   sizeof(t)   },
        { CKA_VALUE_LEN, &klen,sizeof(klen)},
        { CKA_LABEL,     (void*)label, (CK_ULONG)strlen(label) },
    };
    CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_RV rv = ctx->mod.fn->C_GenerateKey(ctx->rw_session, &m, tmpl, 5, &key);
    ASSERT_RV_OK(rv, "Generate token AES-256");
    ASSERT_NE(key, CK_INVALID_HANDLE, "Token AES key handle valid");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

static int test_gen_aes_bad_keylen(TestCtx *ctx)
{
    CK_BBOOL t = CK_TRUE;
    CK_ULONG klen = 7; /* invalid */
    CK_BBOOL tok = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &tok,  sizeof(tok)  },
        { CKA_ENCRYPT,   &t,    sizeof(t)    },
        { CKA_VALUE_LEN, &klen, sizeof(klen) },
    };
    CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key;
    CK_RV rv = ctx->mod.fn->C_GenerateKey(ctx->rw_session, &m, tmpl, 3, &key);
    ASSERT_TRUE(rv != CKR_OK, "AES with bad key length should fail");
    TEST_PASS();
}

static int test_gen_rsa_1024(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub, priv;
    int rc = gen_rsa_keypair(ctx, 1024, &pub, &priv);
    ASSERT_EQ(rc, 0, "Generate RSA-1024 key pair");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

static int test_gen_rsa_2048(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub, priv;
    int rc = gen_rsa_keypair(ctx, 2048, &pub, &priv);
    ASSERT_EQ(rc, 0, "Generate RSA-2048 key pair");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

static int test_gen_rsa_4096(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub, priv;
    int rc = gen_rsa_keypair(ctx, 4096, &pub, &priv);
    ASSERT_EQ(rc, 0, "Generate RSA-4096 key pair");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

/* P-256 OID: 1.2.840.10045.3.1.7 */
static const unsigned char P256_OID[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
                                           0x3d, 0x03, 0x01, 0x07 };
/* P-384 OID */
static const unsigned char P384_OID[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
/* P-521 OID */
static const unsigned char P521_OID[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 };

static int test_gen_ec_p256(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub, priv;
    int rc = gen_ec_keypair(ctx, P256_OID, sizeof(P256_OID), &pub, &priv);
    if (rc != 0) SKIP("EC P-256 not supported");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

static int test_gen_ec_p384(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub, priv;
    int rc = gen_ec_keypair(ctx, P384_OID, sizeof(P384_OID), &pub, &priv);
    if (rc != 0) SKIP("EC P-384 not supported");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

static int test_gen_ec_p521(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub, priv;
    int rc = gen_ec_keypair(ctx, P521_OID, sizeof(P521_OID), &pub, &priv);
    if (rc != 0) SKIP("EC P-521 not supported");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv);
    TEST_PASS();
}

static int test_gen_des3_key(TestCtx *ctx)
{
    CK_BBOOL t   = CK_TRUE;
    CK_BBOOL tok = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,   &tok, sizeof(tok) },
        { CKA_ENCRYPT, &t,   sizeof(t)   },
        { CKA_DECRYPT, &t,   sizeof(t)   },
    };
    CK_MECHANISM m = { CKM_DES3_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key;
    CK_RV rv = ctx->mod.fn->C_GenerateKey(ctx->rw_session, &m, tmpl, 3, &key);
    if (rv == CKR_MECHANISM_INVALID) SKIP("DES3 not supported");
    ASSERT_RV_OK(rv, "Generate DES3 key");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

static int test_gen_generic_key(TestCtx *ctx)
{
    CK_BBOOL tok = CK_FALSE;
    CK_BBOOL t   = CK_TRUE;
    CK_ULONG klen = 32;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &tok,  sizeof(tok)  },
        { CKA_DERIVE,    &t,    sizeof(t)    },
        { CKA_VALUE_LEN, &klen, sizeof(klen) },
    };
    CK_MECHANISM m = { CKM_GENERIC_SECRET_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key;
    CK_RV rv = ctx->mod.fn->C_GenerateKey(ctx->rw_session, &m, tmpl, 3, &key);
    if (rv == CKR_MECHANISM_INVALID) SKIP("GENERIC_SECRET_KEY_GEN not supported");
    ASSERT_RV_OK(rv, "Generate generic secret key");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

static int test_gen_key_invalid_mechanism(TestCtx *ctx)
{
    CK_BBOOL t = CK_TRUE;
    CK_ATTRIBUTE tmpl[] = { { CKA_TOKEN, &t, sizeof(t) } };
    CK_MECHANISM m = { 0x80009999UL, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key;
    CK_RV rv = ctx->mod.fn->C_GenerateKey(ctx->rw_session, &m, tmpl, 1, &key);
    ASSERT_RV(rv, CKR_MECHANISM_INVALID, "GenerateKey with invalid mechanism");
    TEST_PASS();
}

BEGIN_TESTS(key_generation)
    ADD_TEST("AES_128",                test_gen_aes_128);
    ADD_TEST("AES_192",                test_gen_aes_192);
    ADD_TEST("AES_256",                test_gen_aes_256);
    ADD_TEST("AES_token_persistent",   test_gen_aes_token_persistent);
    ADD_TEST("AES_bad_keylen",         test_gen_aes_bad_keylen);
    ADD_TEST("RSA_1024",               test_gen_rsa_1024);
    ADD_TEST("RSA_2048",               test_gen_rsa_2048);
    ADD_TEST("RSA_4096",               test_gen_rsa_4096);
    ADD_TEST("EC_P256",                test_gen_ec_p256);
    ADD_TEST("EC_P384",                test_gen_ec_p384);
    ADD_TEST("EC_P521",                test_gen_ec_p521);
    ADD_TEST("DES3",                   test_gen_des3_key);
    ADD_TEST("GenericSecret",          test_gen_generic_key);
    ADD_TEST("InvalidMechanism",       test_gen_key_invalid_mechanism);
END_TESTS()
