#include "test_framework.h"
#include <string.h>
#include <stdlib.h>

static CK_OBJECT_HANDLE make_aes_key_ex(TestCtx *ctx, CK_ULONG bits,
                                         CK_BBOOL wrap, CK_BBOOL unwrap,
                                         CK_BBOOL extractable)
{
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG klen = bits / 8;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,       &f,           sizeof(f)    },
        { CKA_ENCRYPT,     &t,           sizeof(t)    },
        { CKA_DECRYPT,     &t,           sizeof(t)    },
        { CKA_WRAP,        &wrap,        sizeof(wrap) },
        { CKA_UNWRAP,      &unwrap,      sizeof(unwrap)},
        { CKA_EXTRACTABLE, &extractable, sizeof(extractable) },
        { CKA_VALUE_LEN,   &klen,        sizeof(klen) },
    };
    CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ctx->mod.fn->C_GenerateKey(ctx->rw_session, &m, tmpl, 7, &key);
    return key;
}

/* Wrap an AES key with another AES key using AES-KEY-WRAP */
static int test_aes_wrap_unwrap(TestCtx *ctx)
{
    CK_OBJECT_HANDLE wrap_key   = make_aes_key_ex(ctx, 256, CK_TRUE, CK_TRUE, CK_TRUE);
    CK_OBJECT_HANDLE target_key = make_aes_key_ex(ctx, 128, CK_FALSE, CK_FALSE, CK_TRUE);

    ASSERT_NE(wrap_key,   CK_INVALID_HANDLE, "Wrapping key generated");
    ASSERT_NE(target_key, CK_INVALID_HANDLE, "Target key generated");

    unsigned char wrapped[64];
    CK_ULONG wrapped_len = sizeof(wrapped);

    CK_MECHANISM m = { CKM_AES_KEY_WRAP, NULL_PTR, 0 };
    CK_RV rv = ctx->mod.fn->C_WrapKey(ctx->rw_session, &m, wrap_key, target_key,
                                        wrapped, &wrapped_len);
    if (rv == CKR_MECHANISM_INVALID) {
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, wrap_key);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, target_key);
        SKIP("AES_KEY_WRAP not supported");
    }
    ASSERT_RV_OK(rv, "C_WrapKey AES");
    ASSERT_TRUE(wrapped_len > 0, "Wrapped key has content");

    /* Unwrap it back */
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_OBJECT_CLASS key_cls  = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type     = CKK_AES;
    CK_ATTRIBUTE unwrap_tmpl[] = {
        { CKA_CLASS,       &key_cls,  sizeof(key_cls)  },
        { CKA_KEY_TYPE,    &key_type, sizeof(key_type) },
        { CKA_TOKEN,       &f,        sizeof(f)        },
        { CKA_ENCRYPT,     &t,        sizeof(t)        },
        { CKA_DECRYPT,     &t,        sizeof(t)        },
        { CKA_EXTRACTABLE, &t,        sizeof(t)        },
    };
    CK_OBJECT_HANDLE unwrapped = CK_INVALID_HANDLE;
    rv = ctx->mod.fn->C_UnwrapKey(ctx->rw_session, &m, wrap_key,
                                   wrapped, wrapped_len,
                                   unwrap_tmpl, 6, &unwrapped);
    ASSERT_RV_OK(rv, "C_UnwrapKey AES");
    ASSERT_NE(unwrapped, CK_INVALID_HANDLE, "Unwrapped key handle valid");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, wrap_key);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, target_key);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, unwrapped);
    TEST_PASS();
}

/* Wrap non-extractable key must fail */
static int test_wrap_non_extractable(TestCtx *ctx)
{
    CK_OBJECT_HANDLE wrap_key   = make_aes_key_ex(ctx, 256, CK_TRUE, CK_TRUE, CK_TRUE);
    CK_OBJECT_HANDLE target_key = make_aes_key_ex(ctx, 128, CK_FALSE, CK_FALSE, CK_FALSE);

    ASSERT_NE(wrap_key,   CK_INVALID_HANDLE, "Wrapping key");
    ASSERT_NE(target_key, CK_INVALID_HANDLE, "Non-extractable key");

    unsigned char wrapped[64];
    CK_ULONG wrapped_len = sizeof(wrapped);
    CK_MECHANISM m = { CKM_AES_KEY_WRAP, NULL_PTR, 0 };

    CK_RV rv = ctx->mod.fn->C_WrapKey(ctx->rw_session, &m, wrap_key, target_key,
                                        wrapped, &wrapped_len);
    if (rv == CKR_MECHANISM_INVALID) {
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, wrap_key);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, target_key);
        SKIP("AES_KEY_WRAP not supported");
    }
    ASSERT_RV(rv, CKR_KEY_UNEXTRACTABLE, "Wrap non-extractable key should fail");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, wrap_key);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, target_key);
    TEST_PASS();
}

/* RSA wrap/unwrap an AES key */
static int test_rsa_wrap_unwrap_aes(TestCtx *ctx)
{
    /* Generate RSA-2048 key pair */
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG mod_bits = 2048;
    unsigned char exp[] = { 0x01, 0x00, 0x01 };
    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_TOKEN,           &f,       sizeof(f)        },
        { CKA_WRAP,            &t,       sizeof(t)        },
        { CKA_MODULUS_BITS,    &mod_bits,sizeof(mod_bits) },
        { CKA_PUBLIC_EXPONENT, exp,      sizeof(exp)      },
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        { CKA_TOKEN,   &f, sizeof(f) },
        { CKA_UNWRAP,  &t, sizeof(t) },
        { CKA_SENSITIVE,&t,sizeof(t) },
    };
    CK_MECHANISM rsa_gen = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE rsa_pub, rsa_priv;
    CK_RV rv = ctx->mod.fn->C_GenerateKeyPair(ctx->rw_session, &rsa_gen,
                                               pub_tmpl, 4, priv_tmpl, 3,
                                               &rsa_pub, &rsa_priv);
    ASSERT_RV_OK(rv, "Gen RSA-2048 for wrap");

    CK_OBJECT_HANDLE target = make_aes_key_ex(ctx, 128, CK_FALSE, CK_FALSE, CK_TRUE);
    ASSERT_NE(target, CK_INVALID_HANDLE, "Target AES key");

    unsigned char wrapped[512];
    CK_ULONG wrapped_len = sizeof(wrapped);
    CK_MECHANISM wrap_m = { CKM_RSA_PKCS, NULL_PTR, 0 };

    rv = ctx->mod.fn->C_WrapKey(ctx->rw_session, &wrap_m, rsa_pub, target,
                                  wrapped, &wrapped_len);
    if (rv == CKR_MECHANISM_INVALID) {
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, rsa_pub);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, rsa_priv);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, target);
        SKIP("RSA_PKCS wrap not supported");
    }
    ASSERT_RV_OK(rv, "C_WrapKey RSA");

    CK_OBJECT_CLASS key_cls = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type    = CKK_AES;
    CK_ATTRIBUTE unwrap_tmpl[] = {
        { CKA_CLASS,     &key_cls,  sizeof(key_cls)  },
        { CKA_KEY_TYPE,  &key_type, sizeof(key_type) },
        { CKA_TOKEN,     &f,        sizeof(f)        },
        { CKA_ENCRYPT,   &t,        sizeof(t)        },
    };
    CK_OBJECT_HANDLE unwrapped;
    rv = ctx->mod.fn->C_UnwrapKey(ctx->rw_session, &wrap_m, rsa_priv,
                                   wrapped, wrapped_len, unwrap_tmpl, 4, &unwrapped);
    ASSERT_RV_OK(rv, "C_UnwrapKey RSA");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, rsa_pub);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, rsa_priv);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, target);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, unwrapped);
    TEST_PASS();
}

/* WrapKey with invalid wrapping key */
static int test_wrap_invalid_key(TestCtx *ctx)
{
    unsigned char wrapped[64];
    CK_ULONG wlen = sizeof(wrapped);
    CK_MECHANISM m = { CKM_AES_KEY_WRAP, NULL_PTR, 0 };
    CK_RV rv = ctx->mod.fn->C_WrapKey(ctx->rw_session, &m,
                                        0xDEADBEEF, 0xCAFEBABE,
                                        wrapped, &wlen);
    ASSERT_TRUE(rv != CKR_OK, "WrapKey with invalid handles should fail");
    TEST_PASS();
}

BEGIN_TESTS(wrap_unwrap)
    ADD_TEST("AES_wrap_unwrap",          test_aes_wrap_unwrap);
    ADD_TEST("Wrap_non_extractable",     test_wrap_non_extractable);
    ADD_TEST("RSA_wrap_unwrap_AES",      test_rsa_wrap_unwrap_aes);
    ADD_TEST("WrapKey_invalid_key",      test_wrap_invalid_key);
END_TESTS()
