#include "test_framework.h"
#include <string.h>
#include <stdlib.h>

/* P-256 OID */
static const unsigned char P256_OID[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
                                           0x3d, 0x03, 0x01, 0x07 };

static int gen_ecdh_keypair(TestCtx *ctx, CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv)
{
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_TOKEN,     &f,              sizeof(f)              },
        { CKA_DERIVE,    &t,              sizeof(t)              },
        { CKA_EC_PARAMS, (void*)P256_OID, sizeof(P256_OID)       },
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        { CKA_TOKEN,   &f, sizeof(f) },
        { CKA_DERIVE,  &t, sizeof(t) },
        { CKA_SENSITIVE,&t,sizeof(t) },
    };
    CK_MECHANISM m = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
    return (ctx->mod.fn->C_GenerateKeyPair(ctx->rw_session, &m,
                                            pub_tmpl, 3, priv_tmpl, 3,
                                            pub, priv) == CKR_OK) ? 0 : -1;
}

/* Get EC public key point */
static unsigned char *get_ec_point(TestCtx *ctx, CK_OBJECT_HANDLE pub, CK_ULONG *len)
{
    CK_ATTRIBUTE attr = { CKA_EC_POINT, NULL_PTR, 0 };
    ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, pub, &attr, 1);
    if (attr.ulValueLen == 0 || attr.ulValueLen == (CK_ULONG)-1) return NULL;
    unsigned char *buf = malloc(attr.ulValueLen);
    attr.pValue = buf;
    ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, pub, &attr, 1);
    *len = attr.ulValueLen;
    return buf;
}

/* ECDH1-DERIVE: derive shared secret between two EC key pairs */
static int test_ecdh_derive(TestCtx *ctx)
{
    CK_OBJECT_HANDLE pub_a, priv_a, pub_b, priv_b;

    if (gen_ecdh_keypair(ctx, &pub_a, &priv_a) != 0) SKIP("EC key pair A failed");
    if (gen_ecdh_keypair(ctx, &pub_b, &priv_b) != 0) {
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub_a);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv_a);
        SKIP("EC key pair B failed");
    }

    CK_ULONG pub_b_len = 0;
    unsigned char *pub_b_point = get_ec_point(ctx, pub_b, &pub_b_len);
    ASSERT_TRUE(pub_b_point != NULL, "Got EC point for pub_b");

    CK_ECDH1_DERIVE_PARAMS ecdh = {
        .kdf             = CKD_NULL,
        .shared_data_len = 0,
        .shared_data     = NULL_PTR,
        .public_data_len = pub_b_len,
        .public_data     = pub_b_point,
    };
    CK_MECHANISM m = { CKM_ECDH1_DERIVE, &ecdh, sizeof(ecdh) };

    CK_BBOOL f = CK_FALSE, t = CK_TRUE;
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE kt = CKK_AES;
    CK_ULONG klen = 16;
    CK_ATTRIBUTE derive_tmpl[] = {
        { CKA_CLASS,       &cls,  sizeof(cls)  },
        { CKA_KEY_TYPE,    &kt,   sizeof(kt)   },
        { CKA_TOKEN,       &f,    sizeof(f)    },
        { CKA_ENCRYPT,     &t,    sizeof(t)    },
        { CKA_SENSITIVE,   &f,    sizeof(f)    },
        { CKA_EXTRACTABLE, &t,    sizeof(t)    },
        { CKA_VALUE_LEN,   &klen, sizeof(klen) },
    };

    CK_OBJECT_HANDLE derived_a;
    CK_RV rv = ctx->mod.fn->C_DeriveKey(ctx->rw_session, &m, priv_a,
                                          derive_tmpl, 7, &derived_a);
    free(pub_b_point);
    if (rv == CKR_MECHANISM_INVALID) {
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub_a);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv_a);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub_b);
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv_b);
        SKIP("ECDH1_DERIVE not supported");
    }
    ASSERT_RV_OK(rv, "C_DeriveKey ECDH1 (A->B)");
    ASSERT_NE(derived_a, CK_INVALID_HANDLE, "Derived key handle A valid");

    /* Now derive from B's perspective using A's public key */
    CK_ULONG pub_a_len = 0;
    unsigned char *pub_a_point = get_ec_point(ctx, pub_a, &pub_a_len);
    ecdh.public_data_len = pub_a_len;
    ecdh.public_data     = pub_a_point;

    CK_OBJECT_HANDLE derived_b;
    rv = ctx->mod.fn->C_DeriveKey(ctx->rw_session, &m, priv_b,
                                   derive_tmpl, 7, &derived_b);
    free(pub_a_point);
    ASSERT_RV_OK(rv, "C_DeriveKey ECDH1 (B->A)");

    /* Both derived keys should have the same value */
    CK_ATTRIBUTE val_a = { CKA_VALUE, NULL_PTR, 0 };
    CK_ATTRIBUTE val_b = { CKA_VALUE, NULL_PTR, 0 };
    ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, derived_a, &val_a, 1);
    ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, derived_b, &val_b, 1);
    ASSERT_EQ(val_a.ulValueLen, val_b.ulValueLen, "Derived key lengths match");

    unsigned char *va = malloc(val_a.ulValueLen);
    unsigned char *vb = malloc(val_b.ulValueLen);
    val_a.pValue = va; val_b.pValue = vb;
    ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, derived_a, &val_a, 1);
    ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, derived_b, &val_b, 1);
    ASSERT_MEM_EQ(va, vb, val_a.ulValueLen, "ECDH shared secrets match");
    free(va); free(vb);

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub_a);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv_a);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, pub_b);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, priv_b);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, derived_a);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, derived_b);
    TEST_PASS();
}

/* DeriveKey with invalid mechanism */
static int test_derive_invalid_mechanism(TestCtx *ctx)
{
    CK_BBOOL t = CK_TRUE;
    CK_ATTRIBUTE tmpl[] = { { CKA_TOKEN, &t, sizeof(t) } };
    CK_MECHANISM m = { 0x80009998UL, NULL_PTR, 0 };
    CK_OBJECT_HANDLE derived;
    CK_RV rv = ctx->mod.fn->C_DeriveKey(ctx->rw_session, &m,
                                          CK_INVALID_HANDLE, tmpl, 1, &derived);
    ASSERT_TRUE(rv != CKR_OK, "DeriveKey with invalid mechanism fails");
    TEST_PASS();
}

BEGIN_TESTS(derive)
    ADD_TEST("ECDH_derive",              test_ecdh_derive);
    ADD_TEST("DeriveKey_invalid_mech",   test_derive_invalid_mechanism);
END_TESTS()
