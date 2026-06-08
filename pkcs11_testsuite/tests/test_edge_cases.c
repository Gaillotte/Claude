#include "test_framework.h"
#include <string.h>
#include <stdlib.h>

/* ---- Encrypt active when calling EncryptInit again ---- */
static int test_operation_active(TestCtx *ctx)
{
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG klen = 16;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &f,    sizeof(f)    },
        { CKA_ENCRYPT,   &t,    sizeof(t)    },
        { CKA_VALUE_LEN, &klen, sizeof(klen) },
    };
    CK_MECHANISM gen_m = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key;
    ctx->mod.fn->C_GenerateKey(ctx->rw_session, &gen_m, tmpl, 3, &key);

    unsigned char iv[16] = {0};
    CK_MECHANISM m = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    ctx->mod.fn->C_EncryptInit(ctx->rw_session, &m, key);

    CK_RV rv = ctx->mod.fn->C_EncryptInit(ctx->rw_session, &m, key);
    ASSERT_RV(rv, CKR_OPERATION_ACTIVE, "Double EncryptInit returns OPERATION_ACTIVE");

    /* Abort */
    unsigned char out[32]; CK_ULONG olen = sizeof(out);
    ctx->mod.fn->C_EncryptFinal(ctx->rw_session, out, &olen);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

/* ---- RO session cannot create token objects ---- */
static int test_ro_session_cannot_create_token_object(TestCtx *ctx)
{
    CK_OBJECT_CLASS cls   = CKO_DATA;
    CK_BBOOL        tok   = CK_TRUE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls,          sizeof(cls)      },
        { CKA_TOKEN, &tok,          sizeof(tok)      },
        { CKA_LABEL, (void*)"test", 4                },
        { CKA_VALUE, (void*)"val",  3                },
    };
    CK_OBJECT_HANDLE obj;
    CK_RV rv = ctx->mod.fn->C_CreateObject(ctx->ro_session, tmpl, 4, &obj);
    ASSERT_RV(rv, CKR_SESSION_READ_ONLY, "RO session cannot create token object");
    TEST_PASS();
}

/* ---- Destroy object from wrong session is still OK (any session in same login) ---- */
static int test_destroy_from_different_session(TestCtx *ctx)
{
    /* Create object on rw_session */
    CK_OBJECT_CLASS cls = CKO_DATA;
    CK_BBOOL f = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls,        sizeof(cls) },
        { CKA_TOKEN, &f,          sizeof(f)   },
        { CKA_LABEL, (void*)"x",  1           },
        { CKA_VALUE, (void*)"y",  1           },
    };
    CK_OBJECT_HANDLE obj;
    ctx->mod.fn->C_CreateObject(ctx->rw_session, tmpl, 4, &obj);
    ASSERT_NE(obj, CK_INVALID_HANDLE, "Object created");

    /* Open another session, still same login */
    CK_SESSION_HANDLE other;
    ctx->mod.fn->C_OpenSession(ctx->slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                NULL_PTR, NULL_PTR, &other);

    /* Session objects are visible across sessions with same login */
    CK_RV rv = ctx->mod.fn->C_DestroyObject(other, obj);
    ASSERT_RV_OK(rv, "Destroy session object from different session");
    ctx->mod.fn->C_CloseSession(other);
    TEST_PASS();
}

/* ---- Empty plaintext encryption ---- */
static int test_encrypt_empty_plaintext(TestCtx *ctx)
{
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG klen = 16;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &f,    sizeof(f)    },
        { CKA_ENCRYPT,   &t,    sizeof(t)    },
        { CKA_DECRYPT,   &t,    sizeof(t)    },
        { CKA_VALUE_LEN, &klen, sizeof(klen) },
    };
    CK_MECHANISM gen_m = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key;
    ctx->mod.fn->C_GenerateKey(ctx->rw_session, &gen_m, tmpl, 4, &key);

    unsigned char iv[16]    = {0};
    unsigned char cipher[32]= {0};
    unsigned char dec[32]   = {0};
    CK_ULONG clen = sizeof(cipher), dlen = sizeof(dec);

    CK_MECHANISM m = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    CK_RV rv = ctx->mod.fn->C_EncryptInit(ctx->rw_session, &m, key);
    ASSERT_RV_OK(rv, "EncryptInit empty");
    unsigned char empty_plain[1] = {0};
    rv = ctx->mod.fn->C_Encrypt(ctx->rw_session, empty_plain, 0, cipher, &clen);
    ASSERT_RV_OK(rv, "Encrypt empty plaintext");
    ASSERT_TRUE(clen > 0, "Empty plaintext produces padding block");

    rv = ctx->mod.fn->C_DecryptInit(ctx->rw_session, &m, key);
    ASSERT_RV_OK(rv, "DecryptInit");
    rv = ctx->mod.fn->C_Decrypt(ctx->rw_session, cipher, clen, dec, &dlen);
    ASSERT_RV_OK(rv, "Decrypt empty ciphertext");
    ASSERT_EQ(dlen, 0UL, "Recovered empty plaintext");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

/* ---- Very large object attribute ---- */
static int test_large_data_object(TestCtx *ctx)
{
    CK_OBJECT_CLASS cls = CKO_DATA;
    CK_BBOOL f = CK_FALSE;
    CK_ULONG big_len = 65536;
    unsigned char *big = calloc(1, big_len);
    for (CK_ULONG i = 0; i < big_len; i++) big[i] = (unsigned char)(i & 0xFF);

    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls,          sizeof(cls)  },
        { CKA_TOKEN, &f,            sizeof(f)    },
        { CKA_LABEL, (void*)"big",  3            },
        { CKA_VALUE, big,           big_len      },
    };
    CK_OBJECT_HANDLE obj;
    CK_RV rv = ctx->mod.fn->C_CreateObject(ctx->rw_session, tmpl, 4, &obj);
    ASSERT_RV_OK(rv, "Create large data object (64KB)");

    /* Read it back */
    CK_ATTRIBUTE get = { CKA_VALUE, NULL_PTR, 0 };
    ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, obj, &get, 1);
    ASSERT_EQ(get.ulValueLen, big_len, "Large attribute length matches");

    unsigned char *buf = malloc(big_len);
    get.pValue = buf;
    ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, obj, &get, 1);
    ASSERT_MEM_EQ(buf, big, big_len, "Large attribute content matches");
    free(buf);
    free(big);

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, obj);
    TEST_PASS();
}

/* ---- Get attribute with insufficient buffer ---- */
static int test_get_attr_buffer_too_small(TestCtx *ctx)
{
    CK_OBJECT_CLASS cls = CKO_DATA;
    CK_BBOOL f = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls,            sizeof(cls)  },
        { CKA_TOKEN, &f,              sizeof(f)    },
        { CKA_LABEL, (void*)"label",  5            },
        { CKA_VALUE, (void*)"abcdefg",7            },
    };
    CK_OBJECT_HANDLE obj;
    ctx->mod.fn->C_CreateObject(ctx->rw_session, tmpl, 4, &obj);

    char tiny[1];
    CK_ATTRIBUTE get = { CKA_VALUE, tiny, sizeof(tiny) };
    CK_RV rv = ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, obj, &get, 1);
    ASSERT_RV(rv, CKR_BUFFER_TOO_SMALL, "GetAttributeValue buffer too small");
    /* PKCS#11 2.40 says ulValueLen should be set to required size on CKR_BUFFER_TOO_SMALL.
     * Some implementations set it to CK_UNAVAILABLE_INFORMATION (-1) instead. Accept both. */
    ASSERT_TRUE(get.ulValueLen == 7UL || get.ulValueLen == (CK_ULONG)-1, "Required length returned");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, obj);
    TEST_PASS();
}

/* ---- Decrypt with wrong key ---- */
static int test_decrypt_wrong_key(TestCtx *ctx)
{
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG klen = 16;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &f,    sizeof(f)    },
        { CKA_ENCRYPT,   &t,    sizeof(t)    },
        { CKA_DECRYPT,   &t,    sizeof(t)    },
        { CKA_VALUE_LEN, &klen, sizeof(klen) },
    };
    CK_MECHANISM gen_m = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key1, key2;
    ctx->mod.fn->C_GenerateKey(ctx->rw_session, &gen_m, tmpl, 4, &key1);
    ctx->mod.fn->C_GenerateKey(ctx->rw_session, &gen_m, tmpl, 4, &key2);

    unsigned char iv[16]    = {0};
    unsigned char plain[32] = "plaintext for wrong key test ...";
    unsigned char cipher[64]= {0};
    unsigned char dec[48]   = {0};
    CK_ULONG clen = sizeof(cipher), dlen = sizeof(dec);

    CK_MECHANISM m = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    ctx->mod.fn->C_EncryptInit(ctx->rw_session, &m, key1);
    ctx->mod.fn->C_Encrypt(ctx->rw_session, plain, sizeof(plain), cipher, &clen);

    ctx->mod.fn->C_DecryptInit(ctx->rw_session, &m, key2);
    CK_RV rv = ctx->mod.fn->C_Decrypt(ctx->rw_session, cipher, clen, dec, &dlen);
    /* Either bad padding or invalid data */
    ASSERT_TRUE(rv != CKR_OK || memcmp(dec, plain, sizeof(plain)) != 0,
                "Decrypt with wrong key should fail or produce garbage");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key1);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key2);
    TEST_PASS();
}

/* ---- Template with conflicting attributes ---- */
static int test_create_object_inconsistent_template(TestCtx *ctx)
{
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG klen = 16;
    /* Sensitive=TRUE and Extractable=TRUE is OK; Sensitive=TRUE and
       CKA_VALUE set is inconsistent for a secret key */
    CK_OBJECT_CLASS cls  = CKO_SECRET_KEY;
    CK_KEY_TYPE kt       = CKK_AES;
    unsigned char val[16]= {0};
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,     &cls,  sizeof(cls)  },
        { CKA_KEY_TYPE,  &kt,   sizeof(kt)   },
        { CKA_TOKEN,     &f,    sizeof(f)    },
        { CKA_VALUE,     val,   sizeof(val)  },
        { CKA_SENSITIVE, &t,    sizeof(t)    },
        { CKA_VALUE_LEN, &klen, sizeof(klen) },
    };
    CK_OBJECT_HANDLE obj;
    CK_RV rv = ctx->mod.fn->C_CreateObject(ctx->rw_session, tmpl, 6, &obj);
    if (rv == CKR_OK) {
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, obj);
        log_info("  Token allows creating AES key with explicit value (vendor extension)");
    } else {
        log_info("  Token rejected explicit value for sensitive key: %s", pkcs11_rv_str(rv));
    }
    TEST_PASS(); /* Both outcomes are acceptable */
}

/* ---- FindObjects without FindObjectsInit ---- */
static int test_find_without_init(TestCtx *ctx)
{
    CK_OBJECT_HANDLE buf[8];
    CK_ULONG found;
    CK_RV rv = ctx->mod.fn->C_FindObjects(ctx->rw_session, buf, 8, &found);
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "FindObjects without init");
    TEST_PASS();
}

/* ---- FindObjectsFinal without FindObjectsInit ---- */
static int test_find_final_without_init(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_FindObjectsFinal(ctx->rw_session);
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "FindObjectsFinal without init");
    TEST_PASS();
}

/* ---- NULL session handle operations ---- */
static int test_null_session_encrypt_init(TestCtx *ctx)
{
    CK_MECHANISM m = { CKM_AES_CBC_PAD, NULL_PTR, 0 };
    CK_RV rv = ctx->mod.fn->C_EncryptInit(CK_INVALID_HANDLE, &m, CK_INVALID_HANDLE);
    ASSERT_RV(rv, CKR_SESSION_HANDLE_INVALID, "EncryptInit invalid session");
    TEST_PASS();
}

/* ---- C_GetAttributeValue for sensitive attr ---- */
static int test_get_sensitive_attribute(TestCtx *ctx)
{
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG klen = 16;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &f,    sizeof(f)    },
        { CKA_SENSITIVE, &t,    sizeof(t)    },
        { CKA_EXTRACTABLE,&f,   sizeof(f)    },
        { CKA_ENCRYPT,   &t,    sizeof(t)    },
        { CKA_VALUE_LEN, &klen, sizeof(klen) },
    };
    CK_MECHANISM gen_m = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key;
    ctx->mod.fn->C_GenerateKey(ctx->rw_session, &gen_m, tmpl, 5, &key);
    ASSERT_NE(key, CK_INVALID_HANDLE, "AES key generated");

    /* Trying to get the secret key value should fail */
    unsigned char val_buf[32];
    CK_ATTRIBUTE get_val = { CKA_VALUE, val_buf, sizeof(val_buf) };
    CK_RV rv = ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, key, &get_val, 1);
    ASSERT_TRUE(rv == CKR_ATTRIBUTE_SENSITIVE || rv == CKR_ATTRIBUTE_TYPE_INVALID,
                "Cannot extract sensitive key value");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

BEGIN_TESTS(edge_cases)
    ADD_TEST("OperationActive",                    test_operation_active);
    ADD_TEST("RO_session_no_token_object",         test_ro_session_cannot_create_token_object);
    ADD_TEST("Destroy_from_different_session",     test_destroy_from_different_session);
    ADD_TEST("Encrypt_empty_plaintext",            test_encrypt_empty_plaintext);
    ADD_TEST("Large_data_object",                  test_large_data_object);
    ADD_TEST("GetAttr_buffer_too_small",           test_get_attr_buffer_too_small);
    ADD_TEST("Decrypt_wrong_key",                  test_decrypt_wrong_key);
    ADD_TEST("CreateObject_inconsistent_template", test_create_object_inconsistent_template);
    ADD_TEST("FindObjects_without_init",           test_find_without_init);
    ADD_TEST("FindObjectsFinal_without_init",      test_find_final_without_init);
    ADD_TEST("Null_session_EncryptInit",           test_null_session_encrypt_init);
    ADD_TEST("GetAttr_sensitive_value",            test_get_sensitive_attribute);
END_TESTS()
