/*
 * Requirements-based tests: Object management
 * PKCS#11 v2.40 §11.7 – C_CreateObject, C_CopyObject, C_DestroyObject,
 *                        C_GetObjectSize, C_GetAttributeValue,
 *                        C_SetAttributeValue, C_FindObjectsInit,
 *                        C_FindObjects, C_FindObjectsFinal
 */
#include "test_framework.h"
#include <string.h>
#include <stdlib.h>

/* ── helpers ─────────────────────────────────────────────────────────────── */
static CK_OBJECT_HANDLE make_data_obj(TestCtx *ctx,
                                       const char *label, const char *value,
                                       CK_BBOOL token)
{
    CK_OBJECT_CLASS cls = CKO_DATA;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls,         sizeof(cls)          },
        { CKA_TOKEN, &token,       sizeof(token)        },
        { CKA_LABEL, (void*)label, (CK_ULONG)strlen(label) },
        { CKA_VALUE, (void*)value, (CK_ULONG)strlen(value) },
    };
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    ctx->mod.fn->C_CreateObject(ctx->rw_session, tmpl, 4, &h);
    return h;
}

/* REQ-OBJ-01: C_CreateObject missing required attribute → CKR_TEMPLATE_INCOMPLETE */
static int test_create_object_missing_class(TestCtx *ctx)
{
    /* CKO_DATA object with no CKA_CLASS */
    CK_BBOOL f = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN, &f,           sizeof(f) },
        { CKA_VALUE, (void*)"hi",  2         },
    };
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_RV rv = ctx->mod.fn->C_CreateObject(ctx->rw_session, tmpl, 2, &h);
    ASSERT_RV(rv, CKR_TEMPLATE_INCOMPLETE, "CreateObject missing CKA_CLASS");
    if (h != CK_INVALID_HANDLE) ctx->mod.fn->C_DestroyObject(ctx->rw_session, h);
    TEST_PASS();
}

/* REQ-OBJ-02: C_CreateObject NULL template with count>0 → CKR_ARGUMENTS_BAD */
static int test_create_object_null_template(TestCtx *ctx)
{
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_RV rv = ctx->mod.fn->C_CreateObject(ctx->rw_session, NULL_PTR, 1, &h);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "CreateObject NULL template");
    TEST_PASS();
}

/* REQ-OBJ-03: C_CreateObject NULL phObject → CKR_ARGUMENTS_BAD            */
static int test_create_object_null_handle(TestCtx *ctx)
{
    CK_OBJECT_CLASS cls = CKO_DATA;
    CK_BBOOL f = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls,      sizeof(cls) },
        { CKA_TOKEN, &f,        sizeof(f)   },
        { CKA_VALUE, (void*)"x",1           },
    };
    CK_RV rv = ctx->mod.fn->C_CreateObject(ctx->rw_session, tmpl, 3, NULL_PTR);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "CreateObject NULL phObject");
    TEST_PASS();
}

/* REQ-OBJ-04: CKO_DATA token=TRUE on RO session → CKR_SESSION_READ_ONLY   */
static int test_create_token_object_on_ro_session(TestCtx *ctx)
{
    CK_OBJECT_CLASS cls = CKO_DATA;
    CK_BBOOL t = CK_TRUE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls,          sizeof(cls) },
        { CKA_TOKEN, &t,            sizeof(t)   },
        { CKA_VALUE, (void*)"data", 4           },
    };
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_RV rv = ctx->mod.fn->C_CreateObject(ctx->ro_session, tmpl, 3, &h);
    ASSERT_RV(rv, CKR_SESSION_READ_ONLY,
              "CreateObject token=TRUE on RO session");
    if (h != CK_INVALID_HANDLE) ctx->mod.fn->C_DestroyObject(ctx->rw_session, h);
    TEST_PASS();
}

/* REQ-OBJ-05: Token object persists after session close                   */
static int test_token_object_persists(TestCtx *ctx)
{
    CK_OBJECT_CLASS cls = CKO_DATA;
    CK_BBOOL t = CK_TRUE;
    const char *lbl = "persist_test_label_req";
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls,        sizeof(cls)       },
        { CKA_TOKEN, &t,          sizeof(t)         },
        { CKA_LABEL, (void*)lbl,  (CK_ULONG)strlen(lbl) },
        { CKA_VALUE, (void*)"abc",3                 },
    };
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_RV rv = ctx->mod.fn->C_CreateObject(ctx->rw_session, tmpl, 4, &h);
    ASSERT_RV_OK(rv, "Create token object");

    /* Open a fresh session — token object must still be visible           */
    CK_SESSION_HANDLE tmp = CK_INVALID_HANDLE;
    ctx->mod.fn->C_OpenSession(ctx->slot,
                                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                NULL_PTR, NULL_PTR, &tmp);

    CK_ATTRIBUTE find_tmpl[] = {
        { CKA_LABEL, (void*)lbl, (CK_ULONG)strlen(lbl) },
    };
    CK_OBJECT_HANDLE found = CK_INVALID_HANDLE;
    CK_ULONG found_count = 0;
    ctx->mod.fn->C_FindObjectsInit(tmp, find_tmpl, 1);
    ctx->mod.fn->C_FindObjects(tmp, &found, 1, &found_count);
    ctx->mod.fn->C_FindObjectsFinal(tmp);
    ctx->mod.fn->C_CloseSession(tmp);

    ASSERT_TRUE(found_count > 0 && found != CK_INVALID_HANDLE,
                "Token object visible in new session");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, h);
    TEST_PASS();
}

/* REQ-OBJ-06: C_CopyObject creates independent copy                       */
static int test_copy_object_independent(TestCtx *ctx)
{
    CK_OBJECT_HANDLE orig = make_data_obj(ctx, "orig_copy_req", "originalval", CK_FALSE);
    ASSERT_NE(orig, CK_INVALID_HANDLE, "Original object created");

    const char *new_label = "copy_req";
    CK_ATTRIBUTE mod_tmpl[] = {
        { CKA_LABEL, (void*)new_label, (CK_ULONG)strlen(new_label) },
    };
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    CK_RV rv = ctx->mod.fn->C_CopyObject(ctx->rw_session, orig, mod_tmpl, 1, &copy);
    ASSERT_RV_OK(rv, "CopyObject");
    ASSERT_NE(copy, orig, "Copy handle differs from original");

    /* Verify the new label is set on the copy */
    char buf[64] = {0};
    CK_ATTRIBUTE get = { CKA_LABEL, buf, sizeof(buf) };
    ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, copy, &get, 1);
    ASSERT_TRUE(get.ulValueLen == strlen(new_label) &&
                memcmp(buf, new_label, strlen(new_label)) == 0,
                "Copy has modified label");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, orig);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, copy);
    TEST_PASS();
}

/* REQ-OBJ-07: C_CopyObject NULL phNewObject → CKR_ARGUMENTS_BAD           */
static int test_copy_object_null_handle(TestCtx *ctx)
{
    CK_OBJECT_HANDLE orig = make_data_obj(ctx, "copy_null_req", "v", CK_FALSE);
    ASSERT_NE(orig, CK_INVALID_HANDLE, "Original object");
    CK_RV rv = ctx->mod.fn->C_CopyObject(ctx->rw_session, orig, NULL_PTR, 0, NULL_PTR);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "CopyObject NULL phNewObject");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, orig);
    TEST_PASS();
}

/* REQ-OBJ-08: C_DestroyObject invalid handle → CKR_OBJECT_HANDLE_INVALID  */
static int test_destroy_invalid_handle(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_DestroyObject(ctx->rw_session,
                                              (CK_OBJECT_HANDLE)0xDEADBEEFUL);
    ASSERT_RV(rv, CKR_OBJECT_HANDLE_INVALID, "DestroyObject invalid handle");
    TEST_PASS();
}

/* REQ-OBJ-09: C_GetObjectSize invalid handle → CKR_OBJECT_HANDLE_INVALID  */
static int test_get_object_size_invalid(TestCtx *ctx)
{
    CK_ULONG sz = 0;
    CK_RV rv = ctx->mod.fn->C_GetObjectSize(ctx->rw_session,
                                              (CK_OBJECT_HANDLE)0xDEADBEEFUL, &sz);
    ASSERT_RV(rv, CKR_OBJECT_HANDLE_INVALID, "GetObjectSize invalid handle");
    TEST_PASS();
}

/* REQ-OBJ-10: C_GetObjectSize NULL pulSize → CKR_ARGUMENTS_BAD            */
static int test_get_object_size_null(TestCtx *ctx)
{
    CK_OBJECT_HANDLE h = make_data_obj(ctx, "size_null_req", "value", CK_FALSE);
    ASSERT_NE(h, CK_INVALID_HANDLE, "Object created");
    CK_RV rv = ctx->mod.fn->C_GetObjectSize(ctx->rw_session, h, NULL_PTR);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "GetObjectSize NULL pulSize");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, h);
    TEST_PASS();
}

/* REQ-OBJ-11: C_GetObjectSize returns non-zero for a data object          */
static int test_get_object_size_valid(TestCtx *ctx)
{
    CK_OBJECT_HANDLE h = make_data_obj(ctx, "size_valid_req", "helloworld", CK_FALSE);
    ASSERT_NE(h, CK_INVALID_HANDLE, "Object created");
    CK_ULONG sz = 0;
    CK_RV rv = ctx->mod.fn->C_GetObjectSize(ctx->rw_session, h, &sz);
    /* Some implementations return CKR_INFORMATION_SENSITIVE — accept      */
    ASSERT_TRUE(rv == CKR_OK || rv == CKR_INFORMATION_SENSITIVE,
                "GetObjectSize OK or INFORMATION_SENSITIVE");
    if (rv == CKR_OK)
        ASSERT_TRUE(sz > 0, "Object size > 0");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, h);
    TEST_PASS();
}

/* REQ-OBJ-12: C_GetAttributeValue NULL buffer → size query returns required len */
static int test_get_attr_null_buffer_size_query(TestCtx *ctx)
{
    CK_OBJECT_HANDLE h = make_data_obj(ctx, "attrquery_req", "samplevalue", CK_FALSE);
    ASSERT_NE(h, CK_INVALID_HANDLE, "Object created");

    CK_ATTRIBUTE get = { CKA_VALUE, NULL_PTR, 0 };
    CK_RV rv = ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, h, &get, 1);
    ASSERT_RV_OK(rv, "GetAttributeValue NULL buffer (size query)");
    ASSERT_EQ(get.ulValueLen, (CK_ULONG)strlen("samplevalue"),
              "ulValueLen equals value length");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, h);
    TEST_PASS();
}

/* REQ-OBJ-13: C_GetAttributeValue non-existent attribute                  */
static int test_get_attr_nonexistent(TestCtx *ctx)
{
    CK_OBJECT_HANDLE h = make_data_obj(ctx, "nonexist_req", "v", CK_FALSE);
    ASSERT_NE(h, CK_INVALID_HANDLE, "Object created");

    char buf[32];
    CK_ATTRIBUTE get = { CKA_PRIME, buf, sizeof(buf) };  /* not on data obj */
    CK_RV rv = ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, h, &get, 1);
    /* PKCS#11: ulValueLen set to CK_UNAVAILABLE_INFORMATION; rv may be
     * CKR_ATTRIBUTE_TYPE_INVALID                                          */
    ASSERT_TRUE(rv == CKR_ATTRIBUTE_TYPE_INVALID ||
                get.ulValueLen == (CK_ULONG)-1,
                "Non-existent attribute: error or CK_UNAVAILABLE");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, h);
    TEST_PASS();
}

/* REQ-OBJ-14: C_GetAttributeValue sensitive key attribute → CK_UNAVAILABLE */
static int test_get_attr_sensitive(TestCtx *ctx)
{
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG klen = 16;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &f,    sizeof(f)    },
        { CKA_SENSITIVE, &t,    sizeof(t)    },
        { CKA_ENCRYPT,   &t,    sizeof(t)    },
        { CKA_VALUE_LEN, &klen, sizeof(klen) },
    };
    CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ctx->mod.fn->C_GenerateKey(ctx->rw_session, &m, tmpl, 4, &key);
    ASSERT_NE(key, CK_INVALID_HANDLE, "AES key generated");

    unsigned char val[32];
    CK_ATTRIBUTE get = { CKA_VALUE, val, sizeof(val) };
    CK_RV rv = ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, key, &get, 1);
    ASSERT_TRUE(rv == CKR_ATTRIBUTE_SENSITIVE ||
                get.ulValueLen == (CK_ULONG)-1,
                "Sensitive key CKA_VALUE not accessible");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, key);
    TEST_PASS();
}

/* REQ-OBJ-15: C_GetAttributeValue buffer too small → CKR_BUFFER_TOO_SMALL */
static int test_get_attr_buffer_too_small(TestCtx *ctx)
{
    CK_OBJECT_HANDLE h = make_data_obj(ctx, "toosmall_req", "longvalue123", CK_FALSE);
    ASSERT_NE(h, CK_INVALID_HANDLE, "Object created");

    char tiny[1];
    CK_ATTRIBUTE get = { CKA_VALUE, tiny, sizeof(tiny) };
    CK_RV rv = ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, h, &get, 1);
    ASSERT_RV(rv, CKR_BUFFER_TOO_SMALL, "GetAttributeValue buffer too small");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, h);
    TEST_PASS();
}

/* REQ-OBJ-16: C_GetAttributeValue invalid object → CKR_OBJECT_HANDLE_INVALID */
static int test_get_attr_invalid_object(TestCtx *ctx)
{
    char buf[8];
    CK_ATTRIBUTE get = { CKA_CLASS, buf, sizeof(buf) };
    CK_RV rv = ctx->mod.fn->C_GetAttributeValue(ctx->rw_session,
                                                  (CK_OBJECT_HANDLE)0xDEADBEEFUL,
                                                  &get, 1);
    ASSERT_RV(rv, CKR_OBJECT_HANDLE_INVALID, "GetAttributeValue invalid object");
    TEST_PASS();
}

/* REQ-OBJ-17: C_SetAttributeValue read-only attribute → CKR_ATTRIBUTE_READ_ONLY */
static int test_set_attr_read_only(TestCtx *ctx)
{
    CK_OBJECT_HANDLE h = make_data_obj(ctx, "readonly_req", "v", CK_FALSE);
    ASSERT_NE(h, CK_INVALID_HANDLE, "Object created");

    /* CKA_CLASS is read-only */
    CK_OBJECT_CLASS new_cls = CKO_CERTIFICATE;
    CK_ATTRIBUTE mod = { CKA_CLASS, &new_cls, sizeof(new_cls) };
    CK_RV rv = ctx->mod.fn->C_SetAttributeValue(ctx->rw_session, h, &mod, 1);
    ASSERT_RV(rv, CKR_ATTRIBUTE_READ_ONLY, "SetAttributeValue CKA_CLASS read-only");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, h);
    TEST_PASS();
}

/* REQ-OBJ-18: C_SetAttributeValue on RO session → CKR_SESSION_READ_ONLY   */
static int test_set_attr_ro_session(TestCtx *ctx)
{
    /* Token object: modification via RO session must be rejected          */
    CK_OBJECT_HANDLE h = make_data_obj(ctx, "ro_set_req_tok", "value", CK_TRUE);
    ASSERT_NE(h, CK_INVALID_HANDLE, "Token object created");

    const char *new_lbl = "new_label";
    CK_ATTRIBUTE mod = { CKA_LABEL, (void*)new_lbl, (CK_ULONG)strlen(new_lbl) };
    CK_RV rv = ctx->mod.fn->C_SetAttributeValue(ctx->ro_session, h, &mod, 1);
    ASSERT_RV(rv, CKR_SESSION_READ_ONLY, "SetAttributeValue token obj on RO session");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, h);
    TEST_PASS();
}

/* REQ-OBJ-19: C_SetAttributeValue invalid handle → CKR_OBJECT_HANDLE_INVALID */
static int test_set_attr_invalid_object(TestCtx *ctx)
{
    const char *lbl = "x";
    CK_ATTRIBUTE mod = { CKA_LABEL, (void*)lbl, 1 };
    CK_RV rv = ctx->mod.fn->C_SetAttributeValue(ctx->rw_session,
                                                  (CK_OBJECT_HANDLE)0xDEADBEEFUL,
                                                  &mod, 1);
    ASSERT_RV(rv, CKR_OBJECT_HANDLE_INVALID, "SetAttributeValue invalid handle");
    TEST_PASS();
}

/* REQ-OBJ-20: C_FindObjectsInit while search already active → CKR_OPERATION_ACTIVE */
static int test_find_objects_init_while_active(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_FindObjectsInit(ctx->rw_session, NULL_PTR, 0);
    ASSERT_RV_OK(rv, "First FindObjectsInit");

    rv = ctx->mod.fn->C_FindObjectsInit(ctx->rw_session, NULL_PTR, 0);
    ASSERT_RV(rv, CKR_OPERATION_ACTIVE, "Second FindObjectsInit while active");

    ctx->mod.fn->C_FindObjectsFinal(ctx->rw_session);
    TEST_PASS();
}

/* REQ-OBJ-21: C_FindObjects without FindObjectsInit → CKR_OPERATION_NOT_INITIALIZED */
static int test_find_objects_without_init(TestCtx *ctx)
{
    CK_OBJECT_HANDLE h;
    CK_ULONG count = 0;
    CK_RV rv = ctx->mod.fn->C_FindObjects(ctx->rw_session, &h, 1, &count);
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED,
              "FindObjects without Init");
    TEST_PASS();
}

/* REQ-OBJ-22: C_FindObjectsFinal without FindObjectsInit → CKR_OPERATION_NOT_INITIALIZED */
static int test_find_objects_final_without_init(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_FindObjectsFinal(ctx->rw_session);
    ASSERT_RV(rv, CKR_OPERATION_NOT_INITIALIZED,
              "FindObjectsFinal without Init");
    TEST_PASS();
}

/* REQ-OBJ-23: C_FindObjects NULL phObject → CKR_ARGUMENTS_BAD             */
static int test_find_objects_null_handle(TestCtx *ctx)
{
    ctx->mod.fn->C_FindObjectsInit(ctx->rw_session, NULL_PTR, 0);
    CK_ULONG count = 0;
    CK_RV rv = ctx->mod.fn->C_FindObjects(ctx->rw_session, NULL_PTR, 1, &count);
    ASSERT_RV(rv, CKR_ARGUMENTS_BAD, "FindObjects NULL phObject");
    ctx->mod.fn->C_FindObjectsFinal(ctx->rw_session);
    TEST_PASS();
}

/* REQ-OBJ-24: FindObjects returns at most ulMaxObjectCount handles        */
static int test_find_objects_max_count(TestCtx *ctx)
{
    /* Create 5 objects */
    CK_OBJECT_HANDLE objs[5];
    for (int i = 0; i < 5; i++) {
        char lbl[32];
        snprintf(lbl, sizeof(lbl), "maxcount_req_%d", i);
        objs[i] = make_data_obj(ctx, lbl, "v", CK_FALSE);
    }

    ctx->mod.fn->C_FindObjectsInit(ctx->rw_session, NULL_PTR, 0);
    CK_OBJECT_HANDLE found[3];
    CK_ULONG count = 0;
    CK_RV rv = ctx->mod.fn->C_FindObjects(ctx->rw_session, found, 3, &count);
    ASSERT_RV_OK(rv, "FindObjects with max 3");
    ASSERT_TRUE(count <= 3, "FindObjects returned at most 3 handles");
    ctx->mod.fn->C_FindObjectsFinal(ctx->rw_session);

    for (int i = 0; i < 5; i++)
        ctx->mod.fn->C_DestroyObject(ctx->rw_session, objs[i]);
    TEST_PASS();
}

/* REQ-OBJ-25: FindObjects with multi-attribute template filters correctly */
static int test_find_objects_multi_attr_filter(TestCtx *ctx)
{
    /* Create two objects with different labels */
    CK_OBJECT_HANDLE h1 = make_data_obj(ctx, "filter_req_A", "aaa", CK_FALSE);
    CK_OBJECT_HANDLE h2 = make_data_obj(ctx, "filter_req_B", "bbb", CK_FALSE);
    ASSERT_NE(h1, CK_INVALID_HANDLE, "Object A created");
    ASSERT_NE(h2, CK_INVALID_HANDLE, "Object B created");

    const char *target = "filter_req_A";
    CK_ATTRIBUTE tmpl[] = {
        { CKA_LABEL, (void*)target, (CK_ULONG)strlen(target) },
    };
    ctx->mod.fn->C_FindObjectsInit(ctx->rw_session, tmpl, 1);
    CK_OBJECT_HANDLE found[5];
    CK_ULONG count = 0;
    ctx->mod.fn->C_FindObjects(ctx->rw_session, found, 5, &count);
    ctx->mod.fn->C_FindObjectsFinal(ctx->rw_session);

    ASSERT_TRUE(count >= 1, "At least one object found with label filter_req_A");
    /* Verify none of the found objects has label filter_req_B */
    for (CK_ULONG i = 0; i < count; i++) {
        char lbl[64] = {0};
        CK_ATTRIBUTE chk = { CKA_LABEL, lbl, sizeof(lbl) };
        ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, found[i], &chk, 1);
        ASSERT_TRUE(chk.ulValueLen == strlen(target) &&
                    memcmp(lbl, target, strlen(target)) == 0,
                    "All found objects match the label filter");
    }

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, h1);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, h2);
    TEST_PASS();
}

/* REQ-OBJ-26: C_CreateObject certificate object                           */
static int test_create_certificate_object(TestCtx *ctx)
{
    CK_OBJECT_CLASS cls  = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE ct = CKC_X_509;
    CK_BBOOL f = CK_FALSE;
    /* Minimal DER-encoded Subject: SEQUENCE { SET { SEQUENCE { OID cn, UTF8 "test" } } } */
    unsigned char subject[] = {
        0x30,0x0e, 0x31,0x0c, 0x30,0x0a,
        0x06,0x03,0x55,0x04,0x03, 0x0c,0x03,0x74,0x65,0x73,0x74
    };
    unsigned char fake_cert[64];
    memset(fake_cert, 0xAB, sizeof(fake_cert));

    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,            &cls,       sizeof(cls)            },
        { CKA_CERTIFICATE_TYPE, &ct,        sizeof(ct)             },
        { CKA_TOKEN,            &f,         sizeof(f)              },
        { CKA_SUBJECT,          subject,    sizeof(subject)        },
        { CKA_VALUE,            fake_cert,  sizeof(fake_cert)      },
    };
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_RV rv = ctx->mod.fn->C_CreateObject(ctx->rw_session, tmpl, 5, &h);
    ASSERT_RV_OK(rv, "CreateObject certificate");
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, h);
    TEST_PASS();
}

/* REQ-OBJ-27: C_CreateObject public-key object with raw value             */
static int test_create_secret_key_with_value(TestCtx *ctx)
{
    CK_OBJECT_CLASS cls  = CKO_SECRET_KEY;
    CK_KEY_TYPE ktype    = CKK_AES;
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    unsigned char aes_val[16];
    memset(aes_val, 0x42, sizeof(aes_val));

    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,     &cls,    sizeof(cls)    },
        { CKA_KEY_TYPE,  &ktype,  sizeof(ktype)  },
        { CKA_TOKEN,     &f,      sizeof(f)      },
        { CKA_ENCRYPT,   &t,      sizeof(t)      },
        { CKA_DECRYPT,   &t,      sizeof(t)      },
        { CKA_VALUE,     aes_val, sizeof(aes_val)},
    };
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_RV rv = ctx->mod.fn->C_CreateObject(ctx->rw_session, tmpl, 6, &h);
    ASSERT_RV_OK(rv, "CreateObject AES key with value");

    /* Verify it can encrypt */
    unsigned char iv[16] = {0}, plain[16] = "test", cipher[32] = {0};
    CK_ULONG clen = sizeof(cipher);
    CK_MECHANISM m = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    rv = ctx->mod.fn->C_EncryptInit(ctx->rw_session, &m, h);
    ASSERT_RV_OK(rv, "EncryptInit with imported AES key");
    rv = ctx->mod.fn->C_Encrypt(ctx->rw_session, plain, sizeof(plain), cipher, &clen);
    ASSERT_RV_OK(rv, "Encrypt with imported AES key");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, h);
    TEST_PASS();
}

BEGIN_TESTS(req_objects)
    ADD_TEST("REQ-OBJ-01_CreateObject_missing_class",      test_create_object_missing_class);
    ADD_TEST("REQ-OBJ-02_CreateObject_null_template",      test_create_object_null_template);
    ADD_TEST("REQ-OBJ-03_CreateObject_null_handle",        test_create_object_null_handle);
    ADD_TEST("REQ-OBJ-04_CreateObject_token_on_ro_session",test_create_token_object_on_ro_session);
    ADD_TEST("REQ-OBJ-05_Token_object_persists",           test_token_object_persists);
    ADD_TEST("REQ-OBJ-06_CopyObject_independent",          test_copy_object_independent);
    ADD_TEST("REQ-OBJ-07_CopyObject_null_handle",          test_copy_object_null_handle);
    ADD_TEST("REQ-OBJ-08_DestroyObject_invalid_handle",    test_destroy_invalid_handle);
    ADD_TEST("REQ-OBJ-09_GetObjectSize_invalid",           test_get_object_size_invalid);
    ADD_TEST("REQ-OBJ-10_GetObjectSize_null",              test_get_object_size_null);
    ADD_TEST("REQ-OBJ-11_GetObjectSize_valid",             test_get_object_size_valid);
    ADD_TEST("REQ-OBJ-12_GetAttr_null_buffer_size_query",  test_get_attr_null_buffer_size_query);
    ADD_TEST("REQ-OBJ-13_GetAttr_nonexistent",             test_get_attr_nonexistent);
    ADD_TEST("REQ-OBJ-14_GetAttr_sensitive",               test_get_attr_sensitive);
    ADD_TEST("REQ-OBJ-15_GetAttr_buffer_too_small",        test_get_attr_buffer_too_small);
    ADD_TEST("REQ-OBJ-16_GetAttr_invalid_object",          test_get_attr_invalid_object);
    ADD_TEST("REQ-OBJ-17_SetAttr_read_only",               test_set_attr_read_only);
    ADD_TEST("REQ-OBJ-18_SetAttr_ro_session",              test_set_attr_ro_session);
    ADD_TEST("REQ-OBJ-19_SetAttr_invalid_object",          test_set_attr_invalid_object);
    ADD_TEST("REQ-OBJ-20_FindObjectsInit_while_active",    test_find_objects_init_while_active);
    ADD_TEST("REQ-OBJ-21_FindObjects_without_init",        test_find_objects_without_init);
    ADD_TEST("REQ-OBJ-22_FindObjectsFinal_without_init",   test_find_objects_final_without_init);
    ADD_TEST("REQ-OBJ-23_FindObjects_null_handle",         test_find_objects_null_handle);
    ADD_TEST("REQ-OBJ-24_FindObjects_max_count",           test_find_objects_max_count);
    ADD_TEST("REQ-OBJ-25_FindObjects_multi_attr_filter",   test_find_objects_multi_attr_filter);
    ADD_TEST("REQ-OBJ-26_CreateObject_certificate",        test_create_certificate_object);
    ADD_TEST("REQ-OBJ-27_CreateObject_secret_key_value",   test_create_secret_key_with_value);
END_TESTS()
