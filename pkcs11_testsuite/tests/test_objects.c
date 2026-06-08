#include "test_framework.h"
#include <string.h>
#include <stdlib.h>

/* Create a data object and verify it */
static int test_create_data_object(TestCtx *ctx)
{
    CK_OBJECT_CLASS cls   = CKO_DATA;
    CK_BBOOL        tok   = CK_TRUE;
    const char     *label = "TestDataObject";
    const char     *value = "Hello, PKCS11!";

    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &cls,            sizeof(cls)          },
        { CKA_TOKEN,       &tok,            sizeof(tok)          },
        { CKA_LABEL,       (void*)label,    (CK_ULONG)strlen(label) },
        { CKA_VALUE,       (void*)value,    (CK_ULONG)strlen(value) },
    };

    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_RV rv = ctx->mod.fn->C_CreateObject(ctx->rw_session, tmpl, 4, &obj);
    ASSERT_RV_OK(rv, "C_CreateObject data");
    ASSERT_NE(obj, CK_INVALID_HANDLE, "Created object has valid handle");

    rv = ctx->mod.fn->C_DestroyObject(ctx->rw_session, obj);
    ASSERT_RV_OK(rv, "C_DestroyObject data");
    TEST_PASS();
}

/* Create a certificate object */
static int test_create_certificate_object(TestCtx *ctx)
{
    CK_OBJECT_CLASS  cls      = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
    CK_BBOOL         tok      = CK_TRUE;
    const char       *label   = "TestCert";
    unsigned char     fake_cert[] = { 0x30, 0x0a, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02,
                                      0x02, 0x01, 0x03, 0x02 };
    unsigned char     fake_subj[] = { 0x30, 0x01, 0x00 };

    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,            &cls,        sizeof(cls)              },
        { CKA_CERTIFICATE_TYPE, &cert_type,  sizeof(cert_type)        },
        { CKA_TOKEN,            &tok,        sizeof(tok)              },
        { CKA_LABEL,            (void*)label,(CK_ULONG)strlen(label)  },
        { CKA_VALUE,            fake_cert,   sizeof(fake_cert)        },
        { CKA_SUBJECT,          fake_subj,   sizeof(fake_subj)        },
    };

    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_RV rv = ctx->mod.fn->C_CreateObject(ctx->rw_session, tmpl, 6, &obj);
    ASSERT_RV_OK(rv, "C_CreateObject certificate");
    rv = ctx->mod.fn->C_DestroyObject(ctx->rw_session, obj);
    ASSERT_RV_OK(rv, "C_DestroyObject certificate");
    TEST_PASS();
}

static int test_find_objects(TestCtx *ctx)
{
    /* Create two data objects */
    CK_OBJECT_CLASS cls = CKO_DATA;
    CK_BBOOL        tok = CK_FALSE; /* session object */
    const char *lbl1 = "FindMe1";
    const char *lbl2 = "FindMe2";

    CK_ATTRIBUTE tmpl1[] = {
        { CKA_CLASS, &cls,          sizeof(cls)           },
        { CKA_TOKEN, &tok,          sizeof(tok)           },
        { CKA_LABEL, (void*)lbl1,   (CK_ULONG)strlen(lbl1) },
        { CKA_VALUE, (void*)"v1",   2                     },
    };
    CK_ATTRIBUTE tmpl2[] = {
        { CKA_CLASS, &cls,          sizeof(cls)           },
        { CKA_TOKEN, &tok,          sizeof(tok)           },
        { CKA_LABEL, (void*)lbl2,   (CK_ULONG)strlen(lbl2) },
        { CKA_VALUE, (void*)"v2",   2                     },
    };

    CK_OBJECT_HANDLE o1, o2;
    ctx->mod.fn->C_CreateObject(ctx->rw_session, tmpl1, 4, &o1);
    ctx->mod.fn->C_CreateObject(ctx->rw_session, tmpl2, 4, &o2);

    /* Find all data objects (session) */
    CK_ATTRIBUTE search[] = { { CKA_CLASS, &cls, sizeof(cls) } };
    CK_OBJECT_HANDLE found[16];
    CK_ULONG count = pkcs11_find_objects(ctx->mod.fn, ctx->rw_session,
                                          search, 1, found, 16);
    ASSERT_TRUE(count >= 2, "Found at least 2 data objects");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, o1);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, o2);
    TEST_PASS();
}

static int test_find_objects_init_null_template(TestCtx *ctx)
{
    /* FindObjectsInit with NULL template should find all objects */
    CK_RV rv = ctx->mod.fn->C_FindObjectsInit(ctx->rw_session, NULL_PTR, 0);
    ASSERT_RV_OK(rv, "C_FindObjectsInit NULL template");
    CK_OBJECT_HANDLE buf[64];
    CK_ULONG found;
    rv = ctx->mod.fn->C_FindObjects(ctx->rw_session, buf, 64, &found);
    ASSERT_RV_OK(rv, "C_FindObjects");
    rv = ctx->mod.fn->C_FindObjectsFinal(ctx->rw_session);
    ASSERT_RV_OK(rv, "C_FindObjectsFinal");
    TEST_PASS();
}

static int test_find_objects_active_op(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_FindObjectsInit(ctx->rw_session, NULL_PTR, 0);
    ASSERT_RV_OK(rv, "C_FindObjectsInit");
    /* Starting another search while one is active */
    rv = ctx->mod.fn->C_FindObjectsInit(ctx->rw_session, NULL_PTR, 0);
    ASSERT_RV(rv, CKR_OPERATION_ACTIVE, "Double FindObjectsInit");
    ctx->mod.fn->C_FindObjectsFinal(ctx->rw_session);
    TEST_PASS();
}

static int test_get_attribute_value(TestCtx *ctx)
{
    CK_OBJECT_CLASS cls   = CKO_DATA;
    CK_BBOOL        tok   = CK_FALSE;
    const char     *label = "AttrTest";
    const char     *value = "TestValue123";

    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls,         sizeof(cls)           },
        { CKA_TOKEN, &tok,         sizeof(tok)           },
        { CKA_LABEL, (void*)label, (CK_ULONG)strlen(label) },
        { CKA_VALUE, (void*)value, (CK_ULONG)strlen(value) },
    };

    CK_OBJECT_HANDLE obj;
    ctx->mod.fn->C_CreateObject(ctx->rw_session, tmpl, 4, &obj);

    /* Get CKA_VALUE */
    CK_ATTRIBUTE get[] = { { CKA_VALUE, NULL_PTR, 0 } };
    CK_RV rv = ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, obj, get, 1);
    ASSERT_RV_OK(rv, "C_GetAttributeValue get len");
    ASSERT_EQ(get[0].ulValueLen, (CK_ULONG)strlen(value), "value length matches");

    get[0].pValue = malloc(get[0].ulValueLen);
    rv = ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, obj, get, 1);
    ASSERT_RV_OK(rv, "C_GetAttributeValue get value");
    ASSERT_MEM_EQ(get[0].pValue, value, strlen(value), "value content matches");
    free(get[0].pValue);

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, obj);
    TEST_PASS();
}

static int test_get_attribute_invalid_obj(TestCtx *ctx)
{
    CK_ATTRIBUTE get[] = { { CKA_CLASS, NULL_PTR, 0 } };
    CK_RV rv = ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, 0xDEADBEEF, get, 1);
    ASSERT_RV(rv, CKR_OBJECT_HANDLE_INVALID, "C_GetAttributeValue invalid object");
    TEST_PASS();
}

static int test_set_attribute_value(TestCtx *ctx)
{
    CK_OBJECT_CLASS cls   = CKO_DATA;
    CK_BBOOL        tok   = CK_FALSE;
    CK_BBOOL        modifiable = CK_TRUE;
    const char     *label = "SetAttrTest";
    const char     *value = "original";

    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,      &cls,         sizeof(cls)              },
        { CKA_TOKEN,      &tok,         sizeof(tok)              },
        { CKA_MODIFIABLE, &modifiable,  sizeof(modifiable)       },
        { CKA_LABEL,      (void*)label, (CK_ULONG)strlen(label)  },
        { CKA_VALUE,      (void*)value, (CK_ULONG)strlen(value)  },
    };

    CK_OBJECT_HANDLE obj;
    CK_RV rv = ctx->mod.fn->C_CreateObject(ctx->rw_session, tmpl, 5, &obj);
    ASSERT_RV_OK(rv, "C_CreateObject for SetAttr test");

    const char *new_val = "modified";
    CK_ATTRIBUTE set[] = { { CKA_LABEL, (void*)new_val, (CK_ULONG)strlen(new_val) } };
    rv = ctx->mod.fn->C_SetAttributeValue(ctx->rw_session, obj, set, 1);
    ASSERT_RV_OK(rv, "C_SetAttributeValue label");

    /* Verify */
    CK_ATTRIBUTE get[] = { { CKA_LABEL, NULL_PTR, 0 } };
    ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, obj, get, 1);
    char *buf = malloc(get[0].ulValueLen + 1);
    buf[get[0].ulValueLen] = '\0';
    get[0].pValue = buf;
    ctx->mod.fn->C_GetAttributeValue(ctx->rw_session, obj, get, 1);
    ASSERT_TRUE(strcmp(buf, new_val) == 0, "Modified label matches");
    free(buf);

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, obj);
    TEST_PASS();
}

static int test_copy_object(TestCtx *ctx)
{
    CK_OBJECT_CLASS cls   = CKO_DATA;
    CK_BBOOL        tok   = CK_FALSE;
    const char     *label = "CopyTest";
    const char     *value = "copy_me";

    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls,         sizeof(cls)           },
        { CKA_TOKEN, &tok,         sizeof(tok)           },
        { CKA_LABEL, (void*)label, (CK_ULONG)strlen(label) },
        { CKA_VALUE, (void*)value, (CK_ULONG)strlen(value) },
    };

    CK_OBJECT_HANDLE src, dst;
    ctx->mod.fn->C_CreateObject(ctx->rw_session, tmpl, 4, &src);

    const char *new_label = "CopyDest";
    CK_ATTRIBUTE extra[] = { { CKA_LABEL, (void*)new_label, (CK_ULONG)strlen(new_label) } };
    CK_RV rv = ctx->mod.fn->C_CopyObject(ctx->rw_session, src, extra, 1, &dst);
    ASSERT_RV_OK(rv, "C_CopyObject");
    ASSERT_NE(src, dst, "Copy has different handle");

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, src);
    ctx->mod.fn->C_DestroyObject(ctx->rw_session, dst);
    TEST_PASS();
}

static int test_destroy_invalid_object(TestCtx *ctx)
{
    CK_RV rv = ctx->mod.fn->C_DestroyObject(ctx->rw_session, 0xDEADBEEF);
    ASSERT_RV(rv, CKR_OBJECT_HANDLE_INVALID, "C_DestroyObject invalid handle");
    TEST_PASS();
}

static int test_get_object_size(TestCtx *ctx)
{
    CK_OBJECT_CLASS cls   = CKO_DATA;
    CK_BBOOL        tok   = CK_FALSE;
    const char     *label = "SizeTest";
    const char     *value = "some_value";

    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls,         sizeof(cls)              },
        { CKA_TOKEN, &tok,         sizeof(tok)              },
        { CKA_LABEL, (void*)label, (CK_ULONG)strlen(label)  },
        { CKA_VALUE, (void*)value, (CK_ULONG)strlen(value)  },
    };

    CK_OBJECT_HANDLE obj;
    ctx->mod.fn->C_CreateObject(ctx->rw_session, tmpl, 4, &obj);

    CK_ULONG size = 0;
    CK_RV rv = ctx->mod.fn->C_GetObjectSize(ctx->rw_session, obj, &size);
    /* May return CKR_INFORMATION_SENSITIVE for some tokens */
    ASSERT_TRUE(rv == CKR_OK || rv == CKR_INFORMATION_SENSITIVE,
                "C_GetObjectSize returns ok or sensitive");
    if (rv == CKR_OK)
        log_info("  Object size: %lu bytes", size);

    ctx->mod.fn->C_DestroyObject(ctx->rw_session, obj);
    TEST_PASS();
}

BEGIN_TESTS(objects)
    ADD_TEST("C_CreateObject_data",          test_create_data_object);
    ADD_TEST("C_CreateObject_certificate",   test_create_certificate_object);
    ADD_TEST("C_FindObjects",                test_find_objects);
    ADD_TEST("C_FindObjectsInit_null_tmpl",  test_find_objects_init_null_template);
    ADD_TEST("C_FindObjectsInit_active",     test_find_objects_active_op);
    ADD_TEST("C_GetAttributeValue",          test_get_attribute_value);
    ADD_TEST("C_GetAttributeValue_invalid",  test_get_attribute_invalid_obj);
    ADD_TEST("C_SetAttributeValue",          test_set_attribute_value);
    ADD_TEST("C_CopyObject",                 test_copy_object);
    ADD_TEST("C_DestroyObject_invalid",      test_destroy_invalid_object);
    ADD_TEST("C_GetObjectSize",              test_get_object_size);
END_TESTS()
