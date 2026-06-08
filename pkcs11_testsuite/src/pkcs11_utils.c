#include "pkcs11_utils.h"
#include "pkcs11_loader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* ---- Colour codes ---- */
#define COL_RESET  "\033[0m"
#define COL_GREEN  "\033[32m"
#define COL_RED    "\033[31m"
#define COL_YELLOW "\033[33m"
#define COL_CYAN   "\033[36m"

void log_info(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    printf(COL_CYAN "[INFO] " COL_RESET); vprintf(fmt, ap); printf("\n");
    va_end(ap);
}
void log_warn(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    printf(COL_YELLOW "[WARN] " COL_RESET); vprintf(fmt, ap); printf("\n");
    va_end(ap);
}
void log_error(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, COL_RED "[ERR]  " COL_RESET); vfprintf(stderr, fmt, ap); fprintf(stderr, "\n");
    va_end(ap);
}
void log_ok(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    printf(COL_GREEN "[ OK ] " COL_RESET); vprintf(fmt, ap); printf("\n");
    va_end(ap);
}
void log_fail(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, COL_RED "[FAIL] " COL_RESET); vfprintf(stderr, fmt, ap); fprintf(stderr, "\n");
    va_end(ap);
}

/* ---- Hex helpers ---- */
void hex_print(const char *label, const unsigned char *buf, size_t len)
{
    printf("  %s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

char *hex_encode(const unsigned char *buf, size_t len)
{
    char *out = malloc(len * 2 + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < len; i++) sprintf(out + i*2, "%02x", buf[i]);
    out[len*2] = '\0';
    return out;
}

int hex_parse(const char *hex, unsigned char *buf, size_t *out_len)
{
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0) return -1;
    *out_len = hlen / 2;
    for (size_t i = 0; i < *out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + i*2, "%02x", &byte) != 1) return -1;
        buf[i] = (unsigned char)byte;
    }
    return 0;
}

/* ---- Attribute helpers ---- */
CK_ATTRIBUTE *attr_alloc(CK_ULONG count)
{
    CK_ATTRIBUTE *a = calloc(count, sizeof(CK_ATTRIBUTE));
    return a;
}

void attr_free(CK_ATTRIBUTE *attrs, CK_ULONG count)
{
    if (!attrs) return;
    for (CK_ULONG i = 0; i < count; i++) {
        free(attrs[i].pValue);
    }
    free(attrs);
}

void attr_set_bool(CK_ATTRIBUTE *a, CK_ATTRIBUTE_TYPE type, CK_BBOOL val)
{
    CK_BBOOL *v = malloc(sizeof(CK_BBOOL));
    *v = val;
    a->type = type;
    a->pValue = v;
    a->ulValueLen = sizeof(CK_BBOOL);
}

void attr_set_ulong(CK_ATTRIBUTE *a, CK_ATTRIBUTE_TYPE type, CK_ULONG val)
{
    CK_ULONG *v = malloc(sizeof(CK_ULONG));
    *v = val;
    a->type = type;
    a->pValue = v;
    a->ulValueLen = sizeof(CK_ULONG);
}

void attr_set_bytes(CK_ATTRIBUTE *a, CK_ATTRIBUTE_TYPE type, const void *data, CK_ULONG len)
{
    void *v = malloc(len);
    memcpy(v, data, len);
    a->type = type;
    a->pValue = v;
    a->ulValueLen = len;
}

void attr_set_str(CK_ATTRIBUTE *a, CK_ATTRIBUTE_TYPE type, const char *str)
{
    attr_set_bytes(a, type, str, (CK_ULONG)strlen(str));
}

/* ---- Mechanism helpers ---- */
CK_MECHANISM mech(CK_MECHANISM_TYPE type)
{
    CK_MECHANISM m = { type, NULL_PTR, 0 };
    return m;
}

CK_MECHANISM mech_param(CK_MECHANISM_TYPE type, void *param, CK_ULONG param_len)
{
    CK_MECHANISM m = { type, param, param_len };
    return m;
}

/* ---- Token init ---- */
int pkcs11_init_token(CK_FUNCTION_LIST_PTR fn, CK_SLOT_ID slot,
                      const char *label, const char *so_pin, const char *user_pin)
{
    char padded_label[32];
    memset(padded_label, ' ', 32);
    size_t llen = strlen(label);
    if (llen > 32) llen = 32;
    memcpy(padded_label, label, llen);

    CK_RV rv = fn->C_InitToken(slot,
                               (CK_UTF8CHAR_PTR)so_pin, (CK_ULONG)strlen(so_pin),
                               (CK_UTF8CHAR_PTR)padded_label);
    if (rv != CKR_OK) {
        log_error("C_InitToken: %s", pkcs11_rv_str(rv));
        return -1;
    }

    /* Open SO session to set user PIN */
    CK_SESSION_HANDLE sess;
    rv = fn->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &sess);
    if (rv != CKR_OK) { log_error("C_OpenSession: %s", pkcs11_rv_str(rv)); return -1; }

    rv = fn->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR)so_pin, (CK_ULONG)strlen(so_pin));
    if (rv != CKR_OK) { fn->C_CloseSession(sess); log_error("C_Login SO: %s", pkcs11_rv_str(rv)); return -1; }

    rv = fn->C_InitPIN(sess, (CK_UTF8CHAR_PTR)user_pin, (CK_ULONG)strlen(user_pin));
    fn->C_Logout(sess);
    fn->C_CloseSession(sess);

    if (rv != CKR_OK) { log_error("C_InitPIN: %s", pkcs11_rv_str(rv)); return -1; }
    return 0;
}

/* ---- Object search ---- */
CK_OBJECT_HANDLE pkcs11_find_object(CK_FUNCTION_LIST_PTR fn,
                                    CK_SESSION_HANDLE session,
                                    CK_ATTRIBUTE *tmpl, CK_ULONG count)
{
    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
    CK_ULONG found = 0;

    fn->C_FindObjectsInit(session, tmpl, count);
    fn->C_FindObjects(session, &handle, 1, &found);
    fn->C_FindObjectsFinal(session);

    return (found > 0) ? handle : CK_INVALID_HANDLE;
}

CK_ULONG pkcs11_find_objects(CK_FUNCTION_LIST_PTR fn,
                              CK_SESSION_HANDLE session,
                              CK_ATTRIBUTE *tmpl, CK_ULONG count,
                              CK_OBJECT_HANDLE *handles, CK_ULONG max_handles)
{
    CK_ULONG found = 0;

    fn->C_FindObjectsInit(session, tmpl, count);
    fn->C_FindObjects(session, handles, max_handles, &found);
    fn->C_FindObjectsFinal(session);

    return found;
}
