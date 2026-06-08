#ifndef PKCS11_UTILS_H
#define PKCS11_UTILS_H

#include <pkcs11.h>
#include <stddef.h>
#include <stdint.h>

/* Hex helpers */
void    hex_print(const char *label, const unsigned char *buf, size_t len);
int     hex_parse(const char *hex, unsigned char *buf, size_t *out_len);
char   *hex_encode(const unsigned char *buf, size_t len);

/* Attribute helpers */
CK_ATTRIBUTE *attr_alloc(CK_ULONG count);
void          attr_free(CK_ATTRIBUTE *attrs, CK_ULONG count);
void          attr_set_bool(CK_ATTRIBUTE *a, CK_ATTRIBUTE_TYPE type, CK_BBOOL val);
void          attr_set_ulong(CK_ATTRIBUTE *a, CK_ATTRIBUTE_TYPE type, CK_ULONG val);
void          attr_set_bytes(CK_ATTRIBUTE *a, CK_ATTRIBUTE_TYPE type, const void *data, CK_ULONG len);
void          attr_set_str(CK_ATTRIBUTE *a, CK_ATTRIBUTE_TYPE type, const char *str);

/* Mechanism helpers */
CK_MECHANISM mech(CK_MECHANISM_TYPE type);
CK_MECHANISM mech_param(CK_MECHANISM_TYPE type, void *param, CK_ULONG param_len);

/* Token setup */
int pkcs11_init_token(CK_FUNCTION_LIST_PTR fn, CK_SLOT_ID slot,
                      const char *label, const char *so_pin, const char *user_pin);

/* Find objects */
CK_OBJECT_HANDLE pkcs11_find_object(CK_FUNCTION_LIST_PTR fn,
                                    CK_SESSION_HANDLE session,
                                    CK_ATTRIBUTE *tmpl, CK_ULONG count);

CK_ULONG pkcs11_find_objects(CK_FUNCTION_LIST_PTR fn,
                              CK_SESSION_HANDLE session,
                              CK_ATTRIBUTE *tmpl, CK_ULONG count,
                              CK_OBJECT_HANDLE *handles, CK_ULONG max_handles);

/* Logging */
void log_info(const char *fmt, ...);
void log_warn(const char *fmt, ...);
void log_error(const char *fmt, ...);
void log_ok(const char *fmt, ...);
void log_fail(const char *fmt, ...);

#endif /* PKCS11_UTILS_H */
