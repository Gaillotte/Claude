#ifndef PKCS11_LOADER_H
#define PKCS11_LOADER_H

#include <pkcs11.h>
#include <stddef.h>

typedef struct {
    void *handle;
    CK_FUNCTION_LIST_PTR fn;
    char lib_path[512];
} PKCS11_Module;

int  pkcs11_load(PKCS11_Module *mod, const char *lib_path);
void pkcs11_unload(PKCS11_Module *mod);

/* Convenience wrappers that check return value */
const char *pkcs11_rv_str(CK_RV rv);

#endif /* PKCS11_LOADER_H */
