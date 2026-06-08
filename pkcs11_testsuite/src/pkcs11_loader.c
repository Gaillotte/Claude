#include "pkcs11_loader.h"
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

int pkcs11_load(PKCS11_Module *mod, const char *lib_path)
{
    if (!mod || !lib_path) return -1;

    memset(mod, 0, sizeof(*mod));
    strncpy(mod->lib_path, lib_path, sizeof(mod->lib_path) - 1);

    mod->handle = dlopen(lib_path, RTLD_NOW | RTLD_LOCAL);
    if (!mod->handle) {
        fprintf(stderr, "dlopen(%s): %s\n", lib_path, dlerror());
        return -1;
    }

    CK_C_GetFunctionList get_fn = (CK_C_GetFunctionList)dlsym(mod->handle, "C_GetFunctionList");
    if (!get_fn) {
        fprintf(stderr, "C_GetFunctionList not found: %s\n", dlerror());
        dlclose(mod->handle);
        mod->handle = NULL;
        return -1;
    }

    CK_RV rv = get_fn(&mod->fn);
    if (rv != CKR_OK || !mod->fn) {
        fprintf(stderr, "C_GetFunctionList returned 0x%lX\n", rv);
        dlclose(mod->handle);
        mod->handle = NULL;
        return -1;
    }

    return 0;
}

void pkcs11_unload(PKCS11_Module *mod)
{
    if (!mod) return;
    if (mod->fn) {
        mod->fn->C_Finalize(NULL_PTR);
    }
    if (mod->handle) {
        dlclose(mod->handle);
        mod->handle = NULL;
    }
    mod->fn = NULL;
}

/* ---- Return value strings ---- */
#define RV_CASE(x) case x: return #x

const char *pkcs11_rv_str(CK_RV rv)
{
    switch (rv) {
        RV_CASE(CKR_OK);
        RV_CASE(CKR_CANCEL);
        RV_CASE(CKR_HOST_MEMORY);
        RV_CASE(CKR_SLOT_ID_INVALID);
        RV_CASE(CKR_GENERAL_ERROR);
        RV_CASE(CKR_FUNCTION_FAILED);
        RV_CASE(CKR_ARGUMENTS_BAD);
        RV_CASE(CKR_NO_EVENT);
        RV_CASE(CKR_NEED_TO_CREATE_THREADS);
        RV_CASE(CKR_CANT_LOCK);
        RV_CASE(CKR_ATTRIBUTE_READ_ONLY);
        RV_CASE(CKR_ATTRIBUTE_SENSITIVE);
        RV_CASE(CKR_ATTRIBUTE_TYPE_INVALID);
        RV_CASE(CKR_ATTRIBUTE_VALUE_INVALID);
        RV_CASE(CKR_DATA_INVALID);
        RV_CASE(CKR_DATA_LEN_RANGE);
        RV_CASE(CKR_DEVICE_ERROR);
        RV_CASE(CKR_DEVICE_MEMORY);
        RV_CASE(CKR_DEVICE_REMOVED);
        RV_CASE(CKR_ENCRYPTED_DATA_INVALID);
        RV_CASE(CKR_ENCRYPTED_DATA_LEN_RANGE);
        RV_CASE(CKR_FUNCTION_CANCELED);
        RV_CASE(CKR_FUNCTION_NOT_PARALLEL);
        RV_CASE(CKR_FUNCTION_NOT_SUPPORTED);
        RV_CASE(CKR_KEY_HANDLE_INVALID);
        RV_CASE(CKR_KEY_SIZE_RANGE);
        RV_CASE(CKR_KEY_TYPE_INCONSISTENT);
        RV_CASE(CKR_KEY_NOT_NEEDED);
        RV_CASE(CKR_KEY_CHANGED);
        RV_CASE(CKR_KEY_NEEDED);
        RV_CASE(CKR_KEY_INDIGESTIBLE);
        RV_CASE(CKR_KEY_FUNCTION_NOT_PERMITTED);
        RV_CASE(CKR_KEY_NOT_WRAPPABLE);
        RV_CASE(CKR_KEY_UNEXTRACTABLE);
        RV_CASE(CKR_MECHANISM_INVALID);
        RV_CASE(CKR_MECHANISM_PARAM_INVALID);
        RV_CASE(CKR_OBJECT_HANDLE_INVALID);
        RV_CASE(CKR_OPERATION_ACTIVE);
        RV_CASE(CKR_OPERATION_NOT_INITIALIZED);
        RV_CASE(CKR_PIN_INCORRECT);
        RV_CASE(CKR_PIN_INVALID);
        RV_CASE(CKR_PIN_LEN_RANGE);
        RV_CASE(CKR_PIN_EXPIRED);
        RV_CASE(CKR_PIN_LOCKED);
        RV_CASE(CKR_SESSION_CLOSED);
        RV_CASE(CKR_SESSION_COUNT);
        RV_CASE(CKR_SESSION_HANDLE_INVALID);
        RV_CASE(CKR_SESSION_PARALLEL_NOT_SUPPORTED);
        RV_CASE(CKR_SESSION_READ_ONLY);
        RV_CASE(CKR_SESSION_EXISTS);
        RV_CASE(CKR_SESSION_READ_ONLY_EXISTS);
        RV_CASE(CKR_SESSION_READ_WRITE_SO_EXISTS);
        RV_CASE(CKR_SIGNATURE_INVALID);
        RV_CASE(CKR_SIGNATURE_LEN_RANGE);
        RV_CASE(CKR_TEMPLATE_INCOMPLETE);
        RV_CASE(CKR_TEMPLATE_INCONSISTENT);
        RV_CASE(CKR_TOKEN_NOT_PRESENT);
        RV_CASE(CKR_TOKEN_NOT_RECOGNIZED);
        RV_CASE(CKR_TOKEN_WRITE_PROTECTED);
        RV_CASE(CKR_UNWRAPPING_KEY_HANDLE_INVALID);
        RV_CASE(CKR_UNWRAPPING_KEY_SIZE_RANGE);
        RV_CASE(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT);
        RV_CASE(CKR_USER_ALREADY_LOGGED_IN);
        RV_CASE(CKR_USER_NOT_LOGGED_IN);
        RV_CASE(CKR_USER_PIN_NOT_INITIALIZED);
        RV_CASE(CKR_USER_TYPE_INVALID);
        RV_CASE(CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
        RV_CASE(CKR_USER_TOO_MANY_TYPES);
        RV_CASE(CKR_WRAPPED_KEY_INVALID);
        RV_CASE(CKR_WRAPPED_KEY_LEN_RANGE);
        RV_CASE(CKR_WRAPPING_KEY_HANDLE_INVALID);
        RV_CASE(CKR_WRAPPING_KEY_SIZE_RANGE);
        RV_CASE(CKR_WRAPPING_KEY_TYPE_INCONSISTENT);
        RV_CASE(CKR_RANDOM_SEED_NOT_SUPPORTED);
        RV_CASE(CKR_RANDOM_NO_RNG);
        RV_CASE(CKR_DOMAIN_PARAMS_INVALID);
        RV_CASE(CKR_BUFFER_TOO_SMALL);
        RV_CASE(CKR_SAVED_STATE_INVALID);
        RV_CASE(CKR_INFORMATION_SENSITIVE);
        RV_CASE(CKR_STATE_UNSAVEABLE);
        RV_CASE(CKR_CRYPTOKI_NOT_INITIALIZED);
        RV_CASE(CKR_CRYPTOKI_ALREADY_INITIALIZED);
        RV_CASE(CKR_MUTEX_BAD);
        RV_CASE(CKR_MUTEX_NOT_LOCKED);
        RV_CASE(CKR_VENDOR_DEFINED);
        default:
            return "CKR_UNKNOWN";
    }
}
