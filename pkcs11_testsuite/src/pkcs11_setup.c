#include "pkcs11_loader.h"
#include "pkcs11_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("  -l <lib>    PKCS#11 library (default: /usr/lib/softhsm/libsofthsm2.so)\n");
    printf("  -s <slot>   Slot to initialize\n");
    printf("  -L <label>  Token label (default: TestToken)\n");
    printf("  -p <pin>    User PIN (default: 1234)\n");
    printf("  -P <sopin>  SO PIN (default: 1234)\n");
    printf("  -i          Initialize token on slot\n");
    printf("  -I          Print info and exit\n");
    printf("  -h          Help\n");
}

int main(int argc, char *argv[])
{
    const char *lib_path  = "/usr/lib/softhsm/libsofthsm2.so";
    const char *label     = "TestToken";
    const char *user_pin  = "1234";
    const char *so_pin    = "1234";
    CK_SLOT_ID  slot      = 0;
    int         do_init   = 0;
    int         do_info   = 0;
    int         opt;

    while ((opt = getopt(argc, argv, "l:s:L:p:P:iIh")) != -1) {
        switch (opt) {
            case 'l': lib_path = optarg; break;
            case 's': slot     = (CK_SLOT_ID)atoi(optarg); break;
            case 'L': label    = optarg; break;
            case 'p': user_pin = optarg; break;
            case 'P': so_pin   = optarg; break;
            case 'i': do_init  = 1; break;
            case 'I': do_info  = 1; break;
            case 'h': usage(argv[0]); return 0;
            default:  usage(argv[0]); return 1;
        }
    }

    PKCS11_Module mod;
    if (pkcs11_load(&mod, lib_path) != 0) {
        log_error("Failed to load %s", lib_path);
        return 2;
    }

    CK_RV rv = mod.fn->C_Initialize(NULL_PTR);
    if (rv != CKR_OK) { log_error("C_Initialize: %s", pkcs11_rv_str(rv)); return 3; }

    if (do_info) {
        CK_INFO info;
        mod.fn->C_GetInfo(&info);
        printf("Cryptoki version: %d.%02d\n", info.cryptokiVersion.major, info.cryptokiVersion.minor);
        printf("Manufacturer: %.32s\n", info.manufacturerID);
        printf("Library: %.32s v%d.%02d\n", info.libraryDescription,
               info.libraryVersion.major, info.libraryVersion.minor);

        CK_ULONG count = 0;
        mod.fn->C_GetSlotList(CK_FALSE, NULL_PTR, &count);
        CK_SLOT_ID *slots = malloc(count * sizeof(CK_SLOT_ID));
        mod.fn->C_GetSlotList(CK_FALSE, slots, &count);

        printf("\nSlots (%lu):\n", count);
        for (CK_ULONG i = 0; i < count; i++) {
            CK_SLOT_INFO si;
            CK_TOKEN_INFO ti;
            mod.fn->C_GetSlotInfo(slots[i], &si);
            printf("  Slot %lu: %.64s\n", slots[i], si.slotDescription);
            if (si.flags & CKF_TOKEN_PRESENT) {
                mod.fn->C_GetTokenInfo(slots[i], &ti);
                printf("    Token: %.32s (init=%s)\n", ti.label,
                       (ti.flags & CKF_TOKEN_INITIALIZED) ? "yes" : "no");
            }
        }
        free(slots);
    }

    if (do_init) {
        log_info("Initializing token on slot %lu...", slot);
        if (pkcs11_init_token(mod.fn, slot, label, so_pin, user_pin) == 0)
            log_ok("Token initialized: label='%s'", label);
        else
            log_error("Token initialization failed");
    }

    mod.fn->C_Finalize(NULL_PTR);
    pkcs11_unload(&mod);
    return 0;
}
