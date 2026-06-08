#include "pkcs11_loader.h"
#include "pkcs11_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ============================================================
 * Interactive PKCS#11 application — demonstration & manual testing
 * ============================================================ */

static PKCS11_Module  g_mod;
static CK_SESSION_HANDLE g_sess = CK_INVALID_HANDLE;
static CK_SLOT_ID     g_slot = 0;

/* ---- Helpers ---- */
static void print_slots(void)
{
    CK_ULONG count = 0;
    g_mod.fn->C_GetSlotList(CK_FALSE, NULL_PTR, &count);
    if (count == 0) { printf("No slots found.\n"); return; }

    CK_SLOT_ID *slots = malloc(count * sizeof(CK_SLOT_ID));
    g_mod.fn->C_GetSlotList(CK_FALSE, slots, &count);

    for (CK_ULONG i = 0; i < count; i++) {
        CK_SLOT_INFO si;
        g_mod.fn->C_GetSlotInfo(slots[i], &si);
        printf("  Slot %-3lu  %s  %.64s\n", slots[i],
               (si.flags & CKF_TOKEN_PRESENT) ? "[token]" : "[empty]",
               si.slotDescription);
        if (si.flags & CKF_TOKEN_PRESENT) {
            CK_TOKEN_INFO ti;
            g_mod.fn->C_GetTokenInfo(slots[i], &ti);
            printf("           Token: %.32s (init=%s, login_req=%s)\n",
                   ti.label,
                   (ti.flags & CKF_TOKEN_INITIALIZED) ? "yes" : "no",
                   (ti.flags & CKF_LOGIN_REQUIRED) ? "yes" : "no");
        }
    }
    free(slots);
}

static void print_objects(void)
{
    if (g_sess == CK_INVALID_HANDLE) { printf("No active session.\n"); return; }

    CK_RV rv = g_mod.fn->C_FindObjectsInit(g_sess, NULL_PTR, 0);
    if (rv != CKR_OK) { printf("FindObjectsInit: %s\n", pkcs11_rv_str(rv)); return; }

    CK_OBJECT_HANDLE buf[256];
    CK_ULONG found = 0;
    g_mod.fn->C_FindObjects(g_sess, buf, 256, &found);
    g_mod.fn->C_FindObjectsFinal(g_sess);

    printf("  Found %lu object(s):\n", found);
    for (CK_ULONG i = 0; i < found; i++) {
        CK_OBJECT_CLASS cls = 0;
        char label[64] = {0};
        CK_ATTRIBUTE ga[] = {
            { CKA_CLASS, &cls,  sizeof(cls)   },
            { CKA_LABEL, label, sizeof(label)-1 },
        };
        g_mod.fn->C_GetAttributeValue(g_sess, buf[i], ga, 2);

        const char *cls_str;
        switch (cls) {
            case CKO_DATA:        cls_str = "DATA";         break;
            case CKO_CERTIFICATE: cls_str = "CERTIFICATE";  break;
            case CKO_PUBLIC_KEY:  cls_str = "PUBLIC_KEY";   break;
            case CKO_PRIVATE_KEY: cls_str = "PRIVATE_KEY";  break;
            case CKO_SECRET_KEY:  cls_str = "SECRET_KEY";   break;
            default:              cls_str = "UNKNOWN";      break;
        }
        printf("    [%lu] Handle=%-6lu  Class=%-12s  Label=%s\n",
               i+1, buf[i], cls_str, label[0] ? label : "(no label)");
    }
}

static void demo_generate_aes(void)
{
    if (g_sess == CK_INVALID_HANDLE) { printf("Open a session first.\n"); return; }

    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG klen = 32;
    char label[] = "DemoAES256";
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &f,       sizeof(f)              },
        { CKA_ENCRYPT,   &t,       sizeof(t)              },
        { CKA_DECRYPT,   &t,       sizeof(t)              },
        { CKA_VALUE_LEN, &klen,    sizeof(klen)           },
        { CKA_LABEL,     label,    (CK_ULONG)strlen(label)},
    };
    CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key;
    CK_RV rv = g_mod.fn->C_GenerateKey(g_sess, &m, tmpl, 5, &key);
    if (rv == CKR_OK)
        printf("  AES-256 key generated: handle=%lu\n", key);
    else
        printf("  GenerateKey failed: %s\n", pkcs11_rv_str(rv));
}

static void demo_aes_encrypt_decrypt(void)
{
    if (g_sess == CK_INVALID_HANDLE) { printf("Open a session first.\n"); return; }

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
    g_mod.fn->C_GenerateKey(g_sess, &gen_m, tmpl, 4, &key);

    unsigned char iv[16]    = { 0xDE,0xAD,0xBE,0xEF,0x00,0x01,0x02,0x03,
                                 0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b };
    const char *plain_str   = "Hello, PKCS#11!";
    unsigned char cipher[64]= {0};
    unsigned char dec[48]   = {0};
    CK_ULONG clen = sizeof(cipher), dlen = sizeof(dec);

    CK_MECHANISM m = { CKM_AES_CBC_PAD, iv, sizeof(iv) };

    g_mod.fn->C_EncryptInit(g_sess, &m, key);
    g_mod.fn->C_Encrypt(g_sess, (CK_BYTE_PTR)plain_str, (CK_ULONG)strlen(plain_str), cipher, &clen);

    printf("  Plaintext:  %s\n", plain_str);
    hex_print("Ciphertext", cipher, clen);

    g_mod.fn->C_DecryptInit(g_sess, &m, key);
    g_mod.fn->C_Decrypt(g_sess, cipher, clen, dec, &dlen);
    dec[dlen] = '\0';
    printf("  Decrypted:  %s\n", (char*)dec);

    g_mod.fn->C_DestroyObject(g_sess, key);
}

static void demo_rsa_sign_verify(void)
{
    if (g_sess == CK_INVALID_HANDLE) { printf("Open a session first.\n"); return; }

    printf("  Generating RSA-2048 key pair...\n");
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_ULONG mod_bits = 2048;
    unsigned char exp[] = { 0x01, 0x00, 0x01 };
    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_TOKEN,           &f,       sizeof(f)        },
        { CKA_ENCRYPT,         &t,       sizeof(t)        },
        { CKA_VERIFY,          &t,       sizeof(t)        },
        { CKA_MODULUS_BITS,    &mod_bits,sizeof(mod_bits) },
        { CKA_PUBLIC_EXPONENT, exp,      sizeof(exp)      },
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        { CKA_TOKEN,   &f, sizeof(f) },
        { CKA_DECRYPT, &t, sizeof(t) },
        { CKA_SIGN,    &t, sizeof(t) },
        { CKA_SENSITIVE,&t,sizeof(t) },
        { CKA_EXTRACTABLE,&f,sizeof(f)},
    };
    CK_MECHANISM gen_m = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE pub, priv;
    CK_RV rv = g_mod.fn->C_GenerateKeyPair(g_sess, &gen_m, pub_tmpl, 5, priv_tmpl, 5, &pub, &priv);
    if (rv != CKR_OK) { printf("  GenerateKeyPair: %s\n", pkcs11_rv_str(rv)); return; }
    printf("  Keys: pub=%lu priv=%lu\n", pub, priv);

    const char *msg = "Message to sign";
    unsigned char sig[512]; CK_ULONG slen = sizeof(sig);

    CK_MECHANISM m = { CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };
    g_mod.fn->C_SignInit(g_sess, &m, priv);
    rv = g_mod.fn->C_Sign(g_sess, (CK_BYTE_PTR)msg, (CK_ULONG)strlen(msg), sig, &slen);
    if (rv != CKR_OK) { printf("  Sign: %s\n", pkcs11_rv_str(rv)); return; }
    hex_print("Signature", sig, slen);

    g_mod.fn->C_VerifyInit(g_sess, &m, pub);
    rv = g_mod.fn->C_Verify(g_sess, (CK_BYTE_PTR)msg, (CK_ULONG)strlen(msg), sig, slen);
    printf("  Verify: %s\n", (rv == CKR_OK) ? "OK - signature valid" : pkcs11_rv_str(rv));

    g_mod.fn->C_DestroyObject(g_sess, pub);
    g_mod.fn->C_DestroyObject(g_sess, priv);
}

static void demo_sha256(void)
{
    if (g_sess == CK_INVALID_HANDLE) { printf("Open a session first.\n"); return; }

    const char *msg = "The quick brown fox jumps over the lazy dog";
    unsigned char digest[32]; CK_ULONG dlen = sizeof(digest);
    CK_MECHANISM m = { CKM_SHA256, NULL_PTR, 0 };

    g_mod.fn->C_DigestInit(g_sess, &m);
    CK_RV rv = g_mod.fn->C_Digest(g_sess, (CK_BYTE_PTR)msg, (CK_ULONG)strlen(msg), digest, &dlen);
    if (rv == CKR_OK)
        hex_print("SHA-256", digest, dlen);
    else
        printf("  Digest: %s\n", pkcs11_rv_str(rv));
}

static void demo_random(void)
{
    if (g_sess == CK_INVALID_HANDLE) { printf("Open a session first.\n"); return; }
    unsigned char buf[32];
    g_mod.fn->C_GenerateRandom(g_sess, buf, sizeof(buf));
    hex_print("Random (32B)", buf, sizeof(buf));
}

static void print_menu(void)
{
    printf("\n");
    printf("╔══════════════════════════════════════════╗\n");
    printf("║         PKCS#11 Interactive App          ║\n");
    printf("╠══════════════════════════════════════════╣\n");
    printf("║  1. List slots & tokens                  ║\n");
    printf("║  2. Open session on slot N               ║\n");
    printf("║  3. Login (user PIN)                     ║\n");
    printf("║  4. List objects                         ║\n");
    printf("║  5. Demo: Generate AES-256 key           ║\n");
    printf("║  6. Demo: AES-CBC encrypt/decrypt        ║\n");
    printf("║  7. Demo: RSA-2048 sign/verify           ║\n");
    printf("║  8. Demo: SHA-256 digest                 ║\n");
    printf("║  9. Demo: Generate random                ║\n");
    printf("║  0. Exit                                 ║\n");
    printf("╚══════════════════════════════════════════╝\n");
    printf("Choice: ");
}

static void usage(const char *prog)
{
    printf("Usage: %s [-l <lib>] [-s <slot>] [-p <pin>]\n", prog);
}

int main(int argc, char *argv[])
{
    const char *lib_path = "/usr/lib/softhsm/libsofthsm2.so";
    const char *user_pin = "1234";
    int opt;

    while ((opt = getopt(argc, argv, "l:s:p:h")) != -1) {
        switch (opt) {
            case 'l': lib_path = optarg; break;
            case 's': g_slot   = (CK_SLOT_ID)atoi(optarg); break;
            case 'p': user_pin = optarg; break;
            case 'h': usage(argv[0]); return 0;
        }
    }

    if (pkcs11_load(&g_mod, lib_path) != 0) {
        log_error("Failed to load library: %s", lib_path);
        return 1;
    }

    CK_RV rv = g_mod.fn->C_Initialize(NULL_PTR);
    if (rv != CKR_OK) { log_error("C_Initialize: %s", pkcs11_rv_str(rv)); return 1; }
    log_ok("Library loaded: %s", lib_path);

    char input[64];
    int running = 1;
    while (running) {
        print_menu();
        if (!fgets(input, sizeof(input), stdin)) break;
        int choice = atoi(input);

        switch (choice) {
            case 1:
                print_slots();
                break;
            case 2: {
                printf("Slot number: ");
                fgets(input, sizeof(input), stdin);
                g_slot = (CK_SLOT_ID)atoi(input);
                if (g_sess != CK_INVALID_HANDLE) {
                    g_mod.fn->C_CloseSession(g_sess);
                    g_sess = CK_INVALID_HANDLE;
                }
                rv = g_mod.fn->C_OpenSession(g_slot,
                                              CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                              NULL_PTR, NULL_PTR, &g_sess);
                if (rv == CKR_OK)
                    printf("  Session opened: handle=%lu on slot=%lu\n", g_sess, g_slot);
                else
                    printf("  OpenSession: %s\n", pkcs11_rv_str(rv));
                break;
            }
            case 3: {
                if (g_sess == CK_INVALID_HANDLE) { printf("Open a session first.\n"); break; }
                printf("PIN (default: %s): ", user_pin);
                fgets(input, sizeof(input), stdin);
                input[strcspn(input, "\n")] = '\0';
                const char *pin = (input[0] != '\0') ? input : user_pin;
                rv = g_mod.fn->C_Login(g_sess, CKU_USER,
                                        (CK_UTF8CHAR_PTR)pin, (CK_ULONG)strlen(pin));
                printf("  Login: %s\n", (rv == CKR_OK) ? "success" : pkcs11_rv_str(rv));
                break;
            }
            case 4: print_objects(); break;
            case 5: demo_generate_aes(); break;
            case 6: demo_aes_encrypt_decrypt(); break;
            case 7: demo_rsa_sign_verify(); break;
            case 8: demo_sha256(); break;
            case 9: demo_random(); break;
            case 0: running = 0; break;
            default: printf("Unknown choice.\n");
        }
    }

    if (g_sess != CK_INVALID_HANDLE) g_mod.fn->C_CloseSession(g_sess);
    pkcs11_unload(&g_mod);
    return 0;
}
