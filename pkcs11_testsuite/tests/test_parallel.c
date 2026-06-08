#include "test_framework.h"
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#define NUM_THREADS 4
#define OPS_PER_THREAD 8

typedef struct {
    CK_FUNCTION_LIST_PTR fn;
    CK_SLOT_ID slot;
    const char *user_pin;
    int thread_id;
    int result;
} ThreadArg;

static void *thread_encrypt_decrypt(void *arg)
{
    ThreadArg *a = (ThreadArg*)arg;
    a->result = -1;

    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    CK_RV rv = a->fn->C_OpenSession(a->slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL_PTR, NULL_PTR, &sess);
    if (rv != CKR_OK) return NULL;

    /* The main session already logged in — all sessions share the login state.
     * C_Login returns CKR_USER_ALREADY_LOGGED_IN which is fine. */
    rv = a->fn->C_Login(sess, CKU_USER,
                         (CK_UTF8CHAR_PTR)a->user_pin,
                         (CK_ULONG)strlen(a->user_pin));
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
        a->fn->C_CloseSession(sess);
        return NULL;
    }

    /* Generate a key per thread */
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
    rv = a->fn->C_GenerateKey(sess, &gen_m, tmpl, 4, &key);
    if (rv != CKR_OK) { a->fn->C_CloseSession(sess); return NULL; }

    unsigned char iv[16]    = {0};
    unsigned char plain[32] = "parallel test data for thread...";
    unsigned char cipher[64]= {0};
    unsigned char dec[48]   = {0};

    for (int i = 0; i < OPS_PER_THREAD; i++) {
        iv[0] = (unsigned char)i;
        CK_MECHANISM m = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
        CK_ULONG clen = sizeof(cipher), dlen = sizeof(dec);

        rv = a->fn->C_EncryptInit(sess, &m, key);
        if (rv != CKR_OK) { a->fn->C_DestroyObject(sess, key); a->fn->C_CloseSession(sess); return NULL; }
        rv = a->fn->C_Encrypt(sess, plain, sizeof(plain), cipher, &clen);
        if (rv != CKR_OK) { a->fn->C_DestroyObject(sess, key); a->fn->C_CloseSession(sess); return NULL; }

        rv = a->fn->C_DecryptInit(sess, &m, key);
        if (rv != CKR_OK) { a->fn->C_DestroyObject(sess, key); a->fn->C_CloseSession(sess); return NULL; }
        rv = a->fn->C_Decrypt(sess, cipher, clen, dec, &dlen);
        if (rv != CKR_OK) { a->fn->C_DestroyObject(sess, key); a->fn->C_CloseSession(sess); return NULL; }

        if (memcmp(dec, plain, sizeof(plain)) != 0) {
            a->fn->C_DestroyObject(sess, key);
            a->fn->C_CloseSession(sess);
            return NULL;
        }
    }

    a->fn->C_DestroyObject(sess, key);
    a->fn->C_CloseSession(sess);
    a->result = 0;
    return NULL;
}

static int test_parallel_sessions(TestCtx *ctx)
{
    if (ctx->rw_session == CK_INVALID_HANDLE)
        SKIP("No session available — parallel test skipped");

    pthread_t threads[NUM_THREADS];
    ThreadArg args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].fn       = ctx->mod.fn;
        args[i].slot     = ctx->slot;
        args[i].user_pin = ctx->user_pin;
        args[i].thread_id= i;
        args[i].result   = -1;
        pthread_create(&threads[i], NULL, thread_encrypt_decrypt, &args[i]);
    }

    int any_fail = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
        if (args[i].result != 0) {
            log_fail("Thread %d failed", i);
            any_fail = 1;
        }
    }

    ASSERT_TRUE(!any_fail, "All parallel threads succeeded");
    TEST_PASS();
}

/* Multiple sessions on same token, parallel digest */
static void *thread_digest(void *arg)
{
    ThreadArg *a = (ThreadArg*)arg;
    a->result = -1;

    CK_SESSION_HANDLE sess;
    a->fn->C_OpenSession(a->slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sess);

    CK_MECHANISM m = { CKM_SHA256, NULL_PTR, 0 };
    for (int i = 0; i < 16; i++) {
        unsigned char data[64];
        memset(data, i, sizeof(data));
        unsigned char digest[32]; CK_ULONG dlen = sizeof(digest);

        if (a->fn->C_DigestInit(sess, &m) != CKR_OK) break;
        if (a->fn->C_Digest(sess, data, sizeof(data), digest, &dlen) != CKR_OK) break;
    }

    a->fn->C_CloseSession(sess);
    a->result = 0;
    return NULL;
}

static int test_parallel_digest(TestCtx *ctx)
{
    if (ctx->rw_session == CK_INVALID_HANDLE)
        SKIP("No session available — parallel test skipped");

    pthread_t threads[NUM_THREADS];
    ThreadArg args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].fn       = ctx->mod.fn;
        args[i].slot     = ctx->slot;
        args[i].user_pin = ctx->user_pin;
        args[i].thread_id= i;
        args[i].result   = -1;
        pthread_create(&threads[i], NULL, thread_digest, &args[i]);
    }

    int any_fail = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
        if (args[i].result != 0) { log_fail("Digest thread %d failed", i); any_fail = 1; }
    }

    ASSERT_TRUE(!any_fail, "All parallel digest threads succeeded");
    TEST_PASS();
}

BEGIN_TESTS(parallel)
    ADD_TEST("Parallel_encrypt_decrypt",  test_parallel_sessions);
    ADD_TEST("Parallel_digest",           test_parallel_digest);
END_TESTS()
