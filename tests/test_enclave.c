/*
 * test_enclave.c — Unity port of chain/tests/priscilla/enclave.test.ts.
 *
 * PrivateEnclave (crypto-shredding, paper §4.2): seal()/open() AES-256-GCM
 * round-trip, ciphertext secrecy, crypto-shred -> permanently undecryptable
 * (BNS_ESHREDDED), deterministic identity-bound shred marker, tamper detection
 * (BNS_EINTEGRITY), GCM-AAD identity binding (independent of key separation),
 * and per-identity isolation of shredding.
 *
 * Build+run (from chain_c/): see tests/README or the orchestration command. The
 * build uses -Iinclude -Ithird_party/unity -Itests/helpers, links unity.c, all
 * tests/helpers .c, and -lbonsai_chain (+ secp256k1/crypto/curl/m/pthread).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "common/error.h"
#include "common/bytes.h"
#include "privacy/key_vault.h"
#include "privacy/enclave.h"

#define KL BONSAI_KEY_VAULT_KEY_LEN

/* injected clock: TS uses now=()=>1000 */
static int64_t fixed_clock(void *user) { (void)user; return 1000; }

/* per-test fresh InMemoryKeyVault + enclave */
static key_vault_t        g_vault;
static private_enclave_t *g_enc;

void setUp(void)
{
    memset(&g_vault, 0, sizeof g_vault);
    TEST_ASSERT_EQUAL_INT(BNS_OK, in_memory_key_vault_new(&g_vault));
    g_enc = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_new(&g_vault, fixed_clock, NULL, &g_enc));
}
void tearDown(void)
{
    private_enclave_free(g_enc);
    in_memory_key_vault_free(&g_vault);
}

static bool open_equals(const sealed_record_t *rec, const char *expect)
{
    byte_buf_t out; byte_buf_init(&out);
    int rc = private_enclave_open(g_enc, rec, &out);
    bool ok = (rc == BNS_OK) && out.len == strlen(expect) &&
              memcmp(out.data, expect, out.len) == 0;
    byte_buf_free(&out);
    return ok;
}

/* ---- seals and opens a payload round-trip ---------------------------------- */
static void test_seal_open_roundtrip(void)
{
    const char *pt = "the agent called the deploy API";
    sealed_record_t rec; memset(&rec, 0, sizeof rec);
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        private_enclave_seal(g_enc, "id-1", (const uint8_t *)pt, strlen(pt), &rec));

    /* sealed.identityId == 'id-1' */
    TEST_ASSERT_NOT_NULL(rec.identity_id);
    TEST_ASSERT_EQUAL_STRING("id-1", rec.identity_id);
    /* ciphertext is a non-empty hex string */
    TEST_ASSERT_NOT_NULL(rec.ciphertext);
    TEST_ASSERT_TRUE(strlen(rec.ciphertext) > 0);
    /* sealedAt comes from injected clock */
    TEST_ASSERT_EQUAL_INT64(1000, rec.sealed_at);

    /* open round-trips to the original plaintext */
    TEST_ASSERT_TRUE(open_equals(&rec, pt));
    sealed_record_free(&rec);
}

/* ---- reveals nothing in the sealed record without the key ------------------ */
static void test_ciphertext_not_plaintext(void)
{
    const char *pt = "secret payload";
    sealed_record_t rec; memset(&rec, 0, sizeof rec);
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        private_enclave_seal(g_enc, "id-1", (const uint8_t *)pt, strlen(pt), &rec));

    /* hex of the plaintext must not appear in the ciphertext hex */
    static const char plain_hex[] = "736563726574207061796c6f6164"; /* "secret payload" */
    TEST_ASSERT_NULL(strstr(rec.ciphertext, plain_hex));
    sealed_record_free(&rec);
}

/* ---- crypto-shred makes prior records permanently undecryptable ------------ */
static void test_shred_makes_undecryptable(void)
{
    const char *pt = "erase me";
    sealed_record_t rec; memset(&rec, 0, sizeof rec);
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        private_enclave_seal(g_enc, "id-1", (const uint8_t *)pt, strlen(pt), &rec));

    bool shredded = false; char *marker = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_shred(g_enc, "id-1", &shredded, &marker));
    TEST_ASSERT_TRUE(shredded);

    /* marker matches /^[0-9a-f]{64}$/ (SHA-256 hex) */
    TEST_ASSERT_NOT_NULL(marker);
    TEST_ASSERT_EQUAL_INT(64, (int)strlen(marker));
    for (const char *p = marker; *p; p++)
        TEST_ASSERT_TRUE((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'));
    free(marker);

    /* open() now throws ShreddedError -> BNS_ESHREDDED */
    byte_buf_t out; byte_buf_init(&out);
    TEST_ASSERT_EQUAL_INT(BNS_ESHREDDED, private_enclave_open(g_enc, &rec, &out));
    byte_buf_free(&out);
    sealed_record_free(&rec);
}

/* ---- shred marker is deterministic and identity-bound, payload-independent -- */
static void test_shred_marker_deterministic_identity_bound(void)
{
    char *a = NULL, *b = NULL, *c = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_shred_marker("id-1", &a));
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_shred_marker("id-1", &b));
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_shred_marker("id-2", &c));
    TEST_ASSERT_EQUAL_STRING(a, b);            /* deterministic */
    TEST_ASSERT_FALSE(strcmp(a, c) == 0);      /* identity-bound */
    free(a); free(b); free(c);
}

/* ---- distinguishes lawful erasure from tampering -> IntegrityError --------- */
static void test_tamper_is_integrity_error(void)
{
    const char *pt = "payload";
    sealed_record_t rec; memset(&rec, 0, sizeof rec);
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        private_enclave_seal(g_enc, "id-1", (const uint8_t *)pt, strlen(pt), &rec));

    /* flip the first hex nibble of the ciphertext while the key still exists */
    TEST_ASSERT_TRUE(strlen(rec.ciphertext) > 0);
    rec.ciphertext[0] = (rec.ciphertext[0] == '0') ? '1' : '0';

    byte_buf_t out; byte_buf_init(&out);
    TEST_ASSERT_EQUAL_INT(BNS_EINTEGRITY, private_enclave_open(g_enc, &rec, &out));
    byte_buf_free(&out);
    sealed_record_free(&rec);
}

/* ---- SharedKeyVault: hands the SAME key to every live identity --------------
 * Isolates GCM-AAD identity binding from key separation. */
typedef struct { uint8_t key[KL]; bool a_live, b_live, key_set; } shared_vault_t;

static bool sv_live(const shared_vault_t *s, const char *id)
{
    if (strcmp(id, "id-A") == 0) return s->a_live;
    if (strcmp(id, "id-B") == 0) return s->b_live;
    return false;
}
static void sv_mark(shared_vault_t *s, const char *id, bool live)
{
    if (strcmp(id, "id-A") == 0) s->a_live = live;
    else if (strcmp(id, "id-B") == 0) s->b_live = live;
}
static int sv_ensure(void *ctx, const char *id, uint8_t out[KL])
{
    shared_vault_t *s = ctx;
    if (!s->key_set) { for (int i = 0; i < KL; i++) s->key[i] = (uint8_t)(0xA0 ^ i); s->key_set = true; }
    sv_mark(s, id, true);
    memcpy(out, s->key, KL);
    return BNS_OK;
}
static int sv_get(void *ctx, const char *id, uint8_t out[KL], bool *found)
{
    shared_vault_t *s = ctx;
    if (sv_live(s, id)) { memcpy(out, s->key, KL); *found = true; }
    else *found = false;
    return BNS_OK;
}
static int sv_shred(void *ctx, const char *id, bool *had)
{
    shared_vault_t *s = ctx;
    *had = sv_live(s, id);
    sv_mark(s, id, false);
    return BNS_OK;
}
static bool sv_has(void *ctx, const char *id) { return sv_live(ctx, id); }

/* binds identityId via the GCM AAD, independent of key separation.
 * Two identities deliberately share one key; the only thing tying a record to
 * its identity is the AAD. Re-labelling id-A's record as id-B fails auth. */
static void test_aad_identity_binding(void)
{
    shared_vault_t sv; memset(&sv, 0, sizeof sv);
    key_vault_t vt; memset(&vt, 0, sizeof vt);
    vt.ctx = &sv; vt.ensure_key = sv_ensure; vt.get_key = sv_get; vt.shred = sv_shred; vt.has = sv_has;

    private_enclave_t *enc = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_new(&vt, fixed_clock, NULL, &enc));

    const char *pt = "cross-identity payload";
    sealed_record_t rec; memset(&rec, 0, sizeof rec);
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        private_enclave_seal(enc, "id-A", (const uint8_t *)pt, strlen(pt), &rec));

    /* register id-B so it has the (shared) live key — else open() bails with
     * ShreddedError before reaching the AAD/auth check */
    uint8_t tmp[KL]; TEST_ASSERT_EQUAL_INT(BNS_OK, sv_ensure(&sv, "id-B", tmp));

    /* sanity: with the SAME key, decrypting the unmodified record works */
    byte_buf_t ok; byte_buf_init(&ok);
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_open(enc, &rec, &ok));
    TEST_ASSERT_EQUAL_INT((int)strlen(pt), (int)ok.len);
    TEST_ASSERT_EQUAL_MEMORY(pt, ok.data, ok.len);
    byte_buf_free(&ok);

    /* re-label to a different (key-sharing) identity -> AAD mismatch -> reject */
    char *saved = rec.identity_id;
    rec.identity_id = strdup("id-B");
    TEST_ASSERT_NOT_NULL(rec.identity_id);
    byte_buf_t bad; byte_buf_init(&bad);
    TEST_ASSERT_EQUAL_INT(BNS_EINTEGRITY, private_enclave_open(enc, &rec, &bad));
    byte_buf_free(&bad);
    free(rec.identity_id);
    rec.identity_id = saved; /* restore for sealed_record_free */

    sealed_record_free(&rec);
    private_enclave_free(enc);
}

/* ---- isolates identities: shredding one does not affect another ------------ */
static void test_identity_isolation(void)
{
    sealed_record_t s1, s2; memset(&s1, 0, sizeof s1); memset(&s2, 0, sizeof s2);
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        private_enclave_seal(g_enc, "id-1", (const uint8_t *)"one", 3, &s1));
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        private_enclave_seal(g_enc, "id-2", (const uint8_t *)"two", 3, &s2));

    bool shredded = false; char *marker = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_shred(g_enc, "id-1", &shredded, &marker));
    TEST_ASSERT_TRUE(shredded);
    free(marker);

    /* id-1 now undecryptable, id-2 still opens */
    byte_buf_t o1; byte_buf_init(&o1);
    TEST_ASSERT_EQUAL_INT(BNS_ESHREDDED, private_enclave_open(g_enc, &s1, &o1));
    byte_buf_free(&o1);

    TEST_ASSERT_TRUE(open_equals(&s2, "two"));

    sealed_record_free(&s1);
    sealed_record_free(&s2);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_seal_open_roundtrip);
    RUN_TEST(test_ciphertext_not_plaintext);
    RUN_TEST(test_shred_makes_undecryptable);
    RUN_TEST(test_shred_marker_deterministic_identity_bound);
    RUN_TEST(test_tamper_is_integrity_error);
    RUN_TEST(test_aad_identity_binding);
    RUN_TEST(test_identity_isolation);
    return UNITY_END();
}
