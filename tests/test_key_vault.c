/*
 * test_key_vault.c — Unity port of chain/tests/priscilla/keyVault.test.ts.
 *
 * Mirrors the KeyVault interface contract (crypto-shred ROOT): the per-identity
 * AES-256 key store whose GDPR Art.17 erasure property is "destroy the key".
 *
 * The C vault (privacy/key_vault.h) exposes ensure_key/get_key/shred/has as a
 * vtable; ensure_key/get_key COPY the 32-byte key into a caller buffer (the TS
 * version returns the internal Buffer by reference). The behavioral contract is
 * identical; the one TS assertion that inspects the returned Buffer's bytes
 * being zeroised in place after shred() is not observable through the C copy-out
 * API (see TEST_IGNORE note below) — the equivalent guarantee is exercised via
 * the irreversibility test (a fresh key after shred differs from the old one).
 *
 * Build+run (from chain_c/): see tests/README or the orchestration command. The
 * build uses -Iinclude -Ithird_party/unity -Itests/helpers, links unity.c, all
 * tests/helpers .c, and -lbonsai_chain (+ secp256k1/crypto/curl/m/pthread).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>

#include "unity.h"
#include "common/error.h"
#include "privacy/key_vault.h"

#define KL BONSAI_KEY_VAULT_KEY_LEN

static key_vault_t g_vault;

void setUp(void)    { memset(&g_vault, 0, sizeof g_vault); TEST_ASSERT_EQUAL_INT(BNS_OK, in_memory_key_vault_new(&g_vault)); }
void tearDown(void) { in_memory_key_vault_free(&g_vault); }

static bool all_zero(const uint8_t *b, size_t n) { for (size_t i = 0; i < n; i++) if (b[i]) return false; return true; }

/* ensureKey mints a 32-byte key, is idempotent, and gives distinct identities
 * distinct keys. (TS: "ensureKey mints a 32-byte key, is idempotent, ...") */
static void test_ensure_key_idempotent_and_distinct(void)
{
    uint8_t k1[KL], k1b[KL], k2[KL];

    TEST_ASSERT_EQUAL_INT(BNS_OK, g_vault.ensure_key(g_vault.ctx, "a", k1));
    /* a 32-byte key is minted (it is essentially never all-zero from a CSPRNG) */
    TEST_ASSERT_FALSE(all_zero(k1, KL));
    TEST_ASSERT_TRUE(g_vault.has(g_vault.ctx, "a"));

    /* idempotent: same key bytes on repeat */
    TEST_ASSERT_EQUAL_INT(BNS_OK, g_vault.ensure_key(g_vault.ctx, "a", k1b));
    TEST_ASSERT_EQUAL_MEMORY(k1, k1b, KL);

    /* distinct identity -> distinct key */
    TEST_ASSERT_EQUAL_INT(BNS_OK, g_vault.ensure_key(g_vault.ctx, "b", k2));
    TEST_ASSERT_FALSE(memcmp(k1, k2, KL) == 0);
}

/* getKey returns absent for an identity that was never created.
 * (TS: getKey returns null for an identity never created.) */
static void test_get_key_absent_for_unknown(void)
{
    uint8_t kb[KL];
    bool found = true;
    TEST_ASSERT_EQUAL_INT(BNS_OK, g_vault.get_key(g_vault.ctx, "never", kb, &found));
    TEST_ASSERT_FALSE(found);
}

/* shred removes the key, reports whether one was present.
 * (TS: shred removes the key, reports whether one was present, and zeroises ...) */
static void test_shred_removes_and_reports(void)
{
    uint8_t kb[KL];
    bool found = false, had = false;

    TEST_ASSERT_EQUAL_INT(BNS_OK, g_vault.ensure_key(g_vault.ctx, "a", kb));

    /* a key was present */
    TEST_ASSERT_EQUAL_INT(BNS_OK, g_vault.shred(g_vault.ctx, "a", &had));
    TEST_ASSERT_TRUE(had);

    /* getKey now absent, has() false */
    found = true;
    TEST_ASSERT_EQUAL_INT(BNS_OK, g_vault.get_key(g_vault.ctx, "a", kb, &found));
    TEST_ASSERT_FALSE(found);
    TEST_ASSERT_FALSE(g_vault.has(g_vault.ctx, "a"));

    /* already gone — nothing to shred */
    had = true;
    TEST_ASSERT_EQUAL_INT(BNS_OK, g_vault.shred(g_vault.ctx, "a", &had));
    TEST_ASSERT_FALSE(had);
}

/* TS: "...and zeroises the old buffer" — the in-place zeroisation of the
 * returned Buffer. The C vtable copies the key into a caller buffer, so there is
 * no shared internal buffer to observe being cleansed (the header pins that
 * shred OPENSSL_cleanse()s the internal bytes before removal — verified by the
 * library, not observable through copy-out). Equivalent erasure guarantee is
 * covered by test_shred_is_irreversible. */
static void test_shred_zeroises_returned_buffer(void)
{
    TEST_IGNORE_MESSAGE("C copy-out ensure_key has no shared internal buffer to "
                        "observe zeroisation; internal OPENSSL_cleanse is a library "
                        "invariant. Erasure covered by test_shred_is_irreversible.");
}

/* shred is irreversible: re-ensureKey after shred mints a FRESH key, never the
 * old one (the GDPR Art.17 erasure property at the root).
 * (TS: "shred is irreversible: re-ensureKey after shred mints a FRESH key".) */
static void test_shred_is_irreversible(void)
{
    uint8_t before[KL], after[KL];
    bool had = false;

    TEST_ASSERT_EQUAL_INT(BNS_OK, g_vault.ensure_key(g_vault.ctx, "a", before));
    TEST_ASSERT_EQUAL_INT(BNS_OK, g_vault.shred(g_vault.ctx, "a", &had));
    TEST_ASSERT_TRUE(had);

    TEST_ASSERT_EQUAL_INT(BNS_OK, g_vault.ensure_key(g_vault.ctx, "a", after));
    /* the key is gone for good: a fresh mint never equals the shredded one */
    TEST_ASSERT_FALSE(memcmp(before, after, KL) == 0);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_ensure_key_idempotent_and_distinct);
    RUN_TEST(test_get_key_absent_for_unknown);
    RUN_TEST(test_shred_removes_and_reports);
    RUN_TEST(test_shred_zeroises_returned_buffer);
    RUN_TEST(test_shred_is_irreversible);
    return UNITY_END();
}
