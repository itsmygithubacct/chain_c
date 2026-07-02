/*
 * test_provenance.c — Unity port of chain/tests/priscilla/provenance.test.ts
 * ("Theme D — dataset/model provenance receipts").
 *
 * Mirrors the KEY assertions of the TS suite against the real C public API:
 *   provenance.h     (compute_provenance_hash, provenance_preimage,
 *                     BONSAI_ZERO_PROVENANCE, provenance_record_t)
 *   privacy/enclave.h(private_enclave_seal_action / open / shred — the
 *                     PrivateEnclave.sealAction TS behaviour)
 *   privacy/key_vault.h (InMemoryKeyVault)
 *
 * Build+run with the standalone command in the cluster task description (gcc
 * -std=c11 -D_GNU_SOURCE over include + third_party + tests/helpers, linking
 * build/libbonsai_chain.a and libsecp256k1/libcrypto/libcurl).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>
#include <stdlib.h>

#include "unity.h"

#include "common/error.h"
#include "common/bytes.h"
#include "provenance.h"
#include "privacy/enclave.h"
#include "privacy/key_vault.h"

#include "fixtures.h"   /* fix_provenance_record == TS REC */

void setUp(void) {}
void tearDown(void) {}

/* The TS REC, mirrored via the shared fixture. */
static void rec(provenance_record_t *r) { fix_provenance_record(r); }

/* Convenience: compute hash, asserting BNS_OK; caller frees. */
static char *hash_of(const provenance_record_t *r)
{
    char *h = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, compute_provenance_hash(r, &h));
    TEST_ASSERT_NOT_NULL(h);
    return h;
}

/* TS: 'ZERO_PROVENANCE is 32 zero bytes' */
static void test_zero_provenance_is_32_zero_bytes(void)
{
    TEST_ASSERT_EQUAL_INT(64, (int)strlen(BONSAI_ZERO_PROVENANCE));
    TEST_ASSERT_EQUAL_STRING(
        "0000000000000000000000000000000000000000000000000000000000000000",
        BONSAI_ZERO_PROVENANCE);
}

/* TS: 'computeProvenanceHash is deterministic and 32 bytes' */
static void test_compute_is_deterministic_and_32_bytes(void)
{
    provenance_record_t r; rec(&r);
    char *h1 = hash_of(&r);
    char *h2 = hash_of(&r);
    TEST_ASSERT_EQUAL_STRING(h1, h2);                 /* deterministic */
    TEST_ASSERT_EQUAL_INT(64, (int)strlen(h1));        /* 32 bytes      */
    TEST_ASSERT_TRUE(strcmp(h1, BONSAI_ZERO_PROVENANCE) != 0);
    free(h1); free(h2);
}

/* TS: 'changes when any field changes' */
static void test_changes_when_any_field_changes(void)
{
    provenance_record_t base; rec(&base);
    char *b = hash_of(&base);

    provenance_record_t v;

    rec(&v); v.dataset_id  = "other";       { char *h = hash_of(&v); TEST_ASSERT_TRUE(strcmp(h, b) != 0); free(h); }
    rec(&v); v.model_id     = "gpt-x";       { char *h = hash_of(&v); TEST_ASSERT_TRUE(strcmp(h, b) != 0); free(h); }
    rec(&v); v.version      = "2026-02";     { char *h = hash_of(&v); TEST_ASSERT_TRUE(strcmp(h, b) != 0); free(h); }
    rec(&v); v.licence_tag  = "proprietary"; { char *h = hash_of(&v); TEST_ASSERT_TRUE(strcmp(h, b) != 0); free(h); }

    free(b);
}

/* TS: 'length-prefixing prevents field-boundary collisions'
 * Without length prefixes, ("ab","c") and ("a","bc") would collide. */
static void test_length_prefixing_prevents_collisions(void)
{
    provenance_record_t a = { .dataset_id = "ab", .model_id = "c",  .version = "v", .licence_tag = "l" };
    provenance_record_t b = { .dataset_id = "a",  .model_id = "bc", .version = "v", .licence_tag = "l" };

    byte_buf_t pa, pb; byte_buf_init(&pa); byte_buf_init(&pb);
    TEST_ASSERT_EQUAL_INT(BNS_OK, provenance_preimage(&a, &pa));
    TEST_ASSERT_EQUAL_INT(BNS_OK, provenance_preimage(&b, &pb));
    TEST_ASSERT_FALSE(byte_buf_eq(&pa, &pb));
    byte_buf_free(&pa); byte_buf_free(&pb);
}

/* TS: 'sealAction returns the provenanceHash and stores the record for audit' */
static void test_seal_action_returns_hash_and_stores_record(void)
{
    key_vault_t vault;
    TEST_ASSERT_EQUAL_INT(BNS_OK, in_memory_key_vault_new(&vault));
    private_enclave_t *enc = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_new(&vault, NULL, NULL, &enc));

    provenance_record_t r; rec(&r);
    const char *payload = "do work";

    sealed_record_t sealed; memset(&sealed, 0, sizeof sealed);
    char *action_hash = NULL, *prov_hash = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_seal_action(
        enc, "id-1", (const uint8_t *)payload, strlen(payload), &r,
        &sealed, &action_hash, &prov_hash));

    /* provenanceHash == computeProvenanceHash(REC) */
    char *expect = hash_of(&r);
    TEST_ASSERT_EQUAL_STRING(expect, prov_hash);

    /* sealed.provenance deep-equals REC */
    TEST_ASSERT_TRUE(sealed.has_provenance);
    TEST_ASSERT_EQUAL_STRING(r.dataset_id,  sealed.provenance.dataset_id);
    TEST_ASSERT_EQUAL_STRING(r.model_id,    sealed.provenance.model_id);
    TEST_ASSERT_EQUAL_STRING(r.version,     sealed.provenance.version);
    TEST_ASSERT_EQUAL_STRING(r.licence_tag, sealed.provenance.licence_tag);

    /* actionHash has length 64 */
    TEST_ASSERT_NOT_NULL(action_hash);
    TEST_ASSERT_EQUAL_INT(64, (int)strlen(action_hash));

    /* An auditor recomputes the commitment from the stored record. */
    char *recomputed = hash_of(&sealed.provenance);
    TEST_ASSERT_EQUAL_STRING(prov_hash, recomputed);

    free(expect); free(recomputed); free(action_hash); free(prov_hash);
    sealed_record_free(&sealed);
    private_enclave_free(enc);
    in_memory_key_vault_free(&vault);
}

/* TS: 'sealAction with no provenance commits the zero sentinel' */
static void test_seal_action_no_provenance_zero_sentinel(void)
{
    key_vault_t vault;
    TEST_ASSERT_EQUAL_INT(BNS_OK, in_memory_key_vault_new(&vault));
    private_enclave_t *enc = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_new(&vault, NULL, NULL, &enc));

    const char *payload = "do work";
    sealed_record_t sealed; memset(&sealed, 0, sizeof sealed);
    char *action_hash = NULL, *prov_hash = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_seal_action(
        enc, "id-2", (const uint8_t *)payload, strlen(payload), /*provenance=*/NULL,
        &sealed, &action_hash, &prov_hash));

    TEST_ASSERT_EQUAL_STRING(BONSAI_ZERO_PROVENANCE, prov_hash);
    TEST_ASSERT_FALSE(sealed.has_provenance);   /* TS: sealed.provenance === undefined */

    free(action_hash); free(prov_hash);
    sealed_record_free(&sealed);
    private_enclave_free(enc);
    in_memory_key_vault_free(&vault);
}

/* TS: 'provenance survives crypto-shred (auditable metadata, not erased payload)'
 * The confidential payload is erased (open -> shredded), but the provenance
 * metadata remains and stays verifiable. */
static void test_provenance_survives_shred(void)
{
    key_vault_t vault;
    TEST_ASSERT_EQUAL_INT(BNS_OK, in_memory_key_vault_new(&vault));
    private_enclave_t *enc = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_new(&vault, NULL, NULL, &enc));

    provenance_record_t r; rec(&r);
    const char *payload = "secret prompt text";

    sealed_record_t sealed; memset(&sealed, 0, sizeof sealed);
    char *action_hash = NULL, *prov_hash = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_seal_action(
        enc, "id-3", (const uint8_t *)payload, strlen(payload), &r,
        &sealed, &action_hash, &prov_hash));

    /* shred id-3 */
    bool had = false; char *marker = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_shred(enc, "id-3", &had, &marker));
    TEST_ASSERT_TRUE(had);

    /* The confidential payload is erased: open() throws /shredded/ */
    byte_buf_t out; byte_buf_init(&out);
    TEST_ASSERT_EQUAL_INT(BNS_ESHREDDED, private_enclave_open(enc, &sealed, &out));
    byte_buf_free(&out);

    /* ...but the provenance metadata remains and stays verifiable. */
    TEST_ASSERT_TRUE(sealed.has_provenance);
    TEST_ASSERT_EQUAL_STRING(r.dataset_id,  sealed.provenance.dataset_id);
    TEST_ASSERT_EQUAL_STRING(r.model_id,    sealed.provenance.model_id);
    TEST_ASSERT_EQUAL_STRING(r.version,     sealed.provenance.version);
    TEST_ASSERT_EQUAL_STRING(r.licence_tag, sealed.provenance.licence_tag);

    char *still = hash_of(&sealed.provenance);
    TEST_ASSERT_EQUAL_INT(64, (int)strlen(still));

    free(still); free(marker); free(action_hash); free(prov_hash);
    sealed_record_free(&sealed);
    private_enclave_free(enc);
    in_memory_key_vault_free(&vault);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_zero_provenance_is_32_zero_bytes);
    RUN_TEST(test_compute_is_deterministic_and_32_bytes);
    RUN_TEST(test_changes_when_any_field_changes);
    RUN_TEST(test_length_prefixing_prevents_collisions);
    RUN_TEST(test_seal_action_returns_hash_and_stores_record);
    RUN_TEST(test_seal_action_no_provenance_zero_sentinel);
    RUN_TEST(test_provenance_survives_shred);
    return UNITY_END();
}
