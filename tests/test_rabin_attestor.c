/*
 * test_rabin_attestor.c — Unity port of
 *   chain/tests/priscilla/rabinAttestor.test.ts
 *
 * The Rabin-signature attestation toolkit (REAL crypto behind the M-of-N
 * quorum): sign/verify round-trip, rejection under a wrong pubkey / wrong
 * digest, fail-closed parse of malformed wire formats, and the end-to-end run
 * through ReleaseAnchorVerifier with the genuine Rabin AttestationVerifier
 * vtable (charter quorum accept, non-charter key reject, bad-signature reject).
 *
 * Rabin keygen is the slow part, so (like the TS) the keys are generated ONCE in
 * main() and shared across every test via file-scope globals.
 *
 * Build+run standalone (avoids the shared cmake race); see cluster command.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "unity.h"
#include "common/error.h"
#include "crypto/bignum.h"
#include "crypto/rabin.h"
#include "verifier/rabin_attestor.h"
#include "verifier/release_anchor_verifier.h"

/* ---- shared keys (generated once; keygen is expensive) ------------------- */
static rabin_attestor_key_t g_att1, g_att2, g_outsider;
static char *g_pub1, *g_pub2, *g_pub_outsider;
static bool  g_keys_ready;

/* The release fields + canonical digest the TS pins. */
#define B64 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define F64 "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
static char *g_digest;     /* computeActivateDigest(release) */

void setUp(void) {}
void tearDown(void) {}

/* ----------------------------------------------------------------------------
 * parseAttestation — fail-closed wire parse (no real crypto needed)
 * ------------------------------------------------------------------------- */
static void test_parse_attestation_malformed_returns_not_ok(void)
{
    static const char *bad[] = {
        "1:ab",        /* too few fields */
        "1:ab:2:3",    /* too many fields */
        "notnum:ab:2", /* non-numeric seq */
        "-1:ab:2",     /* negative seq */
        "1:zz:2",      /* non-hex signature */
        "1:ab:-1",     /* negative padding */
        "1:ab:x",      /* non-integer padding */
        "not-a-signature", /* (verify-level) no colon at all */
        "zz:3",            /* two fields, non-hex */
        "abc:-1",          /* two fields, negative */
    };
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
        parsed_attestation_t pa; memset(&pa, 0, sizeof pa);
        bool ok = true;
        int rc = parse_attestation(bad[i], &pa, &ok);
        TEST_ASSERT_EQUAL_INT(BNS_OK, rc);     /* never throws */
        TEST_ASSERT_FALSE_MESSAGE(ok, bad[i]); /* the TS null */
        parsed_attestation_free(&pa);
    }
}

static void test_parse_attestation_wellformed(void)
{
    /* "5:ff:2" -> seq 5, s == 0xff == 255, paddingByteCount 2 */
    parsed_attestation_t pa; memset(&pa, 0, sizeof pa);
    bool ok = false;
    TEST_ASSERT_EQUAL_INT(BNS_OK, parse_attestation("5:ff:2", &pa, &ok));
    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL_UINT64(5u, pa.seq);
    TEST_ASSERT_EQUAL_size_t(2u, pa.padding_byte_count);
    /* s == 255: compare via decimal */
    char *dec = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_to_dec(pa.s, &dec));
    TEST_ASSERT_EQUAL_STRING("255", dec);
    free(dec);
    parsed_attestation_free(&pa);
}

/* ----------------------------------------------------------------------------
 * sign/verify round-trip (real Rabin)
 * ------------------------------------------------------------------------- */
static void test_roundtrip_verifies_under_signing_pubkey(void)
{
    if (!g_keys_ready) { TEST_IGNORE_MESSAGE("keygen failed"); }
    char *sig = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_attestor_sign_digest(&g_att1, g_digest, 1, &sig));
    bool ok = false;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_attestation_verify(g_pub1, g_digest, sig, &ok));
    TEST_ASSERT_TRUE(ok);
    free(sig);
}

static void test_rejects_under_different_pubkey(void)
{
    if (!g_keys_ready) { TEST_IGNORE_MESSAGE("keygen failed"); }
    char *sig = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_attestor_sign_digest(&g_att1, g_digest, 1, &sig));
    bool ok = true;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_attestation_verify(g_pub2, g_digest, sig, &ok));
    TEST_ASSERT_FALSE(ok);
    free(sig);
}

static void test_rejects_over_different_digest(void)
{
    if (!g_keys_ready) { TEST_IGNORE_MESSAGE("keygen failed"); }
    char *sig = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_attestor_sign_digest(&g_att1, g_digest, 1, &sig));
    /* digest for a DIFFERENT release version */
    char *other = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, compute_activate_digest(
        "f3a1:0", "bsv-anchor-core", "1.2.1", B64, F64, "announce1", &other));
    bool ok = true;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_attestation_verify(g_pub1, other, sig, &ok));
    TEST_ASSERT_FALSE(ok);
    free(other);
    free(sig);
}

static void test_verify_malformed_inputs_without_throwing(void)
{
    if (!g_keys_ready) { TEST_IGNORE_MESSAGE("keygen failed"); }
    bool ok = true;
    /* malformed signature wire strings -> false, never error */
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_attestation_verify(g_pub1, g_digest, "not-a-signature", &ok));
    TEST_ASSERT_FALSE(ok);
    ok = true;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_attestation_verify(g_pub1, g_digest, "zz:3", &ok));
    TEST_ASSERT_FALSE(ok);
    ok = true;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_attestation_verify(g_pub1, g_digest, "abc:-1", &ok));
    TEST_ASSERT_FALSE(ok);
    /* malformed pubkey ("not-a-number") with a genuine signature -> false */
    char *sig = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_attestor_sign_digest(&g_att1, g_digest, 1, &sig));
    ok = true;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_attestation_verify("not-a-number", g_digest, sig, &ok));
    TEST_ASSERT_FALSE(ok);
    free(sig);
}

/* ----------------------------------------------------------------------------
 * End-to-end through ReleaseAnchorVerifier with the REAL Rabin verifier
 * ------------------------------------------------------------------------- */

/* SPV: announce1 deep+aged, activate1 shallow+confirmed; tip 800200. */
static int e2e_spv_lookup(void *ctx, const char *txid, spv_lookup_t *out, bool *out_found)
{
    (void)ctx;
    if (strcmp(txid, "announce1") == 0) {
        *out = (spv_lookup_t){ .depth = 200, .block_height = 800000, .merkle_verified = true };
        *out_found = true; return BNS_OK;
    }
    if (strcmp(txid, "activate1") == 0) {
        *out = (spv_lookup_t){ .depth = 3, .block_height = 800197, .merkle_verified = true };
        *out_found = true; return BNS_OK;
    }
    *out_found = false; return BNS_OK;
}
static int e2e_spv_tip(void *ctx, int64_t *out_tip) { (void)ctx; *out_tip = 800200; return BNS_OK; }
static int e2e_rev_never(void *ctx, const char *g, const char *s, const char *v, bool *out)
{ (void)ctx; (void)g; (void)s; (void)v; *out = false; return BNS_OK; }

/* Build a verifier wired to the genuine Rabin attestation vtable, run one ref,
 * and return its result. `att_pubkeys`/`atts` describe the quorum. */
static verify_result_t e2e_run(const char *const *charter_pubkeys, size_t n_charter,
                               const release_attestation_t *atts, size_t n_atts)
{
    attestation_verifier_t attc;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_attestation_verifier_vtable(&attc));

    spv_client_t spvc = { .ctx = NULL, .lookup = e2e_spv_lookup, .tip_height = e2e_spv_tip };
    release_revocation_oracle_t revc = { .ctx = NULL, .is_release_revoked = e2e_rev_never };

    release_anchor_verifier_t *v = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, release_anchor_verifier_new(&spvc, &attc, &revc, &v));

    static const char *ns_scopes[] = { "bsv-anchor-*" };
    trusted_publisher_t pub = {
        .label = "bsv-anchor-bundle", .genesis_outpoint = "f3a1:0",
        .namespace_scopes = ns_scopes, .num_namespace_scopes = 1,
        .min_depth = 144, .min_quorum = 2,
        .attestor_pubkeys = charter_pubkeys, .num_attestor_pubkeys = n_charter,
        .max_staleness = 72,
    };
    publish_ref_t ref = {
        .genesis_outpoint = "f3a1:0", .scope = "bsv-anchor-core", .version = "1.2.0",
        .bundle_hash = B64, .file_set_root = F64, .announce_txid = "announce1",
        .activate_txid = "activate1", .activate_digest = g_digest,
        .attestations = atts, .num_attestations = n_atts,
    };
    local_artifact_t local = { .bundle_hash = B64, .file_set_root = F64 };

    verify_result_t res; memset(&res, 0, sizeof res);
    TEST_ASSERT_EQUAL_INT(BNS_OK, release_anchor_verifier_verify(v, &ref, &local, &pub, NULL, &res));
    release_anchor_verifier_free(v);
    return res;
}

static void test_e2e_accepts_genuine_2of2_quorum(void)
{
    if (!g_keys_ready) { TEST_IGNORE_MESSAGE("keygen failed"); }
    char *s1 = NULL, *s2 = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_attestor_sign_digest(&g_att1, g_digest, 1, &s1));
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_attestor_sign_digest(&g_att2, g_digest, 1, &s2));
    const char *charter[] = { g_pub1, g_pub2 };
    release_attestation_t atts[] = { { g_pub1, s1 }, { g_pub2, s2 } };
    verify_result_t r = e2e_run(charter, 2, atts, 2);
    if (!r.ok) printf("    (unexpected deny: %s)\n", deny_reason_str(r.reason));
    TEST_ASSERT_TRUE(r.ok);
    free(s1); free(s2);
}

static void test_e2e_rejects_noncharter_key(void)
{
    if (!g_keys_ready) { TEST_IGNORE_MESSAGE("keygen failed"); }
    /* outsider signs a REAL valid sig, but its pubkey is not in the charter set */
    char *s1 = NULL, *so = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_attestor_sign_digest(&g_att1, g_digest, 1, &s1));
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_attestor_sign_digest(&g_outsider, g_digest, 1, &so));
    const char *charter[] = { g_pub1, g_pub2 };
    release_attestation_t atts[] = { { g_pub1, s1 }, { g_pub_outsider, so } };
    verify_result_t r = e2e_run(charter, 2, atts, 2);
    TEST_ASSERT_FALSE(r.ok);
    TEST_ASSERT_EQUAL_STRING(deny_reason_str(DENY_ATTESTOR_NOT_IN_SET), deny_reason_str(r.reason));
    free(s1); free(so);
}

static void test_e2e_rejects_charter_attestor_bad_signature(void)
{
    if (!g_keys_ready) { TEST_IGNORE_MESSAGE("keygen failed"); }
    /* att2's pubkey but att1's signature — does not verify under att2 */
    char *s1 = NULL, *s1b = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_attestor_sign_digest(&g_att1, g_digest, 1, &s1));
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_attestor_sign_digest(&g_att1, g_digest, 1, &s1b));
    const char *charter[] = { g_pub1, g_pub2 };
    release_attestation_t atts[] = { { g_pub1, s1 }, { g_pub2, s1b } };
    verify_result_t r = e2e_run(charter, 2, atts, 2);
    TEST_ASSERT_FALSE(r.ok);
    TEST_ASSERT_EQUAL_STRING(deny_reason_str(DENY_BAD_ATTESTATION), deny_reason_str(r.reason));
    free(s1); free(s1b);
}

/* ---- key setup/teardown ------------------------------------------------- */
static bool setup_keys(void)
{
    if (generate_attestor_key(&g_att1) != BNS_OK) return false;
    if (generate_attestor_key(&g_att2) != BNS_OK) return false;
    if (generate_attestor_key(&g_outsider) != BNS_OK) return false;
    if (attestor_pub_key(&g_att1, &g_pub1) != BNS_OK) return false;
    if (attestor_pub_key(&g_att2, &g_pub2) != BNS_OK) return false;
    if (attestor_pub_key(&g_outsider, &g_pub_outsider) != BNS_OK) return false;
    if (compute_activate_digest("f3a1:0", "bsv-anchor-core", "1.2.0",
                                B64, F64, "announce1", &g_digest) != BNS_OK) return false;
    return true;
}
static void teardown_keys(void)
{
    if (g_keys_ready) {
        rabin_key_free(&g_att1); rabin_key_free(&g_att2); rabin_key_free(&g_outsider);
        free(g_pub1); free(g_pub2); free(g_pub_outsider);
    }
    free(g_digest);
}

int main(void)
{
    g_keys_ready = setup_keys();
    if (!g_keys_ready)
        fprintf(stderr, "WARN: Rabin keygen failed; crypto tests will IGNORE\n");

    UNITY_BEGIN();
    RUN_TEST(test_parse_attestation_malformed_returns_not_ok);
    RUN_TEST(test_parse_attestation_wellformed);
    RUN_TEST(test_roundtrip_verifies_under_signing_pubkey);
    RUN_TEST(test_rejects_under_different_pubkey);
    RUN_TEST(test_rejects_over_different_digest);
    RUN_TEST(test_verify_malformed_inputs_without_throwing);
    RUN_TEST(test_e2e_accepts_genuine_2of2_quorum);
    RUN_TEST(test_e2e_rejects_noncharter_key);
    RUN_TEST(test_e2e_rejects_charter_attestor_bad_signature);
    int rc = UNITY_END();
    teardown_keys();
    return rc;
}
