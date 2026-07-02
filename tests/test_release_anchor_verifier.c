/*
 * test_release_anchor_verifier.c — Unity port of
 *   chain/tests/priscilla/releaseAnchorVerifier.test.ts
 *
 * Pillar A consumer gate: SPV-verified, aged, M-of-N attested, un-revoked
 * release anchor or it fails closed. The TS test injects STRING-keyed fakes for
 * SpvClient / AttestationVerifier / RevocationOracle (no real crypto), so this
 * port does the same — every distinct DenyReason / boundary / fail-closed vs
 * fail-open path is exercised against the real release_anchor_verifier C API.
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
#include "verifier/release_anchor_verifier.h"

void setUp(void) {}
void tearDown(void) {}

/* ----------------------------------------------------------------------------
 * String-keyed fakes (mirroring the TS FakeSpv / FakeAttestor / FakeRevocation)
 * ------------------------------------------------------------------------- */

/* FakeSpv: announce1/activate1 lookups + a tip; throwTip honored. */
typedef struct {
    spv_lookup_t announce;  bool announce_found;
    spv_lookup_t activate;  bool activate_found;
    int64_t      tip;
    bool         throw_tip;
} fake_spv_t;

static int fake_spv_lookup(void *ctx, const char *txid, spv_lookup_t *out, bool *out_found)
{
    fake_spv_t *s = ctx;
    if (strcmp(txid, "announce1") == 0) { *out = s->announce; *out_found = s->announce_found; return BNS_OK; }
    if (strcmp(txid, "activate1") == 0) { *out = s->activate; *out_found = s->activate_found; return BNS_OK; }
    *out_found = false; return BNS_OK;
}
static int fake_spv_tip(void *ctx, int64_t *out_tip)
{
    fake_spv_t *s = ctx;
    if (s->throw_tip) return BNS_ENET;   /* the TS `throw new Error('tip height unavailable')` */
    *out_tip = s->tip; return BNS_OK;
}

/* FakeAttestor: verify(pub,_,sig) good iff "pub:sig" is in the good set. */
typedef struct { const char **good; size_t n; } fake_att_t;
static int fake_att_verify(void *ctx, const char *pub, const char *dig,
                           const char *sig, bool *out_ok)
{
    (void)dig;
    fake_att_t *a = ctx;
    char key[256]; snprintf(key, sizeof key, "%s:%s", pub, sig);
    *out_ok = false;
    for (size_t i = 0; i < a->n; i++)
        if (strcmp(key, a->good[i]) == 0) { *out_ok = true; break; }
    return BNS_OK;
}

/* FakeRevocation: revoked flag; throwOnCheck honored. */
typedef struct { bool revoked; bool throw_check; } fake_rev_t;
static int fake_rev_check(void *ctx, const char *g, const char *s, const char *v, bool *out)
{
    (void)g; (void)s; (void)v;
    fake_rev_t *r = ctx;
    if (r->throw_check) return BNS_ENET;  /* the TS `throw new Error('revocation oracle unavailable')` */
    *out = r->revoked; return BNS_OK;
}

/* ----------------------------------------------------------------------------
 * Shared fixture data (TS baseRef / publisher / local)
 * ------------------------------------------------------------------------- */
#define B64 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define F64 "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
#define Z64 "0000000000000000000000000000000000000000000000000000000000000000"

static const char *g_ns_scopes[]   = { "bsv-anchor-*" };
static const char *g_att_pubkeys[] = { "att1", "att2", "att3" };

static trusted_publisher_t make_publisher(void)
{
    trusted_publisher_t p = {
        .label = "bsv-anchor-bundle", .genesis_outpoint = "f3a1:0",
        .namespace_scopes = g_ns_scopes, .num_namespace_scopes = 1,
        .min_depth = 144, .min_quorum = 2,
        .attestor_pubkeys = g_att_pubkeys, .num_attestor_pubkeys = 3,
        .max_staleness = 72,
    };
    return p;
}

/* Options for one verify scenario (the TS `verifier(opts?)` factory). */
typedef struct {
    int64_t  depth;            /* announce depth (default 200) */
    int64_t  tip;              /* tip height (default 800200) */
    const char **good_sigs;    /* default {att1:sig1, att2:sig2} */
    size_t   n_good;
    bool     activate_null;    /* activateLookup === null */
    bool     activate_no_merkle;
    bool     throw_tip;
    bool     throw_rev;
    bool     revoked;
    /* ref overrides */
    const char *scope_override;
    const char *local_fsr_override;
    const char *digest_override;          /* owned-by-caller, used as ref.activateDigest */
    const release_attestation_t *atts; size_t n_atts;
    bool     publisher_null;
    /* opts */
    bool     fail_open;        /* failClosed:false */
} scen_t;

/* Run one scenario; returns the verify_result_t. Caller-supplied digest_override
 * (if any) must outlive the call. */
static verify_result_t run_scen(const scen_t *o)
{
    static const char *def_good[] = { "att1:sig1", "att2:sig2" };
    static const release_attestation_t def_atts[] = { { "att1", "sig1" }, { "att2", "sig2" } };

    fake_spv_t spv = {0};
    spv.announce        = (spv_lookup_t){ .depth = o->depth ? o->depth : 200,
                                          .block_height = 800000, .merkle_verified = true };
    spv.announce_found  = true;
    if (o->activate_null) {
        spv.activate_found = false;
    } else {
        spv.activate = (spv_lookup_t){ .depth = 3, .block_height = 800197,
                                       .merkle_verified = !o->activate_no_merkle };
        spv.activate_found = true;
    }
    spv.tip       = o->tip ? o->tip : 800200;
    spv.throw_tip = o->throw_tip;

    fake_att_t att = { o->good_sigs ? o->good_sigs : def_good,
                       o->good_sigs ? o->n_good : 2 };
    fake_rev_t rev = { o->revoked, o->throw_rev };

    spv_client_t spvc = { .ctx = &spv, .lookup = fake_spv_lookup, .tip_height = fake_spv_tip };
    attestation_verifier_t attc = { .ctx = &att, .verify = fake_att_verify };
    release_revocation_oracle_t revc = { .ctx = &rev, .is_release_revoked = fake_rev_check };

    release_anchor_verifier_t *v = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, release_anchor_verifier_new(&spvc, &attc, &revc, &v));

    const char *scope = o->scope_override ? o->scope_override : "bsv-anchor-core";

    /* digest is the canonical one (computed from non-overridden scope) unless
     * the scenario pins a cross-release replay digest. */
    char *digest = NULL;
    if (o->digest_override) {
        digest = strdup(o->digest_override);
    } else {
        TEST_ASSERT_EQUAL_INT(BNS_OK, compute_activate_digest(
            "f3a1:0", "bsv-anchor-core", "1.2.0", B64, F64, "announce1", &digest));
    }

    publish_ref_t ref = {
        .genesis_outpoint = "f3a1:0", .scope = scope, .version = "1.2.0",
        .bundle_hash = B64, .file_set_root = F64, .announce_txid = "announce1",
        .activate_txid = "activate1", .activate_digest = digest,
        .attestations = o->atts ? o->atts : def_atts,
        .num_attestations = o->atts ? o->n_atts : 2,
    };
    local_artifact_t local = {
        .bundle_hash = B64,
        .file_set_root = o->local_fsr_override ? o->local_fsr_override : F64,
    };
    trusted_publisher_t pub = make_publisher();
    verify_opts_t opts = { .fail_closed = !o->fail_open, .has_fail_closed = o->fail_open };

    verify_result_t res; memset(&res, 0, sizeof res);
    int rc = release_anchor_verifier_verify(v, &ref, &local,
                                            o->publisher_null ? NULL : &pub,
                                            o->fail_open ? &opts : NULL, &res);
    TEST_ASSERT_EQUAL_INT(BNS_OK, rc);
    free(digest);
    release_anchor_verifier_free(v);
    return res;
}

/* Convenience asserters. */
static void assert_ok(const scen_t *o)
{
    verify_result_t r = run_scen(o);
    if (!r.ok) printf("    (unexpected deny: %s)\n", deny_reason_str(r.reason));
    TEST_ASSERT_TRUE(r.ok);
    TEST_ASSERT_EQUAL_INT(DENY_NONE, r.reason);
}
static void assert_deny(const scen_t *o, deny_reason_t want)
{
    verify_result_t r = run_scen(o);
    TEST_ASSERT_FALSE(r.ok);
    TEST_ASSERT_EQUAL_STRING(deny_reason_str(want), deny_reason_str(r.reason));
}

/* ----------------------------------------------------------------------------
 * Tests (one per TS `it`)
 * ------------------------------------------------------------------------- */

static void test_accepts_wellformed(void)
{
    scen_t o = {0};
    assert_ok(&o);
}

static void test_unknown_publisher(void)
{
    scen_t o = { .publisher_null = true };
    assert_deny(&o, DENY_UNKNOWN_PUBLISHER);
}

static void test_scope_not_in_namespace(void)
{
    scen_t o = { .scope_override = "evil-package" };
    assert_deny(&o, DENY_SCOPE_NOT_IN_NAMESPACE);
}

static void test_fileset_root_mismatch(void)
{
    scen_t o = { .local_fsr_override = Z64 };
    assert_deny(&o, DENY_FILESET_ROOT_MISMATCH);
}

static void test_insufficient_depth(void)
{
    scen_t o = { .depth = 10 };
    assert_deny(&o, DENY_INSUFFICIENT_DEPTH);
}

static void test_boundary_depth_eq_min_accepts(void)
{
    /* depth == minDepth (144); gate is `< minDepth`, so == passes. staleness 56. */
    scen_t o = { .depth = 144 };
    assert_ok(&o);
}

static void test_boundary_depth_min_minus_one_rejects(void)
{
    scen_t o = { .depth = 143 };
    assert_deny(&o, DENY_INSUFFICIENT_DEPTH);
}

static void test_stale_chain(void)
{
    scen_t o = { .tip = 900000 };
    assert_deny(&o, DENY_STALE_CHAIN);
}

static void test_boundary_staleness_eq_max_accepts(void)
{
    /* staleness = tip-(blockHeight+depth) = 800272-(800000+200) = 72 == max; gate '>' => passes */
    scen_t o = { .tip = 800272 };
    assert_ok(&o);
}

static void test_boundary_staleness_max_plus_one_rejects(void)
{
    scen_t o = { .tip = 800273 };  /* staleness 73 > 72 */
    assert_deny(&o, DENY_STALE_CHAIN);
}

static void test_activate_unconfirmed(void)
{
    scen_t o = { .activate_null = true };
    assert_deny(&o, DENY_ACTIVATE_UNCONFIRMED);
}

static void test_activate_no_merkle_proof(void)
{
    scen_t o = { .activate_no_merkle = true };
    assert_deny(&o, DENY_ACTIVATE_NO_MERKLE_PROOF);
}

static void test_digest_mismatch_cross_release(void)
{
    /* A quorum genuinely signed... for a DIFFERENT release (version 1.1.9). */
    char *bad = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, compute_activate_digest(
        "f3a1:0", "bsv-anchor-core", "1.1.9", B64, F64, "announce1", &bad));
    scen_t o = { .digest_override = bad };
    assert_deny(&o, DENY_DIGEST_MISMATCH);
    free(bad);
}

static void test_below_quorum_bad_attestation(void)
{
    /* one valid sig, need 2 -> the second sig fails verify -> bad-attestation */
    static const char *good1[] = { "att1:sig1" };
    scen_t o = { .good_sigs = good1, .n_good = 1 };
    assert_deny(&o, DENY_BAD_ATTESTATION);
}

static void test_duplicate_attestor(void)
{
    static const char *good1[] = { "att1:sig1" };
    static const release_attestation_t dup[] = { { "att1", "sig1" }, { "att1", "sig1" } };
    scen_t o = { .good_sigs = good1, .n_good = 1, .atts = dup, .n_atts = 2 };
    assert_deny(&o, DENY_DUPLICATE_ATTESTOR);
}

static void test_attestor_not_in_set(void)
{
    /* self-minted keys produce VALID sigs but are not in the charter set. */
    static const char *evil[] = { "evil1:sigX", "evil2:sigY" };
    static const release_attestation_t evil_atts[] = { { "evil1", "sigX" }, { "evil2", "sigY" } };
    scen_t o = { .good_sigs = evil, .n_good = 2, .atts = evil_atts, .n_atts = 2 };
    assert_deny(&o, DENY_ATTESTOR_NOT_IN_SET);
}

static void test_revoked_release(void)
{
    scen_t o = { .revoked = true };
    assert_deny(&o, DENY_RELEASE_REVOKED);
}

static void test_fail_closed_tip_unavailable(void)
{
    /* default fail-closed: tip throw => deny stale-chain (detail mentions fail-closed) */
    scen_t o = { .throw_tip = true };
    verify_result_t r = run_scen(&o);
    TEST_ASSERT_FALSE(r.ok);
    TEST_ASSERT_EQUAL_STRING(deny_reason_str(DENY_STALE_CHAIN), deny_reason_str(r.reason));
    /* TS asserts r.detail matches /fail-closed/ */
    TEST_ASSERT_NOT_NULL(r.detail);
    TEST_ASSERT_NOT_NULL(strstr(r.detail, "fail-closed"));
}

static void test_fail_open_tip_unavailable(void)
{
    /* failClosed:false: tip falls back to blockHeight+depth => staleness 0 => OK */
    scen_t o = { .throw_tip = true, .fail_open = true };
    assert_ok(&o);
}

static void test_fail_closed_revocation_unavailable(void)
{
    scen_t o = { .throw_rev = true };
    verify_result_t r = run_scen(&o);
    TEST_ASSERT_FALSE(r.ok);
    TEST_ASSERT_EQUAL_STRING(deny_reason_str(DENY_RELEASE_REVOKED), deny_reason_str(r.reason));
    TEST_ASSERT_NOT_NULL(r.detail);
    TEST_ASSERT_NOT_NULL(strstr(r.detail, "fail-closed"));
}

static void test_fail_open_revocation_unavailable(void)
{
    scen_t o = { .throw_rev = true, .fail_open = true };
    assert_ok(&o);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_accepts_wellformed);
    RUN_TEST(test_unknown_publisher);
    RUN_TEST(test_scope_not_in_namespace);
    RUN_TEST(test_fileset_root_mismatch);
    RUN_TEST(test_insufficient_depth);
    RUN_TEST(test_boundary_depth_eq_min_accepts);
    RUN_TEST(test_boundary_depth_min_minus_one_rejects);
    RUN_TEST(test_stale_chain);
    RUN_TEST(test_boundary_staleness_eq_max_accepts);
    RUN_TEST(test_boundary_staleness_max_plus_one_rejects);
    RUN_TEST(test_activate_unconfirmed);
    RUN_TEST(test_activate_no_merkle_proof);
    RUN_TEST(test_digest_mismatch_cross_release);
    RUN_TEST(test_below_quorum_bad_attestation);
    RUN_TEST(test_duplicate_attestor);
    RUN_TEST(test_attestor_not_in_set);
    RUN_TEST(test_revoked_release);
    RUN_TEST(test_fail_closed_tip_unavailable);
    RUN_TEST(test_fail_open_tip_unavailable);
    RUN_TEST(test_fail_closed_revocation_unavailable);
    RUN_TEST(test_fail_open_revocation_unavailable);
    return UNITY_END();
}
