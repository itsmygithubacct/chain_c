/*
 * test_ricardian_charter.c — Unity port of
 * chain/tests/priscilla/ricardianCharter.test.ts
 * ("ricardianCharter — prose as single source of truth, Theme A").
 *
 * Real C public API exercised:
 *   ricardian_charter.h: parse_charter_params, assert_params_match_prose,
 *     charter_canonical_json, canonical_contract_bytes, compute_ricardian_hash,
 *     sign_charter, verify_charter_signature
 *   json/json.h: canonical_json (the insertion-order-independence assertion)
 *   crypto/bignum.h, crypto/ecdsa.h, crypto/hash.h
 *
 * Fixtures (== TS const blocks): legal/ricardian-prose.md (read raw),
 *   FIX_CHARTER_VALID_BODY (VALID_BODY), fix_charter_block (block()),
 *   fix_charter_binding (BINDING). tx_helper_key gives a deterministic ECDSA
 *   issuer key (TS uses bsv.PrivateKey.fromRandom — determinism is irrelevant to
 *   the sign/verify round-trip assertions).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "unity.h"

#include "common/error.h"
#include "common/bytes.h"
#include "common/hex.h"
#include "crypto/hash.h"
#include "crypto/bignum.h"
#include "crypto/ecdsa.h"
#include "json/json.h"
#include "ricardian_charter.h"

#include "fixtures.h"
#include "tx_helper.h"

/* The real legal prose, read VERBATIM (raw bytes, no normalization). Loaded
 * once in main; tests must run with WORKING_DIRECTORY == chain_c root. */
static char  *g_prose      = NULL;
static size_t g_prose_len  = 0;

void setUp(void) {}
void tearDown(void) {}

static char *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[got] = '\0';
    if (out_len) *out_len = got;
    return buf;
}

/* Compare a parsed bn_t param against a decimal literal. */
static void assert_param_dec(const bn_t *p, const char *dec)
{
    TEST_ASSERT_NOT_NULL(p);
    bn_t *want = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec(dec, &want));
    TEST_ASSERT_EQUAL_INT(0, bn_cmp(p, want));
    bn_free(want);
}

/* ---- prose-parse assertions -------------------------------------------- */

/* TS: 'parses the real legal/ricardian-prose.md and matches the documented policy' */
static void test_parses_real_prose(void)
{
    charter_params_t p; memset(&p, 0, sizeof p);
    bonsai_err_ctx ctx; memset(&ctx, 0, sizeof ctx);
    TEST_ASSERT_EQUAL_INT(BNS_OK, parse_charter_params(g_prose, &p, &ctx));
    assert_param_dec(p.per_tx_limit,         "100000");
    assert_param_dec(p.daily_limit,          "1000000");
    assert_param_dec(p.window_duration,      "86400");
    assert_param_dec(p.graduation_threshold, "10000");
    assert_param_dec(p.validator_threshold,  "50000");
    charter_params_free(&p);
}

/* TS: 'strips inline comments and code-fence markers' */
static void test_strips_comments_and_fences(void)
{
    /* VALID_BODY with a "# max per payment" inline comment on perTxLimit, wrapped
     * in a ``` code fence, then the charter envelope. */
    const char *body_with_comment =
        "perTxLimit          = 100000   # max per payment\n"
        "dailyLimit          = 1000000\n"
        "windowDuration      = 86400\n"
        "graduationThreshold = 10000\n"
        "validatorThreshold  = 50000";
    char fenced[512];
    snprintf(fenced, sizeof fenced, "```\n%s\n```", body_with_comment);
    char *block = fix_charter_block(fenced);
    TEST_ASSERT_NOT_NULL(block);

    charter_params_t p; memset(&p, 0, sizeof p);
    bonsai_err_ctx ctx; memset(&ctx, 0, sizeof ctx);
    TEST_ASSERT_EQUAL_INT(BNS_OK, parse_charter_params(block, &p, &ctx));
    assert_param_dec(p.per_tx_limit, "100000");
    charter_params_free(&p);
    free(block);
}

/* Run parse over `prose`, asserting it FAILS with BNS_EPARSE and that the
 * captured message contains `needle` (the TS error-string fragment). */
static void expect_parse_error(const char *prose, const char *needle)
{
    charter_params_t p; memset(&p, 0, sizeof p);
    bonsai_err_ctx ctx; memset(&ctx, 0, sizeof ctx);
    int rc = parse_charter_params(prose, &p, &ctx);
    TEST_ASSERT_EQUAL_INT(BNS_EPARSE, rc);
    TEST_ASSERT_NOT_NULL(strstr(ctx.msg, needle));
    charter_params_free(&p);
}

/* TS: 'throws when the params block is absent' */
static void test_throws_block_absent(void)
{
    expect_parse_error("# charter with no block", "missing or malformed");
}

/* TS: 'throws on a missing required parameter' (drop validatorThreshold) */
static void test_throws_missing_required(void)
{
    const char *body =
        "perTxLimit          = 100000\n"
        "dailyLimit          = 1000000\n"
        "windowDuration      = 86400\n"
        "graduationThreshold = 10000";
    char *block = fix_charter_block(body);
    TEST_ASSERT_NOT_NULL(block);
    expect_parse_error(block, "missing required parameter \"validatorThreshold\"");
    free(block);
}

/* TS: 'throws on an unknown/extra parameter with no contract field' */
static void test_throws_unknown_param(void)
{
    char buf[1024];
    snprintf(buf, sizeof buf, "%s\nbogusLimit = 1", FIX_CHARTER_VALID_BODY);
    char *block = fix_charter_block(buf);
    TEST_ASSERT_NOT_NULL(block);
    expect_parse_error(block, "unknown parameter \"bogusLimit\"");
    free(block);
}

/* TS: 'throws on a duplicate parameter' */
static void test_throws_duplicate_param(void)
{
    char buf[1024];
    snprintf(buf, sizeof buf, "%s\nperTxLimit = 200000", FIX_CHARTER_VALID_BODY);
    char *block = fix_charter_block(buf);
    TEST_ASSERT_NOT_NULL(block);
    expect_parse_error(block, "duplicate parameter \"perTxLimit\"");
    free(block);
}

/* TS: 'throws on a non-positive value' (perTxLimit = 0) */
static void test_throws_non_positive(void)
{
    const char *body =
        "perTxLimit = 0\n"
        "dailyLimit          = 1000000\n"
        "windowDuration      = 86400\n"
        "graduationThreshold = 10000\n"
        "validatorThreshold  = 50000";
    char *block = fix_charter_block(body);
    TEST_ASSERT_NOT_NULL(block);
    expect_parse_error(block, "must be positive");
    free(block);
}

/* TS: 'throws on an unparseable line' (perTxLimit 100000 — no '=') */
static void test_throws_unparseable_line(void)
{
    char buf[1024];
    snprintf(buf, sizeof buf, "%s\nperTxLimit 100000", FIX_CHARTER_VALID_BODY);
    char *block = fix_charter_block(buf);
    TEST_ASSERT_NOT_NULL(block);
    expect_parse_error(block, "unparseable parameter line");
    free(block);
}

/* TS: 'assertParamsMatchProse passes when equal and throws on divergence' */
static void test_assert_params_match_prose(void)
{
    char *block = fix_charter_block(FIX_CHARTER_VALID_BODY);
    TEST_ASSERT_NOT_NULL(block);
    charter_params_t p; memset(&p, 0, sizeof p);
    bonsai_err_ctx ctx; memset(&ctx, 0, sizeof ctx);
    TEST_ASSERT_EQUAL_INT(BNS_OK, parse_charter_params(block, &p, &ctx));

    /* equal -> ok */
    memset(&ctx, 0, sizeof ctx);
    TEST_ASSERT_EQUAL_INT(BNS_OK, assert_params_match_prose(&p, &p, &ctx));

    /* divergence (perTxLimit = 999) -> EBINDING with the TS message fragment */
    charter_params_t q; memset(&q, 0, sizeof q);
    bonsai_err_ctx ctx2; memset(&ctx2, 0, sizeof ctx2);
    TEST_ASSERT_EQUAL_INT(BNS_OK, parse_charter_params(block, &q, &ctx2));
    bn_free(q.per_tx_limit);
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("999", &q.per_tx_limit));
    bonsai_err_ctx ctx3; memset(&ctx3, 0, sizeof ctx3);
    int rc = assert_params_match_prose(&p, &q, &ctx3);
    TEST_ASSERT_EQUAL_INT(BNS_EBINDING, rc);
    TEST_ASSERT_NOT_NULL(strstr(ctx3.msg, "single-source-of-truth violation"));

    charter_params_free(&p);
    charter_params_free(&q);
    free(block);
}

/* ---- canonical serialization ------------------------------------------- */

/* TS: 'canonicalJSON is insertion-order independent'.
 * The C charter_canonical_json takes a binding; the underlying serializer is
 * json/json.h::canonical_json over a flat string object, which is exactly what
 * the TS canonicalJSON pins. We exercise that directly with {b,a}/{a,b}. */
static void test_canonical_json_insertion_order_independent(void)
{
    cJSON *o1 = cJSON_CreateObject();   /* {b:'2', a:'1'} */
    cJSON_AddStringToObject(o1, "b", "2");
    cJSON_AddStringToObject(o1, "a", "1");
    cJSON *o2 = cJSON_CreateObject();   /* {a:'1', b:'2'} */
    cJSON_AddStringToObject(o2, "a", "1");
    cJSON_AddStringToObject(o2, "b", "2");

    char *s1 = NULL, *s2 = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, canonical_json(o1, &s1));
    TEST_ASSERT_EQUAL_INT(BNS_OK, canonical_json(o2, &s2));
    TEST_ASSERT_EQUAL_STRING(s1, s2);
    TEST_ASSERT_EQUAL_STRING("{\"a\":\"1\",\"b\":\"2\"}", s1);

    free(s1); free(s2);
    cJSON_Delete(o1); cJSON_Delete(o2);
}

/* TS: 'computeRicardianHash is deterministic and changes when one prose byte
 * changes' */
static void test_ricardian_hash_deterministic_and_prose_sensitive(void)
{
    deployment_binding_t b; TEST_ASSERT_EQUAL_INT(BNS_OK, fix_charter_binding(&b));

    char *h1 = NULL, *h2 = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, compute_ricardian_hash(g_prose, &b, &h1));
    TEST_ASSERT_EQUAL_INT(BNS_OK, compute_ricardian_hash(g_prose, &b, &h2));
    TEST_ASSERT_EQUAL_STRING(h1, h2);
    TEST_ASSERT_EQUAL_INT(64, (int)strlen(h1));

    /* Edit one prose byte: first "100000" -> "100001". */
    char *edited = strdup(g_prose);
    TEST_ASSERT_NOT_NULL(edited);
    char *hit = strstr(edited, "100000");
    TEST_ASSERT_NOT_NULL(hit);
    hit[5] = '1';
    char *he = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, compute_ricardian_hash(edited, &b, &he));
    TEST_ASSERT_TRUE(strcmp(he, h1) != 0);

    free(h1); free(h2); free(he); free(edited);
    deployment_binding_free(&b);
}

/* TS: 'computeRicardianHash changes when the deployment binding changes' */
static void test_ricardian_hash_binding_sensitive(void)
{
    deployment_binding_t b; TEST_ASSERT_EQUAL_INT(BNS_OK, fix_charter_binding(&b));
    char *h1 = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, compute_ricardian_hash(g_prose, &b, &h1));

    deployment_binding_t b2; TEST_ASSERT_EQUAL_INT(BNS_OK, fix_charter_binding(&b2));
    free(b2.agent_pubkey);
    b2.agent_pubkey = strdup("02bb");
    char *h2 = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, compute_ricardian_hash(g_prose, &b2, &h2));
    TEST_ASSERT_TRUE(strcmp(h1, h2) != 0);

    free(h1); free(h2);
    deployment_binding_free(&b);
    deployment_binding_free(&b2);
}

/* TS: 'hash and signature operate on identical canonical bytes'
 * computeRicardianHash == sha256(canonicalContractBytes).toString('hex'). */
static void test_hash_over_canonical_bytes(void)
{
    deployment_binding_t b; TEST_ASSERT_EQUAL_INT(BNS_OK, fix_charter_binding(&b));

    byte_buf_t bytes; byte_buf_init(&bytes);
    TEST_ASSERT_EQUAL_INT(BNS_OK, canonical_contract_bytes(g_prose, &b, &bytes));

    uint8_t digest[BONSAI_SHA256_LEN];
    sha256(bytes.data, bytes.len, digest);
    char *via_bytes = hex_encode(digest, sizeof digest);
    TEST_ASSERT_NOT_NULL(via_bytes);

    char *rh = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, compute_ricardian_hash(g_prose, &b, &rh));
    TEST_ASSERT_EQUAL_STRING(via_bytes, rh);

    free(via_bytes); free(rh);
    byte_buf_free(&bytes);
    deployment_binding_free(&b);
}

/* ---- issuer signature (Theme A item 3) --------------------------------- */

/* TS: 'signs and verifies the canonical contract bytes' */
static void test_sign_and_verify(void)
{
    deployment_binding_t b; TEST_ASSERT_EQUAL_INT(BNS_OK, fix_charter_binding(&b));
    ecdsa_key_t *elder = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, tx_helper_key(TX_KEY_ELDER, &elder));
    ecdsa_pubkey_t *pub = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, ecdsa_key_derive_pubkey(elder, &pub));
    char *pub_hex = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, ecdsa_pubkey_to_hex(pub, &pub_hex));

    charter_signature_t sig; memset(&sig, 0, sizeof sig);
    TEST_ASSERT_EQUAL_INT(BNS_OK, sign_charter(g_prose, &b, elder, &sig));

    /* sig.algo == 'ECDSA-SHA256' */
    TEST_ASSERT_EQUAL_STRING(BONSAI_CHARTER_ALGO, sig.algo);
    /* sig.issuerPubKey == elder.publicKey */
    TEST_ASSERT_EQUAL_STRING(pub_hex, sig.issuer_pubkey);
    /* sig.ricardianHash == computeRicardianHash(prose, binding) */
    char *rh = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, compute_ricardian_hash(g_prose, &b, &rh));
    TEST_ASSERT_EQUAL_STRING(rh, sig.ricardian_hash);

    /* verifyCharterSignature(prose, sig) == { ok: true } */
    charter_verify_result_t r; memset(&r, 0, sizeof r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, verify_charter_signature(g_prose, &sig, &r));
    TEST_ASSERT_TRUE(r.ok);

    free(rh); free(pub_hex);
    ecdsa_pubkey_free(pub);
    ecdsa_key_free(elder);
    charter_signature_free(&sig);
    deployment_binding_free(&b);
}

/* TS: 'rejects when the prose is edited after signing' (ricardianHash mismatch) */
static void test_rejects_edited_prose(void)
{
    deployment_binding_t b; TEST_ASSERT_EQUAL_INT(BNS_OK, fix_charter_binding(&b));
    ecdsa_key_t *elder = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, tx_helper_key(TX_KEY_ELDER, &elder));

    charter_signature_t sig; memset(&sig, 0, sizeof sig);
    TEST_ASSERT_EQUAL_INT(BNS_OK, sign_charter(g_prose, &b, elder, &sig));

    char *tampered = strdup(g_prose);
    char *hit = strstr(tampered, "100000");
    TEST_ASSERT_NOT_NULL(hit);
    hit[5] = '1';

    charter_verify_result_t r; memset(&r, 0, sizeof r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, verify_charter_signature(tampered, &sig, &r));
    TEST_ASSERT_FALSE(r.ok);
    TEST_ASSERT_NOT_NULL(r.reason);
    TEST_ASSERT_NOT_NULL(strstr(r.reason, "ricardianHash mismatch"));

    free(tampered);
    ecdsa_key_free(elder);
    charter_signature_free(&sig);
    deployment_binding_free(&b);
}

/* TS: 'rejects tampered prose even when the self-asserted ricardianHash is
 * patched to match (ECDSA backstop)' — reaches the ECDSA layer: /does not verify/ */
static void test_rejects_tampered_prose_with_patched_hash(void)
{
    deployment_binding_t b; TEST_ASSERT_EQUAL_INT(BNS_OK, fix_charter_binding(&b));
    ecdsa_key_t *elder = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, tx_helper_key(TX_KEY_ELDER, &elder));

    charter_signature_t sig; memset(&sig, 0, sizeof sig);
    TEST_ASSERT_EQUAL_INT(BNS_OK, sign_charter(g_prose, &b, elder, &sig));

    char *tampered = strdup(g_prose);
    char *hit = strstr(tampered, "100000");
    TEST_ASSERT_NOT_NULL(hit);
    hit[5] = '1';

    /* Patch sig.ricardianHash to match the tampered prose so the quick
     * hash cross-check passes — the ECDSA layer must still catch it. */
    char *patched_rh = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, compute_ricardian_hash(tampered, &b, &patched_rh));
    free(sig.ricardian_hash);
    sig.ricardian_hash = patched_rh;

    charter_verify_result_t r; memset(&r, 0, sizeof r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, verify_charter_signature(tampered, &sig, &r));
    TEST_ASSERT_FALSE(r.ok);
    TEST_ASSERT_NOT_NULL(r.reason);
    TEST_ASSERT_NOT_NULL(strstr(r.reason, "does not verify"));

    free(tampered);
    ecdsa_key_free(elder);
    charter_signature_free(&sig);
    deployment_binding_free(&b);
}

/* TS: 'rejects when the binding in the sidecar is swapped' (hash no longer
 * matches the swapped binding -> ok=false) */
static void test_rejects_swapped_binding(void)
{
    deployment_binding_t b; TEST_ASSERT_EQUAL_INT(BNS_OK, fix_charter_binding(&b));
    ecdsa_key_t *elder = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, tx_helper_key(TX_KEY_ELDER, &elder));

    charter_signature_t sig; memset(&sig, 0, sizeof sig);
    TEST_ASSERT_EQUAL_INT(BNS_OK, sign_charter(g_prose, &b, elder, &sig));

    /* Swap the binding carried in the sidecar (agentPubKey -> '02ff'). */
    free(sig.binding.agent_pubkey);
    sig.binding.agent_pubkey = strdup("02ff");

    charter_verify_result_t r; memset(&r, 0, sizeof r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, verify_charter_signature(g_prose, &sig, &r));
    TEST_ASSERT_FALSE(r.ok);

    ecdsa_key_free(elder);
    charter_signature_free(&sig);
    deployment_binding_free(&b);
}

/* TS: 'rejects a signature from the wrong issuer key' — real issuer pubkey,
 * impostor's signature bytes -> /does not verify/ */
static void test_rejects_wrong_issuer_signature(void)
{
    deployment_binding_t b; TEST_ASSERT_EQUAL_INT(BNS_OK, fix_charter_binding(&b));
    ecdsa_key_t *elder = NULL, *impostor = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, tx_helper_key(TX_KEY_ELDER, &elder));
    TEST_ASSERT_EQUAL_INT(BNS_OK, tx_helper_key(TX_KEY_AGENT, &impostor));

    charter_signature_t sig; memset(&sig, 0, sizeof sig);
    TEST_ASSERT_EQUAL_INT(BNS_OK, sign_charter(g_prose, &b, elder, &sig));
    charter_signature_t imp; memset(&imp, 0, sizeof imp);
    TEST_ASSERT_EQUAL_INT(BNS_OK, sign_charter(g_prose, &b, impostor, &imp));

    /* Keep the real issuer pubkey but the impostor's signature bytes. */
    free(sig.signature);
    sig.signature = strdup(imp.signature);

    charter_verify_result_t r; memset(&r, 0, sizeof r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, verify_charter_signature(g_prose, &sig, &r));
    TEST_ASSERT_FALSE(r.ok);
    TEST_ASSERT_NOT_NULL(r.reason);
    TEST_ASSERT_NOT_NULL(strstr(r.reason, "does not verify"));

    ecdsa_key_free(elder);
    ecdsa_key_free(impostor);
    charter_signature_free(&sig);
    charter_signature_free(&imp);
    deployment_binding_free(&b);
}

int main(void)
{
    g_prose = read_file(FIX_CHARTER_PROSE_PATH, &g_prose_len);
    if (!g_prose) {
        fprintf(stderr, "FATAL: cannot read %s (run from chain_c root)\n",
                FIX_CHARTER_PROSE_PATH);
        return 2;
    }

    UNITY_BEGIN();
    RUN_TEST(test_parses_real_prose);
    RUN_TEST(test_strips_comments_and_fences);
    RUN_TEST(test_throws_block_absent);
    RUN_TEST(test_throws_missing_required);
    RUN_TEST(test_throws_unknown_param);
    RUN_TEST(test_throws_duplicate_param);
    RUN_TEST(test_throws_non_positive);
    RUN_TEST(test_throws_unparseable_line);
    RUN_TEST(test_assert_params_match_prose);
    RUN_TEST(test_canonical_json_insertion_order_independent);
    RUN_TEST(test_ricardian_hash_deterministic_and_prose_sensitive);
    RUN_TEST(test_ricardian_hash_binding_sensitive);
    RUN_TEST(test_hash_over_canonical_bytes);
    RUN_TEST(test_sign_and_verify);
    RUN_TEST(test_rejects_edited_prose);
    RUN_TEST(test_rejects_tampered_prose_with_patched_hash);
    RUN_TEST(test_rejects_swapped_binding);
    RUN_TEST(test_rejects_wrong_issuer_signature);
    int rc = UNITY_END();
    free(g_prose);
    return rc;
}
