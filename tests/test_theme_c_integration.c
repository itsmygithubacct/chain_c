/*
 * test_theme_c_integration.c — Unity port of
 * chain/tests/priscilla/themeCIntegration.test.ts ("Theme C — wire the islands":
 * broker<->chain, enclave->receipt, indexer<->shred).
 *
 * Stubs (the C analogues of the TS FakeOracle / FakeView classes) are tiny
 * file-static vtables; the rest drives the real public C API:
 *   - key_broker_issue_from_chain + key_broker_authorize (broker<->chain binding)
 *   - verify_identity_script_on_chain (verify-on-read)
 *   - private_enclave_seal_action / recompute / shred (keyed action commitment)
 *   - shred_marker_hex / private_enclave_shred_marker / annotate_erasure /
 *     is_shred_marker_for (indexer<->shred recognition)
 *
 * Build+run directly:
 *   gcc -std=c11 -D_GNU_SOURCE -Iinclude -Ithird_party/unity -Ithird_party/cJSON
 *       -Ithird_party/ripemd160 -Ithird_party/mimc7_consts -Itests/helpers
 *       tests/test_theme_c_integration.c third_party/unity/unity.c
 *       tests/helpers (all .c) -Lbuild -lbonsai_chain
 *       $(pkg-config --libs libsecp256k1 libcrypto libcurl) -lm -lpthread
 *       -o /tmp/test_theme_c_integration  then run /tmp/test_theme_c_integration
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "unity.h"

#include "common/error.h"
#include "common/hex.h"
#include "crypto/hash.h"
#include "broker/key_broker.h"
#include "broker/identity_chain_view.h"
#include "broker/authorization_envelope.h"
#include "privacy/enclave.h"
#include "privacy/key_vault.h"
#include "reputation_indexer.h"

/* ---- test constants (mirror the TS literals) ---------------------------- */

#define ID       "genesis-txid-abc"
/* AGENT_PK = '02' + 'aa'*32 (33-byte compressed pubkey) */
#define AGENT_PK "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
/* RH = 'cd'*32 (32-byte ricardianHash) */
#define RH       "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
/* SCRIPT = '5101' + '21' + AGENT_PK + '20' + RH + '6a' — embeds both @props. */
#define SCRIPT   "5101" "21" AGENT_PK "20" RH "6a"

void setUp(void) {}
void tearDown(void) {}

/* ----------------------------------------------------------------------------
 * FakeOracle — RevocationOracle stub (TS: class FakeOracle)
 * ------------------------------------------------------------------------- */
typedef struct {
    bool revoked;   /* whether ID is revoked */
    bool throw_it;  /* simulate chain unavailable */
} fake_oracle_t;

static int fake_oracle_is_revoked(void *ctx, const char *identity_id,
                                  bool *out_revoked)
{
    (void)identity_id;
    fake_oracle_t *o = (fake_oracle_t *)ctx;
    if (o->throw_it) return BNS_ENET;          /* 'chain unavailable' */
    *out_revoked = o->revoked;
    return BNS_OK;
}

static revocation_oracle_t make_oracle(fake_oracle_t *o)
{
    revocation_oracle_t v = {0};
    v.ctx = o;
    v.is_revoked = fake_oracle_is_revoked;
    return v;
}

/* ----------------------------------------------------------------------------
 * FakeView — IdentityChainView stub (TS: class FakeView)
 * ------------------------------------------------------------------------- */
typedef struct {
    const char *script_hex;  /* NULL => 'cannot fetch script' */
    bool        throw_it;    /* error => 'cannot fetch script' */
} fake_view_t;

static int fake_view_get_script(void *ctx, const char *genesis_txid,
                                uint32_t vout, char **out_hex)
{
    (void)genesis_txid; (void)vout;
    fake_view_t *fv = (fake_view_t *)ctx;
    if (fv->throw_it || fv->script_hex == NULL) return BNS_ENET;
    char *dup = strdup(fv->script_hex);
    if (!dup) return BNS_ENOMEM;
    *out_hex = dup;
    return BNS_OK;
}

static identity_chain_view_t make_view(fake_view_t *fv)
{
    identity_chain_view_t v = {0};
    v.ctx = fv;
    v.get_identity_script_hex = fake_view_get_script;
    return v;
}

/* Build the canonical issueFromChain args (TS: ISSUE_ARGS) over caller-provided
 * pubkey/hash overrides (pass the defaults for the happy path). */
static key_broker_issue_from_chain_args_t make_args(const char *agent_pk,
                                                    const char *rh)
{
    static const char *scopes[] = { "api:llm:chat" };
    key_broker_issue_from_chain_args_t a = {0};
    a.identity_id                 = ID;
    a.identity_vout               = 0;
    a.expected_locking_script_hex = SCRIPT;
    a.agent_pub_key               = agent_pk;
    a.ricardian_hash              = rh;
    a.params.per_tx_limit         = 100;     /* perTxLimit  */
    a.params.daily_limit          = 250;     /* dailyLimit  */
    a.params.window_duration      = 86400;   /* windowDuration */
    a.scopes                      = scopes;
    a.num_scopes                  = 1;
    return a;
}

/* ============================================================================
 * KeyBroker.issueFromChain (reconstruct & byte-compare binding)
 * ========================================================================= */

/* TS: "mints a key when the on-chain script matches and derives the envelope
 * from params" — and the minted key is metered to the on-chain caps. */
static void test_issue_from_chain_mints_and_meters(void)
{
    fake_oracle_t o = {0};
    revocation_oracle_t oracle = make_oracle(&o);
    key_broker_t *broker = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, key_broker_new(&oracle, NULL, NULL, &broker));

    fake_view_t fv = { .script_hex = SCRIPT, .throw_it = false };
    identity_chain_view_t view = make_view(&fv);
    key_broker_issue_from_chain_args_t args = make_args(AGENT_PK, RH);

    issued_key_t key = {0};
    char *secret = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, key_broker_issue_from_chain(
        broker, &args, &view, &key, &secret, NULL, 0));
    TEST_ASSERT_NOT_NULL(secret);

    /* envelope derived from on-chain params */
    TEST_ASSERT_EQUAL_STRING(ID, key.identity_id);
    TEST_ASSERT_EQUAL_INT64(100, key.envelope.per_call);
    TEST_ASSERT_EQUAL_INT64(250, key.envelope.per_window);
    TEST_ASSERT_EQUAL_size_t(1, key.envelope.num_scopes);
    TEST_ASSERT_EQUAL_STRING("api:llm:chat", key.envelope.scopes[0]);

    /* the minted key works and is metered to the per-call cap */
    authorization_request_t ok_req = { .secret = secret, .scope = "api:llm:chat", .amount = 50 };
    authorization_decision_t dec = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK, key_broker_authorize(broker, &ok_req, &dec));
    TEST_ASSERT_TRUE(dec.allowed);

    authorization_request_t big_req = { .secret = secret, .scope = "api:llm:chat", .amount = 101 };
    memset(&dec, 0, sizeof dec);
    TEST_ASSERT_EQUAL_INT(BNS_OK, key_broker_authorize(broker, &big_req, &dec));
    TEST_ASSERT_FALSE(dec.allowed);   /* exceeds per-call limit */

    free(secret);
    issued_key_free(&key);
    key_broker_free(broker);
}

/* Helper: assert issueFromChain refuses (BNS_EBINDING) and capture the reason. */
static void assert_refuses(fake_oracle_t *o, fake_view_t *fv,
                           const char *agent_pk, const char *rh,
                           char *reason, size_t reason_sz)
{
    revocation_oracle_t oracle = make_oracle(o);
    identity_chain_view_t view = make_view(fv);
    key_broker_issue_from_chain_args_t args = make_args(agent_pk, rh);
    key_broker_t *broker = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, key_broker_new(&oracle, NULL, NULL, &broker));

    issued_key_t key = {0};
    char *secret = NULL;
    int rc = key_broker_issue_from_chain(broker, &args, &view, &key, &secret,
                                         reason, reason_sz);
    TEST_ASSERT_EQUAL_INT(BNS_EBINDING, rc);
    TEST_ASSERT_NULL(secret);
    key_broker_free(broker);
}

/* TS: "refuses (fail-closed) when the on-chain script does not match". */
static void test_issue_from_chain_refuses_script_mismatch(void)
{
    fake_oracle_t o = {0};
    fake_view_t fv = { .script_hex = "76a914" "0000000000000000000000000000000000000000" "88ac",
                       .throw_it = false };
    char reason[256] = {0};
    assert_refuses(&o, &fv, AGENT_PK, RH, reason, sizeof reason);
    TEST_ASSERT_NOT_NULL(strstr(reason, "does not match the expected"));
}

/* TS: "refuses (fail-closed) when the chain is unreachable". */
static void test_issue_from_chain_refuses_chain_unreachable(void)
{
    fake_oracle_t o = {0};
    fake_view_t fv = { .script_hex = NULL, .throw_it = true };
    char reason[256] = {0};
    assert_refuses(&o, &fv, AGENT_PK, RH, reason, sizeof reason);
    TEST_ASSERT_NOT_NULL(strstr(reason, "chain unreachable"));
}

/* TS: "refuses an identity that is revoked on-chain". */
static void test_issue_from_chain_refuses_revoked(void)
{
    fake_oracle_t o = { .revoked = true, .throw_it = false };
    fake_view_t fv = { .script_hex = SCRIPT, .throw_it = false };
    char reason[256] = {0};
    assert_refuses(&o, &fv, AGENT_PK, RH, reason, sizeof reason);
    TEST_ASSERT_NOT_NULL(strstr(reason, "revoked"));
}

/* TS: "refuses (fail-closed) when the revocation oracle throws". */
static void test_issue_from_chain_refuses_oracle_throws(void)
{
    fake_oracle_t o = { .revoked = false, .throw_it = true };
    fake_view_t fv = { .script_hex = SCRIPT, .throw_it = false };
    char reason[256] = {0};
    assert_refuses(&o, &fv, AGENT_PK, RH, reason, sizeof reason);
    TEST_ASSERT_NOT_NULL(strstr(reason, "revocation state unavailable"));
}

/* TS: "throws IdentityBindingError specifically" — the C analogue is the
 * dedicated BNS_EBINDING return code (a malformed script => refuse, not crash). */
static void test_issue_from_chain_binding_error_code(void)
{
    fake_oracle_t o = {0};
    fake_view_t fv = { .script_hex = "deadbeef", .throw_it = false };
    char reason[256] = {0};
    assert_refuses(&o, &fv, AGENT_PK, RH, reason, sizeof reason);
}

/* TS: "refuses when ricardianHash is absent from the verified script". The
 * script matches what the caller presented, but the minted ricardianHash is NOT
 * encoded in it. */
static void test_issue_from_chain_refuses_ricardian_divergence(void)
{
    fake_oracle_t o = {0};
    fake_view_t fv = { .script_hex = SCRIPT, .throw_it = false };
    char reason[256] = {0};
    const char *ff_rh = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    /* Note: expected_locking_script_hex is still SCRIPT (matches on-chain), so
     * the binding passes the script-match check; the divergence is the @prop. */
    assert_refuses(&o, &fv, AGENT_PK, ff_rh, reason, sizeof reason);
    TEST_ASSERT_NOT_NULL(strstr(reason, "ricardianHash is not present"));
}

/* TS: "refuses when agentPubKey is absent from the verified script". */
static void test_issue_from_chain_refuses_pubkey_divergence(void)
{
    fake_oracle_t o = {0};
    fake_view_t fv = { .script_hex = SCRIPT, .throw_it = false };
    char reason[256] = {0};
    const char *bb_pk = "02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    assert_refuses(&o, &fv, bb_pk, RH, reason, sizeof reason);
    TEST_ASSERT_NOT_NULL(strstr(reason, "agentPubKey is not present"));
}

/* ============================================================================
 * verifyIdentityScriptOnChain (Theme A item 5 — verify on read)
 * ========================================================================= */

static void test_verify_on_read_ok(void)
{
    fake_view_t fv = { .script_hex = SCRIPT, .throw_it = false };
    identity_chain_view_t view = make_view(&fv);
    bool ok = false;
    char reason[256] = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK, verify_identity_script_on_chain(
        &view, ID, 0, SCRIPT, &ok, reason, sizeof reason));
    TEST_ASSERT_TRUE(ok);
}

static void test_verify_on_read_case_insensitive(void)
{
    /* on-chain script is UPPERCASE; expected is lowercase SCRIPT */
    static char upper[sizeof(SCRIPT)];
    for (size_t i = 0; i < sizeof(SCRIPT); i++) {
        char c = SCRIPT[i];
        upper[i] = (c >= 'a' && c <= 'z') ? (char)(c - 32) : c;
    }
    fake_view_t fv = { .script_hex = upper, .throw_it = false };
    identity_chain_view_t view = make_view(&fv);
    bool ok = false;
    TEST_ASSERT_EQUAL_INT(BNS_OK, verify_identity_script_on_chain(
        &view, ID, 0, SCRIPT, &ok, NULL, 0));
    TEST_ASSERT_TRUE(ok);
}

static void test_verify_on_read_mismatch(void)
{
    fake_view_t fv = { .script_hex = "51", .throw_it = false };
    identity_chain_view_t view = make_view(&fv);
    bool ok = true;
    char reason[256] = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK, verify_identity_script_on_chain(
        &view, ID, 0, SCRIPT, &ok, reason, sizeof reason));
    TEST_ASSERT_FALSE(ok);
    TEST_ASSERT_NOT_NULL(strstr(reason, "does not match"));
}

static void test_verify_on_read_unreachable(void)
{
    fake_view_t fv = { .script_hex = NULL, .throw_it = true };
    identity_chain_view_t view = make_view(&fv);
    bool ok = true;
    char reason[256] = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK, verify_identity_script_on_chain(
        &view, ID, 0, SCRIPT, &ok, reason, sizeof reason));
    TEST_ASSERT_FALSE(ok);
    TEST_ASSERT_NOT_NULL(strstr(reason, "chain unreachable"));
}

/* ============================================================================
 * PrivateEnclave.sealAction (on-chain H(action) <- sealed payload)
 * ========================================================================= */

/* TS: "commits a KEYED, erasable actionHash an auditor recomputes" */
static void test_enclave_seal_action_keyed_and_erasable(void)
{
    key_vault_t vault;
    TEST_ASSERT_EQUAL_INT(BNS_OK, in_memory_key_vault_new(&vault));
    private_enclave_t *enc = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_new(&vault, NULL, NULL, &enc));

    const char *p = "call openai with prompt X";
    size_t plen = strlen(p);

    sealed_record_t sealed = {0};
    char *action_hash = NULL, *prov_hash = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_seal_action(
        enc, ID, (const uint8_t *)p, plen, NULL, &sealed,
        &action_hash, &prov_hash));
    TEST_ASSERT_NOT_NULL(action_hash);
    TEST_ASSERT_EQUAL_size_t(64, strlen(action_hash));

    /* NOT the bare sha256 of the plaintext (commitment is keyed). */
    uint8_t bare[BONSAI_SHA256_LEN];
    sha256((const uint8_t *)p, plen, bare);
    char *bare_hex = hex_encode(bare, sizeof bare);
    TEST_ASSERT_NOT_NULL(bare_hex);
    TEST_ASSERT_TRUE(strcmp(action_hash, bare_hex) != 0);
    free(bare_hex);

    /* auditor decrypts and recomputes -> matches */
    byte_buf_t opened; byte_buf_init(&opened);
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_open(enc, &sealed, &opened));
    TEST_ASSERT_EQUAL_size_t(plen, opened.len);
    TEST_ASSERT_EQUAL_MEMORY(p, opened.data, plen);

    char *recomputed = NULL; bool found = false;
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_recompute_action_hash(
        enc, ID, opened.data, opened.len, &recomputed, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_STRING(action_hash, recomputed);
    free(recomputed);
    byte_buf_free(&opened);

    /* after shred: payload gone (open => BNS_ESHREDDED) AND recompute => not found */
    bool had = false; char *marker = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_shred(enc, ID, &had, &marker));
    TEST_ASSERT_TRUE(had);
    free(marker);

    byte_buf_t after; byte_buf_init(&after);
    int rc = private_enclave_open(enc, &sealed, &after);
    TEST_ASSERT_EQUAL_INT(BNS_ESHREDDED, rc);
    byte_buf_free(&after);

    char *recomp2 = (char *)0x1; bool found2 = true;
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_recompute_action_hash(
        enc, ID, (const uint8_t *)p, plen, &recomp2, &found2));
    TEST_ASSERT_FALSE(found2);   /* TS: recompute returns null */

    free(action_hash);
    free(prov_hash);
    sealed_record_free(&sealed);
    private_enclave_free(enc);
    in_memory_key_vault_free(&vault);
}

/* TS: "the keyed actionHash differs across identities for the same payload" */
static void test_enclave_action_hash_differs_across_identities(void)
{
    key_vault_t vault;
    TEST_ASSERT_EQUAL_INT(BNS_OK, in_memory_key_vault_new(&vault));
    private_enclave_t *enc = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_new(&vault, NULL, NULL, &enc));

    const char *p = "identical action text";
    size_t plen = strlen(p);

    sealed_record_t sa = {0}, sb = {0};
    char *ha = NULL, *hb = NULL, *pa = NULL, *pb = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_seal_action(
        enc, "id-A", (const uint8_t *)p, plen, NULL, &sa, &ha, &pa));
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_seal_action(
        enc, "id-B", (const uint8_t *)p, plen, NULL, &sb, &hb, &pb));
    TEST_ASSERT_TRUE(strcmp(ha, hb) != 0);

    free(ha); free(hb); free(pa); free(pb);
    sealed_record_free(&sa); sealed_record_free(&sb);
    private_enclave_free(enc);
    in_memory_key_vault_free(&vault);
}

/* ============================================================================
 * indexer shred-marker recognition (data gone, receipt stands)
 * ========================================================================= */

/* TS: "shredMarkerHex matches PrivateEnclave.shredMarker" */
static void test_shred_marker_hex_matches_enclave(void)
{
    char *a = NULL, *b = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, shred_marker_hex(ID, &a));
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_shred_marker(ID, &b));
    TEST_ASSERT_EQUAL_STRING(a, b);
    free(a);
    free(b);
}

/* TS: "annotateErasure flags only the marker receipt and never invalidates" */
static void test_annotate_erasure_flags_only_marker(void)
{
    char *marker = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, shred_marker_hex(ID, &marker));

    tea_receipt_t items[3] = {0};
    strcpy(items[0].txid, "t1"); items[0].time = 100; items[0].valid = true;
    strcpy(items[0].receipt_hash, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    strcpy(items[1].txid, "t2"); items[1].time = 200; items[1].valid = true;
    strncpy(items[1].receipt_hash, marker, sizeof(items[1].receipt_hash) - 1);
    strcpy(items[2].txid, "t3"); items[2].time = 300; items[2].valid = true;
    strcpy(items[2].receipt_hash, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    tea_receipts_t receipts = { .items = items, .count = 3 };
    int64_t erased_at = -99;
    TEST_ASSERT_EQUAL_INT(BNS_OK, annotate_erasure(&receipts, ID, &erased_at));

    TEST_ASSERT_EQUAL_INT64(200, erased_at);
    TEST_ASSERT_FALSE(items[0].erased);
    TEST_ASSERT_TRUE(items[1].erased);
    TEST_ASSERT_FALSE(items[2].erased);
    /* erasure never invalidates: all still valid */
    TEST_ASSERT_TRUE(items[0].valid && items[1].valid && items[2].valid);

    TEST_ASSERT_TRUE(is_shred_marker_for(marker, ID));
    TEST_ASSERT_FALSE(is_shred_marker_for(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ID));

    free(marker);
}

int main(void)
{
    UNITY_BEGIN();
    /* broker<->chain binding */
    RUN_TEST(test_issue_from_chain_mints_and_meters);
    RUN_TEST(test_issue_from_chain_refuses_script_mismatch);
    RUN_TEST(test_issue_from_chain_refuses_chain_unreachable);
    RUN_TEST(test_issue_from_chain_refuses_revoked);
    RUN_TEST(test_issue_from_chain_refuses_oracle_throws);
    RUN_TEST(test_issue_from_chain_binding_error_code);
    RUN_TEST(test_issue_from_chain_refuses_ricardian_divergence);
    RUN_TEST(test_issue_from_chain_refuses_pubkey_divergence);
    /* verify-on-read */
    RUN_TEST(test_verify_on_read_ok);
    RUN_TEST(test_verify_on_read_case_insensitive);
    RUN_TEST(test_verify_on_read_mismatch);
    RUN_TEST(test_verify_on_read_unreachable);
    /* enclave keyed action commitment */
    RUN_TEST(test_enclave_seal_action_keyed_and_erasable);
    RUN_TEST(test_enclave_action_hash_differs_across_identities);
    /* indexer<->shred */
    RUN_TEST(test_shred_marker_hex_matches_enclave);
    RUN_TEST(test_annotate_erasure_flags_only_marker);
    return UNITY_END();
}
