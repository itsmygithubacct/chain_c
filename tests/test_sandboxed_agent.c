/*
 * test_sandboxed_agent.c — Unity port of
 *   chain/tests/priscilla/sandboxedAgent.test.ts
 *
 * Mirrors the KEY behaviors of the SandboxedAgent credential-containment seam:
 *   - allowed, in-budget action: effect runs, receipt produced, actionHash is the
 *     KEYED hash (64 hex, NOT the bare sha256(payload)), the enclave recomputes
 *     the same hash, and the single scoped egress fired exactly once;
 *   - out-of-scope action denied, NO effect;
 *   - a denied action leaves NO off-chain residue (no seal => no vault key =>
 *     recomputeActionHash absent);
 *   - over-per-call-cap denied (reason ~ per-call), NO effect;
 *   - rolling-window cap across actions (two 100-cost pass, third exceeds);
 *   - kill switch: revoke on-chain mid-flight -> next act denied (reason ~ revoked),
 *     NO effect;
 *   - dataset/model provenance carried through to the receipt commitment.
 *
 * Build+run directly (avoids the shared cmake race):
 *   gcc -std=c11 -D_GNU_SOURCE -Iinclude -Ithird_party/unity -Ithird_party/cJSON \
 *       -Ithird_party/ripemd160 -Ithird_party/mimc7_consts -Itests/helpers \
 *       tests/test_sandboxed_agent.c third_party/unity/unity.c \
 *       $(ls tests/helpers/[a-z]*.c) -Lbuild -lbonsai_chain \
 *       $(pkg-config --libs libsecp256k1 libcrypto libcurl) -lm -lpthread \
 *       -o /tmp/test_sandboxed_agent && /tmp/test_sandboxed_agent
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
#include "common/hex.h"
#include "crypto/hash.h"
#include "broker/key_broker.h"
#include "broker/authorization_envelope.h"
#include "privacy/key_vault.h"
#include "privacy/enclave.h"
#include "provenance.h"
#include "sandbox/sandboxed_agent.h"

#define ID "genesis-identity-txid"

/* ---- FakeOracle: a settable on-chain revocation flag --------------------- */
typedef struct { bool revoked; } fake_oracle_ctx_t;
static int fake_is_revoked(void *ctx, const char *id, bool *out)
{
    (void)id;
    *out = ((fake_oracle_ctx_t *)ctx)->revoked;
    return BNS_OK;
}

/* broker clock pinned at 1000 (TS: now: () => 1_000) */
static int64_t broker_clock(void *u) { (void)u; return 1000; }

/* RecordingCapabilityProvider reply: returns the literal "provider-response"
 * (TS: new RecordingCapabilityProvider(() => 'provider-response')). */
static int reply_provider_response(void *user, const char *scope,
                                   const uint8_t *payload, size_t payload_len,
                                   void **out_result)
{
    (void)user; (void)scope; (void)payload; (void)payload_len;
    if (out_result) *out_result = (void *)"provider-response";
    return BNS_OK;
}

/* ---- assembled fixture (TS makeAgent) ----------------------------------- */
typedef struct {
    fake_oracle_ctx_t        oc;
    revocation_oracle_t      oracle;
    authorization_envelope_t env;
    key_broker_t            *broker;
    issued_key_t             key;
    char                    *secret;
    key_vault_t              vault;
    private_enclave_t       *enclave;
    capability_provider_t    caps;
    sandboxed_agent_t       *agent;
} agent_fixture_t;

static void fixture_make(agent_fixture_t *fx)
{
    memset(fx, 0, sizeof *fx);
    fx->oc.revoked = false;
    fx->oracle.ctx = &fx->oc;
    fx->oracle.is_revoked = fake_is_revoked;

    /* PARAMS { perTxLimit:100n, dailyLimit:250n, windowDuration:86_400n } */
    identity_params_t ip = { .per_tx_limit = 100, .daily_limit = 250, .window_duration = 86400 };
    const char *scopes[] = { "api:llm:chat" };
    TEST_ASSERT_EQUAL_INT(BNS_OK, envelope_from_identity(&ip, scopes, 1, &fx->env));

    TEST_ASSERT_EQUAL_INT(BNS_OK, key_broker_new(&fx->oracle, broker_clock, NULL, &fx->broker));

    /* broker.issue({ agentPubKey:'02aa', ricardianHash:'cd'*32, identityId:ID,
     *                envelope: envelopeFromIdentity(PARAMS, ['api:llm:chat']) }) */
    key_broker_issue_args_t ia = {
        .agent_pub_key  = "02aa",
        .ricardian_hash = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        .identity_id    = ID,
        .envelope       = &fx->env,
    };
    TEST_ASSERT_EQUAL_INT(BNS_OK, key_broker_issue(fx->broker, &ia, &fx->key, &fx->secret));
    TEST_ASSERT_NOT_NULL(fx->secret);

    TEST_ASSERT_EQUAL_INT(BNS_OK, in_memory_key_vault_new(&fx->vault));
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_new(&fx->vault, NULL, NULL, &fx->enclave));

    TEST_ASSERT_EQUAL_INT(BNS_OK,
        recording_capability_provider_new(reply_provider_response, NULL, &fx->caps));

    TEST_ASSERT_EQUAL_INT(BNS_OK,
        sandboxed_agent_new(fx->secret, fx->broker, fx->enclave, ID, &fx->caps, &fx->agent));
}

static void fixture_free(agent_fixture_t *fx)
{
    sandboxed_agent_free(fx->agent);
    recording_capability_provider_free(&fx->caps);
    private_enclave_free(fx->enclave);
    in_memory_key_vault_free(&fx->vault);
    free(fx->secret);
    issued_key_free(&fx->key);
    key_broker_free(fx->broker);
    authorization_envelope_free(&fx->env);
    memset(fx, 0, sizeof *fx);
}

/* count recorded egress calls */
static size_t caps_call_count(const agent_fixture_t *fx)
{
    const recording_call_t *calls = NULL; size_t n = 0;
    recording_capability_provider_calls(&fx->caps, &calls, &n);
    return n;
}

/* helper: act() over a string payload (UTF-8 = the raw chars) */
static int act_str(agent_fixture_t *fx, const char *scope, int64_t amount,
                   const char *payload, const provenance_record_t *prov,
                   agent_action_result_t *out)
{
    agent_action_request_t req = {
        .scope       = scope,
        .amount      = amount,
        .payload     = (const uint8_t *)payload,
        .payload_len = strlen(payload),
        .provenance  = prov,
    };
    return sandboxed_agent_act(fx->agent, &req, out);
}

void setUp(void) {}
void tearDown(void) {}

/* allows an in-scope, in-budget action: effect runs, receipt produced. */
static void test_allowed_in_budget(void)
{
    agent_fixture_t fx; fixture_make(&fx);

    agent_action_result_t r; memset(&r, 0, sizeof r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, act_str(&fx, "api:llm:chat", 50, "prompt", NULL, &r));
    TEST_ASSERT_TRUE(r.allowed);
    /* provider return value surfaces through result */
    TEST_ASSERT_NOT_NULL(r.result);
    TEST_ASSERT_EQUAL_STRING("provider-response", (const char *)r.result);

    /* actionHash: 64 hex, and NOT the bare sha256("prompt") */
    TEST_ASSERT_NOT_NULL(r.action_hash);
    TEST_ASSERT_EQUAL_UINT(64, strlen(r.action_hash));

    uint8_t bare_raw[BONSAI_SHA256_LEN];
    char bare[2 * BONSAI_SHA256_LEN + 1];
    sha256((const uint8_t *)"prompt", 6, bare_raw);
    TEST_ASSERT_EQUAL_INT(BNS_OK, hex_encode_to(bare_raw, sizeof bare_raw, bare, sizeof bare));
    TEST_ASSERT_TRUE_MESSAGE(strcmp(r.action_hash, bare) != 0,
        "actionHash must be the KEYED hash, not bare sha256(payload)");

    /* the enclave that sealed it recomputes the same keyed hash */
    char *recomputed = NULL; bool found = false;
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_recompute_action_hash(
        fx.enclave, ID, (const uint8_t *)"prompt", 6, &recomputed, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_NOT_NULL(recomputed);
    TEST_ASSERT_EQUAL_STRING(r.action_hash, recomputed);
    free(recomputed);

    /* the effect went through the single scoped egress exactly once */
    const recording_call_t *calls = NULL; size_t n = 0;
    recording_capability_provider_calls(&fx.caps, &calls, &n);
    TEST_ASSERT_EQUAL_UINT(1, n);
    TEST_ASSERT_EQUAL_STRING("api:llm:chat", calls[0].scope);
    TEST_ASSERT_EQUAL_STRING("prompt", calls[0].payload_utf8);

    agent_action_result_free(&r);
    fixture_free(&fx);
}

/* denies an out-of-scope action and runs NO effect. */
static void test_out_of_scope_denied(void)
{
    agent_fixture_t fx; fixture_make(&fx);

    agent_action_result_t r; memset(&r, 0, sizeof r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, act_str(&fx, "repo:write:acme/secrets", 1, "x", NULL, &r));
    TEST_ASSERT_FALSE(r.allowed);
    TEST_ASSERT_NOT_NULL(r.reason);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(r.reason, "scope"),
        "deny reason must mention scope");
    TEST_ASSERT_EQUAL_UINT(0, caps_call_count(&fx)); /* never reached the egress */

    agent_action_result_free(&r);
    fixture_free(&fx);
}

/* a denied action leaves NO off-chain residue (the seal step never runs):
 * no record handed back AND no per-identity vault key (recompute => not found). */
static void test_denied_no_residue(void)
{
    agent_fixture_t fx; fixture_make(&fx);

    agent_action_result_t r; memset(&r, 0, sizeof r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, act_str(&fx, "repo:write:acme/secrets", 1, "secret", NULL, &r));
    TEST_ASSERT_FALSE(r.allowed);
    TEST_ASSERT_FALSE(r.has_sealed);                 /* no SealedRecord */
    TEST_ASSERT_NULL(r.action_hash);

    /* no key in the vault for ID => recompute reports absent (no seal ran) */
    char *recomputed = NULL; bool found = true;
    TEST_ASSERT_EQUAL_INT(BNS_OK, private_enclave_recompute_action_hash(
        fx.enclave, ID, (const uint8_t *)"secret", 6, &recomputed, &found));
    TEST_ASSERT_FALSE_MESSAGE(found, "a never-authorised action must create no enclave key");
    TEST_ASSERT_NULL(recomputed);

    agent_action_result_free(&r);
    fixture_free(&fx);
}

/* denies an over-per-call-cap action and runs NO effect (amount 101 > perCall 100). */
static void test_over_per_call_denied(void)
{
    agent_fixture_t fx; fixture_make(&fx);

    agent_action_result_t r; memset(&r, 0, sizeof r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, act_str(&fx, "api:llm:chat", 101, "x", NULL, &r));
    TEST_ASSERT_FALSE(r.allowed);
    TEST_ASSERT_NOT_NULL(r.reason);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(r.reason, "per-call"),
        "deny reason must mention per-call");
    TEST_ASSERT_EQUAL_UINT(0, caps_call_count(&fx));

    agent_action_result_free(&r);
    fixture_free(&fx);
}

/* enforces the rolling-window cap across multiple actions:
 * perWindow=250; three 100-cost calls -> first two pass, third exceeds. */
static void test_rolling_window_cap(void)
{
    agent_fixture_t fx; fixture_make(&fx);

    agent_action_result_t r1, r2, r3;
    memset(&r1, 0, sizeof r1); memset(&r2, 0, sizeof r2); memset(&r3, 0, sizeof r3);

    TEST_ASSERT_EQUAL_INT(BNS_OK, act_str(&fx, "api:llm:chat", 100, "a", NULL, &r1));
    TEST_ASSERT_TRUE(r1.allowed);
    TEST_ASSERT_EQUAL_INT(BNS_OK, act_str(&fx, "api:llm:chat", 100, "b", NULL, &r2));
    TEST_ASSERT_TRUE(r2.allowed);
    TEST_ASSERT_EQUAL_INT(BNS_OK, act_str(&fx, "api:llm:chat", 100, "c", NULL, &r3));
    TEST_ASSERT_FALSE(r3.allowed);
    TEST_ASSERT_NOT_NULL(r3.reason);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(r3.reason, "window"),
        "third deny reason must mention window");

    /* only the allowed two reached the egress, payloads 'a' then 'b' */
    const recording_call_t *calls = NULL; size_t n = 0;
    recording_capability_provider_calls(&fx.caps, &calls, &n);
    TEST_ASSERT_EQUAL_UINT(2, n);
    TEST_ASSERT_EQUAL_STRING("a", calls[0].payload_utf8);
    TEST_ASSERT_EQUAL_STRING("b", calls[1].payload_utf8);

    agent_action_result_free(&r1);
    agent_action_result_free(&r2);
    agent_action_result_free(&r3);
    fixture_free(&fx);
}

/* denies after the identity is revoked on-chain (kill switch) and runs NO effect. */
static void test_revocation_kill_switch(void)
{
    agent_fixture_t fx; fixture_make(&fx);

    agent_action_result_t r1, r2;
    memset(&r1, 0, sizeof r1); memset(&r2, 0, sizeof r2);

    TEST_ASSERT_EQUAL_INT(BNS_OK, act_str(&fx, "api:llm:chat", 10, "a", NULL, &r1));
    TEST_ASSERT_TRUE(r1.allowed);

    /* the Elder dissolves the identity on-chain */
    fx.oc.revoked = true;

    TEST_ASSERT_EQUAL_INT(BNS_OK, act_str(&fx, "api:llm:chat", 10, "b", NULL, &r2));
    TEST_ASSERT_FALSE(r2.allowed);
    TEST_ASSERT_NOT_NULL(r2.reason);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(r2.reason, "revoked"),
        "deny reason must mention revoked");

    /* 'b' never reached the egress: only 'a' recorded */
    const recording_call_t *calls = NULL; size_t n = 0;
    recording_capability_provider_calls(&fx.caps, &calls, &n);
    TEST_ASSERT_EQUAL_UINT(1, n);
    TEST_ASSERT_EQUAL_STRING("a", calls[0].payload_utf8);

    agent_action_result_free(&r1);
    agent_action_result_free(&r2);
    fixture_free(&fx);
}

/* carries dataset/model provenance through to the receipt commitment. */
static void test_provenance_carried(void)
{
    agent_fixture_t fx; fixture_make(&fx);

    provenance_record_t prov = {
        .dataset_id  = "ds",
        .model_id    = "agent-fable-5",
        .version     = "2026-01",
        .licence_tag = "CC-BY-4.0",
    };
    agent_action_result_t r; memset(&r, 0, sizeof r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, act_str(&fx, "api:llm:chat", 10, "summarise", &prov, &r));
    TEST_ASSERT_TRUE(r.allowed);

    /* provenanceHash: 64 hex, NOT the all-zero sentinel */
    TEST_ASSERT_NOT_NULL(r.provenance_hash);
    TEST_ASSERT_EQUAL_UINT(64, strlen(r.provenance_hash));
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, strcmp(r.provenance_hash, BONSAI_ZERO_PROVENANCE),
        "provenanceHash must not be the zero sentinel when provenance supplied");

    /* the sealed record carries the modelId through */
    TEST_ASSERT_TRUE(r.has_sealed);
    TEST_ASSERT_TRUE(r.sealed.has_provenance);
    TEST_ASSERT_EQUAL_STRING("agent-fable-5", r.sealed.provenance.model_id);

    agent_action_result_free(&r);
    fixture_free(&fx);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_allowed_in_budget);
    RUN_TEST(test_out_of_scope_denied);
    RUN_TEST(test_denied_no_residue);
    RUN_TEST(test_over_per_call_denied);
    RUN_TEST(test_rolling_window_cap);
    RUN_TEST(test_revocation_kill_switch);
    RUN_TEST(test_provenance_carried);
    return UNITY_END();
}
