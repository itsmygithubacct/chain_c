/*
 * test_key_broker.c — Unity port of chain/tests/priscilla/keyBroker.test.ts.
 *
 * Mirrors the KeyBroker (Pillar B) behaviour: scope/budget authorisation, the
 * rolling-window cap metered against the BROKER's clock (never a caller-supplied
 * time), the on-chain revocation kill switch with local latching and fail-closed
 * behaviour, and the no-plaintext-secret / copy-on-getKey guarantees.
 *
 * The TS RevocationOracle is a FakeOracle (an in-memory revoked-set with a
 * one-shot throw); we reproduce it as a small revocation_oracle_t vtable below.
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
#include "broker/key_broker.h"
#include "broker/authorization_envelope.h"

/* ---- FakeOracle: a controllable revocation_oracle_t (TS FakeOracle) ------- */

typedef struct {
    const char *revoked_id;   /* the single id treated as revoked (NULL = none) */
    bool        throw_once;   /* one-shot: next is_revoked errors then clears   */
    size_t      call_count;   /* number of is_revoked invocations               */
} fake_oracle_t;

static int fake_is_revoked(void *ctx, const char *identity_id, bool *out_revoked)
{
    fake_oracle_t *f = (fake_oracle_t *)ctx;
    f->call_count++;
    if (f->throw_once) {
        f->throw_once = false;
        return BNS_ENET; /* TS: throw new Error('chain unavailable') */
    }
    *out_revoked = (f->revoked_id && identity_id &&
                    strcmp(f->revoked_id, identity_id) == 0);
    return BNS_OK;
}

static void fake_oracle_init(fake_oracle_t *f, revocation_oracle_t *vt)
{
    f->revoked_id = NULL;
    f->throw_once = false;
    f->call_count = 0;
    vt->ctx = f;
    vt->is_revoked = fake_is_revoked;
}

/* ---- test clock the TEST controls (TS `clock = { now }`) ------------------ */

static int64_t g_clock_now;
static int64_t test_clock(void *user) { (void)user; return g_clock_now; }

/* ---- shared issue() helper (TS issue()) ---------------------------------- */

/* Builds the envelope from the TS params + scopes, constructs a broker on the
 * test clock starting at now=1000, and issues a key for identity
 * 'genesis-txid-1'. Caller owns out_key (issued_key_free) + out_secret (free)
 * + must key_broker_free(*out_broker). */
static const char *SCOPE_CHAT = "api:llm:chat";
static const char *SCOPE_REPO = "repo:read:acme/widgets";

static void issue(fake_oracle_t *f, revocation_oracle_t *vt,
                  key_broker_t **out_broker, issued_key_t *out_key,
                  char **out_secret)
{
    fake_oracle_init(f, vt);

    identity_params_t params = { .per_tx_limit = 100, .daily_limit = 250,
                                 .window_duration = 86400 };
    const char *scopes[2] = { SCOPE_CHAT, SCOPE_REPO };
    authorization_envelope_t env;
    TEST_ASSERT_EQUAL_INT(BNS_OK, envelope_from_identity(&params, scopes, 2, &env));

    g_clock_now = 1000;
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        key_broker_new(vt, test_clock, NULL, out_broker));

    key_broker_issue_args_t args = {
        .agent_pub_key  = "02aa",
        .ricardian_hash = "cafecafecafecafecafecafecafecafe"
                          "cafecafecafecafecafecafecafecafe", /* 'cafe'*16 */
        .identity_id    = "genesis-txid-1",
        .envelope       = &env,
    };
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        key_broker_issue(*out_broker, &args, out_key, out_secret));

    authorization_envelope_free(&env);
}

static authorization_decision_t authorize(key_broker_t *b, const char *secret,
                                          const char *scope, int64_t amount)
{
    authorization_request_t req = { .secret = secret, .scope = scope,
                                    .amount = amount };
    authorization_decision_t d;
    TEST_ASSERT_EQUAL_INT(BNS_OK, key_broker_authorize(b, &req, &d));
    return d;
}

void setUp(void) {}
void tearDown(void) {}

/* ---- tests --------------------------------------------------------------- */

/* TS: 'authorises an in-scope, in-budget call' */
static void test_authorises_in_scope_in_budget(void)
{
    fake_oracle_t f; revocation_oracle_t vt;
    key_broker_t *b; issued_key_t key; char *secret;
    issue(&f, &vt, &b, &key, &secret);

    authorization_decision_t d = authorize(b, secret, SCOPE_CHAT, 40);
    TEST_ASSERT_TRUE(d.allowed);

    free(secret); issued_key_free(&key); key_broker_free(b);
}

/* TS: 'rejects an unknown secret' (reason ~ /unknown/, no keyId) */
static void test_rejects_unknown_secret(void)
{
    fake_oracle_t f; revocation_oracle_t vt;
    key_broker_t *b; issued_key_t key; char *secret;
    issue(&f, &vt, &b, &key, &secret);

    authorization_decision_t d = authorize(b, "pk_bogus", SCOPE_CHAT, 1);
    TEST_ASSERT_FALSE(d.allowed);
    TEST_ASSERT_NOT_NULL(d.reason);
    TEST_ASSERT_NOT_NULL(strstr(d.reason, "unknown"));
    TEST_ASSERT_FALSE(d.has_key_id); /* no keyId on the unknown-key branch */

    free(secret); issued_key_free(&key); key_broker_free(b);
}

/* TS: 'rejects an out-of-scope call' (reason ~ /scope/) */
static void test_rejects_out_of_scope(void)
{
    fake_oracle_t f; revocation_oracle_t vt;
    key_broker_t *b; issued_key_t key; char *secret;
    issue(&f, &vt, &b, &key, &secret);

    authorization_decision_t d = authorize(b, secret, "repo:write:acme/widgets", 1);
    TEST_ASSERT_FALSE(d.allowed);
    TEST_ASSERT_NOT_NULL(strstr(d.reason, "scope"));

    free(secret); issued_key_free(&key); key_broker_free(b);
}

/* TS: 'enforces the per-call cap' (amount 101 > perCall 100; reason ~ /per-call/) */
static void test_enforces_per_call_cap(void)
{
    fake_oracle_t f; revocation_oracle_t vt;
    key_broker_t *b; issued_key_t key; char *secret;
    issue(&f, &vt, &b, &key, &secret);

    authorization_decision_t d = authorize(b, secret, SCOPE_CHAT, 101);
    TEST_ASSERT_FALSE(d.allowed);
    TEST_ASSERT_NOT_NULL(strstr(d.reason, "per-call"));

    free(secret); issued_key_free(&key); key_broker_free(b);
}

/* TS: 'enforces the rolling-window cap across calls' (3*100 > 250; reason /window/) */
static void test_enforces_window_cap(void)
{
    fake_oracle_t f; revocation_oracle_t vt;
    key_broker_t *b; issued_key_t key; char *secret;
    issue(&f, &vt, &b, &key, &secret);

    authorization_decision_t d1 = authorize(b, secret, SCOPE_CHAT, 100);
    TEST_ASSERT_TRUE(d1.allowed);
    g_clock_now = 1001;
    authorization_decision_t d2 = authorize(b, secret, SCOPE_CHAT, 100);
    TEST_ASSERT_TRUE(d2.allowed);
    g_clock_now = 1002;
    authorization_decision_t d3 = authorize(b, secret, SCOPE_CHAT, 100);
    TEST_ASSERT_FALSE(d3.allowed); /* 300 > 250 */
    TEST_ASSERT_NOT_NULL(strstr(d3.reason, "window"));

    free(secret); issued_key_free(&key); key_broker_free(b);
}

/* TS: 'rolls the window forward after windowDuration (broker clock, not caller)' */
static void test_window_rolls_forward(void)
{
    fake_oracle_t f; revocation_oracle_t vt;
    key_broker_t *b; issued_key_t key; char *secret;
    issue(&f, &vt, &b, &key, &secret);

    TEST_ASSERT_TRUE(authorize(b, secret, SCOPE_CHAT, 100).allowed);
    g_clock_now = 1001;
    TEST_ASSERT_TRUE(authorize(b, secret, SCOPE_CHAT, 100).allowed);
    /* real time passes the full window: 1000 + 86400 -> budget resets */
    g_clock_now = 1000 + 86400;
    authorization_decision_t next = authorize(b, secret, SCOPE_CHAT, 100);
    TEST_ASSERT_TRUE(next.allowed);

    free(secret); issued_key_free(&key); key_broker_free(b);
}

/* TS: 'a capped-out agent cannot reset its own window (no caller-supplied time)'.
 * The C authorization_request_t carries NO timestamp at all (deliberately), so a
 * lying caller has no `now` field to set. We exercise the equivalent: after two
 * 100-charges in the same broker-window, a third is denied with /window/ even
 * though wall-clock-wise an attacker would claim the window rolled. The broker's
 * clock has NOT advanced, so it stays denied. */
static void test_agent_cannot_reset_window(void)
{
    fake_oracle_t f; revocation_oracle_t vt;
    key_broker_t *b; issued_key_t key; char *secret;
    issue(&f, &vt, &b, &key, &secret);

    TEST_ASSERT_TRUE(authorize(b, secret, SCOPE_CHAT, 100).allowed);
    TEST_ASSERT_TRUE(authorize(b, secret, SCOPE_CHAT, 100).allowed);
    /* broker clock unchanged (still 1000) — request type has no `now` to spoof. */
    authorization_decision_t d = authorize(b, secret, SCOPE_CHAT, 100);
    TEST_ASSERT_FALSE(d.allowed);
    TEST_ASSERT_NOT_NULL(strstr(d.reason, "window"));

    free(secret); issued_key_free(&key); key_broker_free(b);
}

/* TS: 'refuses a key whose identity was revoked on-chain (the kill switch)' */
static void test_refuses_revoked_identity(void)
{
    fake_oracle_t f; revocation_oracle_t vt;
    key_broker_t *b; issued_key_t key; char *secret;
    issue(&f, &vt, &b, &key, &secret);

    f.revoked_id = "genesis-txid-1";
    authorization_decision_t d = authorize(b, secret, SCOPE_CHAT, 1);
    TEST_ASSERT_FALSE(d.allowed);
    TEST_ASSERT_NOT_NULL(strstr(d.reason, "revoked"));

    free(secret); issued_key_free(&key); key_broker_free(b);
}

/* TS: 'checks on-chain revocation BEFORE scope/caps' — revoked must win over a
 * BOTH out-of-scope AND over-cap request (fail-closed order revocation->scope->caps). */
static void test_revocation_precedes_scope_and_caps(void)
{
    fake_oracle_t f; revocation_oracle_t vt;
    key_broker_t *b; issued_key_t key; char *secret;
    issue(&f, &vt, &b, &key, &secret);

    f.revoked_id = "genesis-txid-1";
    authorization_decision_t d = authorize(b, secret, "repo:write:acme/secrets", 9999);
    TEST_ASSERT_FALSE(d.allowed);
    TEST_ASSERT_NOT_NULL(strstr(d.reason, "revoked"));
    /* must not be masked by a later scope/per-call/window check */
    TEST_ASSERT_NULL(strstr(d.reason, "scope"));
    TEST_ASSERT_NULL(strstr(d.reason, "per-call"));
    TEST_ASSERT_NULL(strstr(d.reason, "window"));

    free(secret); issued_key_free(&key); key_broker_free(b);
}

/* TS: 'latches the kill switch locally: stays denied without re-consulting oracle'.
 * After the broker observes the on-chain revocation once (reason ~ /revoked
 * on-chain/), it mirrors it locally; a later call short-circuits at the LOCAL
 * check (reason ~ /key revoked/) WITHOUT calling the (now-throwing) oracle. */
static void test_kill_switch_latches_locally(void)
{
    fake_oracle_t f; revocation_oracle_t vt;
    key_broker_t *b; issued_key_t key; char *secret;
    issue(&f, &vt, &b, &key, &secret);

    f.revoked_id = "genesis-txid-1";
    authorization_decision_t first = authorize(b, secret, SCOPE_CHAT, 1);
    TEST_ASSERT_FALSE(first.allowed);
    TEST_ASSERT_NOT_NULL(strstr(first.reason, "revoked on-chain")); /* observed via oracle */

    /* oracle would now THROW and the on-chain flag is gone — local latch must
     * still deny WITHOUT consulting the oracle. */
    f.revoked_id = NULL;
    f.throw_once = true;
    size_t calls_before = f.call_count;
    authorization_decision_t second = authorize(b, secret, SCOPE_CHAT, 1);
    TEST_ASSERT_FALSE(second.allowed);
    TEST_ASSERT_NOT_NULL(strstr(second.reason, "key revoked")); /* LOCAL latch */
    TEST_ASSERT_NULL(strstr(second.reason, "fail-closed"));
    /* throw_once un-consumed => isRevoked was never called on the 2nd call */
    TEST_ASSERT_TRUE(f.throw_once);
    TEST_ASSERT_EQUAL_size_t(calls_before, f.call_count);

    free(secret); issued_key_free(&key); key_broker_free(b);
}

/* TS: 'fails closed when on-chain revocation state is unavailable' (reason /fail-closed/) */
static void test_fails_closed_when_oracle_unavailable(void)
{
    fake_oracle_t f; revocation_oracle_t vt;
    key_broker_t *b; issued_key_t key; char *secret;
    issue(&f, &vt, &b, &key, &secret);

    f.throw_once = true;
    authorization_decision_t d = authorize(b, secret, SCOPE_CHAT, 1);
    TEST_ASSERT_FALSE(d.allowed);
    TEST_ASSERT_NOT_NULL(strstr(d.reason, "fail-closed"));

    free(secret); issued_key_free(&key); key_broker_free(b);
}

/* TS: 'never stores the plaintext secret'. The public key view exposes no secret
 * material; the issued_key_t struct has no secret/secretHash field, so we assert
 * none of its owned strings equal the plaintext secret. */
static void test_never_stores_plaintext_secret(void)
{
    fake_oracle_t f; revocation_oracle_t vt;
    key_broker_t *b; issued_key_t key; char *secret;
    issue(&f, &vt, &b, &key, &secret);

    issued_key_t view; bool found = false;
    TEST_ASSERT_EQUAL_INT(BNS_OK, key_broker_get_key(b, key.key_id, &view, &found));
    TEST_ASSERT_TRUE(found);

    /* none of the view's string members may contain the plaintext secret */
    TEST_ASSERT_NOT_EQUAL(0, strcmp(view.key_id, secret));
    TEST_ASSERT_TRUE(strstr(secret, view.key_id) == NULL || view.key_id[0] == '\0');
    if (view.agent_pub_key) TEST_ASSERT_NULL(strstr(view.agent_pub_key, secret));
    if (view.ricardian_hash) TEST_ASSERT_NULL(strstr(view.ricardian_hash, secret));
    if (view.identity_id) TEST_ASSERT_NULL(strstr(view.identity_id, secret));

    issued_key_free(&view);
    free(secret); issued_key_free(&key); key_broker_free(b);
}

/* TS: 'getKey returns a copy — mutating it cannot widen the live envelope'.
 * We mutate the returned copy's envelope (add a scope, raise perCall) and prove
 * the live key still denies the newly-"added" scope. */
static void test_getkey_returns_copy(void)
{
    fake_oracle_t f; revocation_oracle_t vt;
    key_broker_t *b; issued_key_t key; char *secret;
    issue(&f, &vt, &b, &key, &secret);

    issued_key_t view; bool found = false;
    TEST_ASSERT_EQUAL_INT(BNS_OK, key_broker_get_key(b, key.key_id, &view, &found));
    TEST_ASSERT_TRUE(found);

    /* mutate the copy: widen perCall and try to inject a scope */
    view.envelope.per_call = 1000000;
    if (view.envelope.num_scopes > 0) {
        free(view.envelope.scopes[0]);
        view.envelope.scopes[0] = strdup("repo:write:acme/widgets");
    }

    /* the live key must still reject the injected scope */
    authorization_decision_t d = authorize(b, secret, "repo:write:acme/widgets", 1);
    TEST_ASSERT_FALSE(d.allowed);
    TEST_ASSERT_NOT_NULL(strstr(d.reason, "scope"));

    issued_key_free(&view);
    free(secret); issued_key_free(&key); key_broker_free(b);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_authorises_in_scope_in_budget);
    RUN_TEST(test_rejects_unknown_secret);
    RUN_TEST(test_rejects_out_of_scope);
    RUN_TEST(test_enforces_per_call_cap);
    RUN_TEST(test_enforces_window_cap);
    RUN_TEST(test_window_rolls_forward);
    RUN_TEST(test_agent_cannot_reset_window);
    RUN_TEST(test_refuses_revoked_identity);
    RUN_TEST(test_revocation_precedes_scope_and_caps);
    RUN_TEST(test_kill_switch_latches_locally);
    RUN_TEST(test_fails_closed_when_oracle_unavailable);
    RUN_TEST(test_never_stores_plaintext_secret);
    RUN_TEST(test_getkey_returns_copy);
    return UNITY_END();
}
