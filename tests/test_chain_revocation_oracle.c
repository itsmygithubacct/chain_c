/*
 * test_chain_revocation_oracle.c — Unity port of
 * chain/tests/priscilla/chainRevocationOracle.test.ts.
 *
 * Exercises the on-chain kill switch: a forward-walk of the identity output-0
 * spend chain reports LIVE while every spend recreates the identity, REVOKED on
 * the first terminal (P2PKH-payout / no-output) spend; caches REVOKED
 * permanently, resumes LIVE walks from the cached tip without masking later
 * revocations, propagates chain failures (so the broker fails closed), enforces
 * maxHops, requires a spend index at construction, and end-to-end kills an
 * issued KeyBroker key.
 *
 * The TS MockChain is the shared mock_chain_source_t helper here.
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
#include "reputation_indexer.h"
#include "broker/chain_revocation_oracle.h"
#include "broker/key_broker.h"
#include "broker/authorization_envelope.h"
#include "mock_chain_source.h"

/* TS: const GENESIS = 'g'.repeat(64) */
#define GENESIS "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"

void setUp(void) {}
void tearDown(void) {}

/* Convenience: build oracle over a mock, return isRevoked verdict. */
static bool is_revoked(chain_revocation_oracle_t *o, const char *id)
{
    bool revoked = false;
    int rc = chain_revocation_oracle_is_revoked(o, id, &revoked);
    TEST_ASSERT_EQUAL_INT(BNS_OK, rc);
    return revoked;
}

/* TS: 'reports LIVE for an unspent genesis identity' */
static void test_live_unspent_genesis(void)
{
    mock_chain_source_t *m = mock_chain_source_new(0);
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_add_state_tx(m, GENESIS, NULL));
    chain_source_t src; TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_as_source(m, &src));
    chain_revocation_oracle_t *o;
    TEST_ASSERT_EQUAL_INT(BNS_OK, chain_revocation_oracle_new(&src, NULL, &o));

    TEST_ASSERT_FALSE(is_revoked(o, GENESIS));

    chain_revocation_oracle_free(o); mock_chain_source_free(m);
}

/* TS: 'reports LIVE while every spend recreates the identity at output 0' */
static void test_live_recreating_chain(void)
{
    mock_chain_source_t *m = mock_chain_source_new(0);
    mock_chain_source_add_state_tx(m, GENESIS, NULL);
    mock_chain_source_add_state_tx(m, "a1", NULL);
    mock_chain_source_add_state_tx(m, "a2", NULL);
    mock_chain_source_link(m, GENESIS, 0, "a1");
    mock_chain_source_link(m, "a1", 0, "a2");
    chain_source_t src; mock_chain_source_as_source(m, &src);
    chain_revocation_oracle_t *o;
    TEST_ASSERT_EQUAL_INT(BNS_OK, chain_revocation_oracle_new(&src, NULL, &o));

    TEST_ASSERT_FALSE(is_revoked(o, GENESIS));

    chain_revocation_oracle_free(o); mock_chain_source_free(m);
}

/* TS: 'reports REVOKED once a terminal (P2PKH-payout) spend ends the chain' */
static void test_revoked_on_terminal_spend(void)
{
    mock_chain_source_t *m = mock_chain_source_new(0);
    mock_chain_source_add_state_tx(m, GENESIS, NULL);
    mock_chain_source_add_state_tx(m, "a1", NULL);
    mock_chain_source_add_terminal_tx(m, "kill");
    mock_chain_source_link(m, GENESIS, 0, "a1");
    mock_chain_source_link(m, "a1", 0, "kill");
    chain_source_t src; mock_chain_source_as_source(m, &src);
    chain_revocation_oracle_t *o;
    TEST_ASSERT_EQUAL_INT(BNS_OK, chain_revocation_oracle_new(&src, NULL, &o));

    TEST_ASSERT_TRUE(is_revoked(o, GENESIS));

    chain_revocation_oracle_free(o); mock_chain_source_free(m);
}

/* TS: 'treats a spend with NO output 0 as terminal (REVOKED, fail-safe)' */
static void test_revoked_on_no_output_spend(void)
{
    mock_chain_source_t *m = mock_chain_source_new(0);
    mock_chain_source_add_state_tx(m, GENESIS, NULL);
    mock_chain_source_add_no_output_tx(m, "sweep");
    mock_chain_source_link(m, GENESIS, 0, "sweep");
    chain_source_t src; mock_chain_source_as_source(m, &src);
    chain_revocation_oracle_t *o;
    TEST_ASSERT_EQUAL_INT(BNS_OK, chain_revocation_oracle_new(&src, NULL, &o));

    TEST_ASSERT_TRUE(is_revoked(o, GENESIS));

    chain_revocation_oracle_free(o); mock_chain_source_free(m);
}

/* TS: 'caches REVOKED permanently — answers even if the chain source later fails' */
static void test_caches_revoked_permanently(void)
{
    mock_chain_source_t *m = mock_chain_source_new(0);
    mock_chain_source_add_state_tx(m, GENESIS, NULL);
    mock_chain_source_add_terminal_tx(m, "kill");
    mock_chain_source_link(m, GENESIS, 0, "kill");
    chain_source_t src; mock_chain_source_as_source(m, &src);
    chain_revocation_oracle_t *o;
    TEST_ASSERT_EQUAL_INT(BNS_OK, chain_revocation_oracle_new(&src, NULL, &o));

    TEST_ASSERT_TRUE(is_revoked(o, GENESIS));
    /* chain now fails on the next call — cached REVOKED must answer with no call */
    mock_chain_source_fail_next(m, true);
    TEST_ASSERT_TRUE(is_revoked(o, GENESIS));

    chain_revocation_oracle_free(o); mock_chain_source_free(m);
}

/* TS: 'resumes a LIVE walk from the last seen tip instead of re-walking'.
 * The second call starts at tip a1 (1 spend lookup), not genesis (2 lookups). */
static void test_resumes_from_cached_tip(void)
{
    mock_chain_source_t *m = mock_chain_source_new(0);
    mock_chain_source_add_state_tx(m, GENESIS, NULL);
    mock_chain_source_add_state_tx(m, "a1", NULL);
    mock_chain_source_link(m, GENESIS, 0, "a1");
    chain_source_t src; mock_chain_source_as_source(m, &src);
    chain_revocation_oracle_t *o;
    TEST_ASSERT_EQUAL_INT(BNS_OK, chain_revocation_oracle_new(&src, NULL, &o));

    TEST_ASSERT_FALSE(is_revoked(o, GENESIS));
    size_t spend_after_first = 0;
    mock_chain_source_calls(m, NULL, &spend_after_first, NULL);

    TEST_ASSERT_FALSE(is_revoked(o, GENESIS));
    size_t spend_after_second = 0;
    mock_chain_source_calls(m, NULL, &spend_after_second, NULL);
    /* exactly one additional spend lookup (a1->null), resuming from tip a1 */
    TEST_ASSERT_EQUAL_size_t(1, spend_after_second - spend_after_first);

    chain_revocation_oracle_free(o); mock_chain_source_free(m);
}

/* TS: 'resume does not mask a revocation that appears PAST the cached tip' */
static void test_resume_does_not_mask_later_revocation(void)
{
    mock_chain_source_t *m = mock_chain_source_new(0);
    mock_chain_source_add_state_tx(m, GENESIS, NULL);
    mock_chain_source_add_state_tx(m, "a1", NULL);
    mock_chain_source_link(m, GENESIS, 0, "a1");
    chain_source_t src; mock_chain_source_as_source(m, &src);
    chain_revocation_oracle_t *o;
    TEST_ASSERT_EQUAL_INT(BNS_OK, chain_revocation_oracle_new(&src, NULL, &o));

    TEST_ASSERT_FALSE(is_revoked(o, GENESIS)); /* caches tip = a1 */
    size_t spend_after_first = 0;
    mock_chain_source_calls(m, NULL, &spend_after_first, NULL);

    /* a1 now spent by a terminal payout */
    mock_chain_source_add_terminal_tx(m, "kill");
    mock_chain_source_link(m, "a1", 0, "kill");
    TEST_ASSERT_TRUE(is_revoked(o, GENESIS));
    size_t spend_after_second = 0;
    mock_chain_source_calls(m, NULL, &spend_after_second, NULL);
    /* resumed from a1 (one lookup a1->kill), not genesis (two) */
    TEST_ASSERT_EQUAL_size_t(1, spend_after_second - spend_after_first);

    chain_revocation_oracle_free(o); mock_chain_source_free(m);
}

/* TS: 'propagates chain failures (so the broker fails closed)'.
 * The C surface propagates as a non-BNS_OK error code rather than a thrown
 * message; assert the call returns BNS_ENET (the mock's fail injection). */
static void test_propagates_chain_failures(void)
{
    mock_chain_source_t *m = mock_chain_source_new(0);
    mock_chain_source_add_state_tx(m, GENESIS, NULL);
    mock_chain_source_fail_next(m, true);
    chain_source_t src; mock_chain_source_as_source(m, &src);
    chain_revocation_oracle_t *o;
    TEST_ASSERT_EQUAL_INT(BNS_OK, chain_revocation_oracle_new(&src, NULL, &o));

    bool revoked = false;
    int rc = chain_revocation_oracle_is_revoked(o, GENESIS, &revoked);
    TEST_ASSERT_NOT_EQUAL(BNS_OK, rc); /* error propagated (fail-closed upstream) */

    chain_revocation_oracle_free(o); mock_chain_source_free(m);
}

/* TS: 'throws when the walk exceeds maxHops'. A pathological loop (a2->a1) with
 * maxHops=5 must error with BNS_EHOPLIMIT (TS: /exceeded 5 hops/). */
static void test_throws_on_max_hops(void)
{
    mock_chain_source_t *m = mock_chain_source_new(0);
    mock_chain_source_add_state_tx(m, GENESIS, NULL);
    mock_chain_source_add_state_tx(m, "a1", NULL);
    mock_chain_source_add_state_tx(m, "a2", NULL);
    mock_chain_source_link(m, GENESIS, 0, "a1");
    mock_chain_source_link(m, "a1", 0, "a2");
    mock_chain_source_link(m, "a2", 0, "a1"); /* loop */
    chain_source_t src; mock_chain_source_as_source(m, &src);
    chain_revocation_oracle_opts_t opts = { 0 };
    opts.has_max_hops = true; opts.max_hops = 5;
    chain_revocation_oracle_t *o;
    TEST_ASSERT_EQUAL_INT(BNS_OK, chain_revocation_oracle_new(&src, &opts, &o));

    bool revoked = false;
    int rc = chain_revocation_oracle_is_revoked(o, GENESIS, &revoked);
    TEST_ASSERT_EQUAL_INT(BNS_EHOPLIMIT, rc);

    chain_revocation_oracle_free(o); mock_chain_source_free(m);
}

/* TS: 'rejects a ChainSource without a spend index at construction' (=> /getSpendingTxid/).
 * The C constructor returns BNS_EINVAL when get_spending_txid is NULL. */
static void test_rejects_source_without_spend_index(void)
{
    mock_chain_source_t *m = mock_chain_source_new(0);
    mock_chain_source_add_state_tx(m, GENESIS, NULL);
    chain_source_t src; mock_chain_source_as_source(m, &src);
    mock_chain_source_disable_spend_index(&src); /* NULL get_spending_txid */
    chain_revocation_oracle_t *o = NULL;
    int rc = chain_revocation_oracle_new(&src, NULL, &o);
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, rc);
    TEST_ASSERT_NULL(o);

    mock_chain_source_free(m);
}

/* TS: 'end-to-end: an on-chain revoke kills the issued key, fail-closed via the
 * broker'. Wire the oracle into a KeyBroker via the as_oracle vtable. */
static int64_t fixed_clock(void *u) { (void)u; return 1000; }

static void test_end_to_end_kill_via_broker(void)
{
    mock_chain_source_t *m = mock_chain_source_new(0);
    mock_chain_source_add_state_tx(m, GENESIS, NULL);
    chain_source_t src; mock_chain_source_as_source(m, &src);
    chain_revocation_oracle_t *o;
    TEST_ASSERT_EQUAL_INT(BNS_OK, chain_revocation_oracle_new(&src, NULL, &o));

    revocation_oracle_t vt;
    TEST_ASSERT_EQUAL_INT(BNS_OK, chain_revocation_oracle_as_oracle(o, &vt));

    key_broker_t *b;
    TEST_ASSERT_EQUAL_INT(BNS_OK, key_broker_new(&vt, fixed_clock, NULL, &b));

    identity_params_t params = { .per_tx_limit = 100, .daily_limit = 250,
                                 .window_duration = 86400 };
    const char *scopes[1] = { "api:llm:chat" };
    authorization_envelope_t env;
    TEST_ASSERT_EQUAL_INT(BNS_OK, envelope_from_identity(&params, scopes, 1, &env));

    key_broker_issue_args_t args = {
        .agent_pub_key  = "02aa",
        .ricardian_hash = "cafecafecafecafecafecafecafecafe"
                          "cafecafecafecafecafecafecafecafe",
        .identity_id    = GENESIS,
        .envelope       = &env,
    };
    issued_key_t key; char *secret;
    TEST_ASSERT_EQUAL_INT(BNS_OK, key_broker_issue(b, &args, &key, &secret));
    authorization_envelope_free(&env);

    /* live: the key works */
    authorization_request_t req = { .secret = secret, .scope = "api:llm:chat",
                                    .amount = 1 };
    authorization_decision_t before;
    TEST_ASSERT_EQUAL_INT(BNS_OK, key_broker_authorize(b, &req, &before));
    TEST_ASSERT_TRUE(before.allowed);

    /* the Elder revokes on-chain (terminal P2PKH spend) */
    mock_chain_source_add_terminal_tx(m, "kill");
    mock_chain_source_link(m, GENESIS, 0, "kill");

    authorization_decision_t after;
    TEST_ASSERT_EQUAL_INT(BNS_OK, key_broker_authorize(b, &req, &after));
    TEST_ASSERT_FALSE(after.allowed);
    TEST_ASSERT_NOT_NULL(strstr(after.reason, "revoked on-chain"));

    free(secret); issued_key_free(&key); key_broker_free(b);
    chain_revocation_oracle_free(o); mock_chain_source_free(m);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_live_unspent_genesis);
    RUN_TEST(test_live_recreating_chain);
    RUN_TEST(test_revoked_on_terminal_spend);
    RUN_TEST(test_revoked_on_no_output_spend);
    RUN_TEST(test_caches_revoked_permanently);
    RUN_TEST(test_resumes_from_cached_tip);
    RUN_TEST(test_resume_does_not_mask_later_revocation);
    RUN_TEST(test_propagates_chain_failures);
    RUN_TEST(test_throws_on_max_hops);
    RUN_TEST(test_rejects_source_without_spend_index);
    RUN_TEST(test_end_to_end_kill_via_broker);
    return UNITY_END();
}
