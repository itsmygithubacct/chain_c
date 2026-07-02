/*
 * test_agent_tea_apply_action.c — Unity coverage for agent_tea_apply_action
 * (include/contracts_next/agent_tea.h, src/contracts_next/agent_tea.c).
 *
 * agent_tea_apply_action computes the POST-action @prop(true) state exactly as
 * the on-chain executeAction does, which the recreated output[0] state MUST match
 * or the contract's hashOutputs assertion fails. This file pins the pure
 * arithmetic (no scrypt VM needed — apply_action only reads c->state and the two
 * params it consults: windowDuration and graduationThreshold):
 *
 *   - window-roll boundary: now - windowStart == windowDuration RESETS
 *     spentInWindow (>= boundary, mirrors windowAccountant); one second under
 *     does NOT reset and the prior spend accumulates;
 *   - spentInWindow accumulation (spent += amount within a live window);
 *   - txCount increment (+1 every action);
 *   - tier graduation at graduationThreshold evaluated POST-increment (txCount
 *     reaching the threshold flips tier 1 -> 2; one under stays tier 1).
 *
 * No artifact / locking script is touched — apply_action is pure state math.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/bignum.h"
#include "contracts_next/agent_tea.h"

void setUp(void) {}
void tearDown(void) {}

/* parse decimal into a bn_t, fatal on failure */
static bn_t *bn_dec(const char *dec)
{
    bn_t *bn = NULL;
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, bn_parse_dec(dec, &bn), dec);
    TEST_ASSERT_NOT_NULL(bn);
    return bn;
}

/* assert a bn_t equals a decimal string */
static void assert_bn_eq(const bn_t *bn, const char *dec)
{
    char *s = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_to_dec(bn, &s));
    TEST_ASSERT_NOT_NULL(s);
    TEST_ASSERT_EQUAL_STRING(dec, s);
    free(s);
}

/* Build a minimal agent_tea_t carrying only the fields apply_action reads:
 * params.window_duration, params.graduation_threshold, and the 5 state ints.
 * No artifact needed. agent_tea_free releases everything (the unused bn_t* and
 * the empty byte_buf members are NULL/zeroed and freed safely). */
static void build_instance(agent_tea_t *c,
                           const char *window_duration,
                           const char *graduation_threshold,
                           const char *tx_count,
                           const char *spent_in_window,
                           const char *window_start,
                           const char *tier,
                           const char *recovery_count)
{
    memset(c, 0, sizeof *c);
    byte_buf_init(&c->params.owner);
    byte_buf_init(&c->params.agent);
    byte_buf_init(&c->params.ricardian_hash);

    c->params.window_duration      = bn_dec(window_duration);
    c->params.graduation_threshold = bn_dec(graduation_threshold);

    c->state.tx_count        = bn_dec(tx_count);
    c->state.spent_in_window = bn_dec(spent_in_window);
    c->state.window_start    = bn_dec(window_start);
    c->state.tier            = bn_dec(tier);
    c->state.recovery_count  = bn_dec(recovery_count);
}

/* ============================================================================
 * window-roll boundary (>= windowDuration resets spentInWindow + windowStart).
 * windowDuration=86400, windowStart=1000, spent=200, tier 1, txCount 0.
 * ========================================================================= */

/* now - windowStart == windowDuration EXACTLY => reset: fresh window, spent
 * starts at 0 then += amount; windowStart advances to now. */
static void test_window_roll_at_exact_boundary(void)
{
    agent_tea_t c;
    build_instance(&c, "86400", "3", "0", "200", "1000", "1", "0");

    bn_t *amount = bn_dec("100");
    agent_tea_state_t next; memset(&next, 0, sizeof next);
    /* now = 1000 + 86400 => delta == windowDuration => reset. */
    TEST_ASSERT_EQUAL_INT(BNS_OK, agent_tea_apply_action(&c, amount, 1000 + 86400, &next));

    assert_bn_eq(next.spent_in_window, "100");        /* prior 200 wiped, +100 */
    assert_bn_eq(next.window_start,    "87400");      /* advanced to now       */
    assert_bn_eq(next.tx_count,        "1");          /* +1                    */
    assert_bn_eq(next.tier,            "1");          /* 1 < threshold(3)      */

    agent_tea_state_free(&next);
    bn_free(amount);
    agent_tea_free(&c);
}

/* now - windowStart == windowDuration - 1 => NO reset: window holds, spend
 * accumulates onto the prior 200; windowStart unchanged. */
static void test_window_no_roll_one_second_under(void)
{
    agent_tea_t c;
    build_instance(&c, "86400", "3", "0", "200", "1000", "1", "0");

    bn_t *amount = bn_dec("100");
    agent_tea_state_t next; memset(&next, 0, sizeof next);
    /* now = 1000 + 86399 => delta == windowDuration - 1 => no reset. */
    TEST_ASSERT_EQUAL_INT(BNS_OK, agent_tea_apply_action(&c, amount, 1000 + 86399, &next));

    assert_bn_eq(next.spent_in_window, "300");        /* 200 + 100 accumulated */
    assert_bn_eq(next.window_start,    "1000");       /* unchanged             */
    assert_bn_eq(next.tx_count,        "1");

    agent_tea_state_free(&next);
    bn_free(amount);
    agent_tea_free(&c);
}

/* ============================================================================
 * spentInWindow accumulation across two in-window actions (apply twice by
 * carrying next-state forward, the resumable-lineage pattern).
 * ========================================================================= */
static void test_spent_accumulates_within_window(void)
{
    agent_tea_t c;
    build_instance(&c, "86400", "10", "0", "0", "1000", "1", "0");

    bn_t *a1 = bn_dec("40"), *a2 = bn_dec("25");
    agent_tea_state_t s1; memset(&s1, 0, sizeof s1);
    TEST_ASSERT_EQUAL_INT(BNS_OK, agent_tea_apply_action(&c, a1, 1001, &s1));
    assert_bn_eq(s1.spent_in_window, "40");
    assert_bn_eq(s1.tx_count,        "1");

    /* carry s1 forward as the new current state and apply a second action. */
    agent_tea_state_free(&c.state);
    c.state = s1;                              /* take ownership of s1 */

    agent_tea_state_t s2; memset(&s2, 0, sizeof s2);
    TEST_ASSERT_EQUAL_INT(BNS_OK, agent_tea_apply_action(&c, a2, 1002, &s2));
    assert_bn_eq(s2.spent_in_window, "65");    /* 40 + 25, same window */
    assert_bn_eq(s2.window_start,    "1000");  /* still the original window */
    assert_bn_eq(s2.tx_count,        "2");     /* incremented again */

    agent_tea_state_free(&s2);
    bn_free(a1); bn_free(a2);
    agent_tea_free(&c);                        /* frees c.state (== s1) */
}

/* ============================================================================
 * tier graduation at graduationThreshold, evaluated POST-increment.
 * ========================================================================= */

/* txCount goes 2 -> 3 with graduationThreshold=3: 3 >= 3 (post-increment) and
 * tier 1 < 2 => graduates to tier 2. */
static void test_tier_graduates_at_threshold_post_increment(void)
{
    agent_tea_t c;
    build_instance(&c, "86400", "3", "2", "0", "1000", "1", "0");

    bn_t *amount = bn_dec("10");
    agent_tea_state_t next; memset(&next, 0, sizeof next);
    TEST_ASSERT_EQUAL_INT(BNS_OK, agent_tea_apply_action(&c, amount, 1001, &next));

    assert_bn_eq(next.tx_count, "3");
    assert_bn_eq(next.tier,     "2");          /* graduated */

    agent_tea_state_free(&next);
    bn_free(amount);
    agent_tea_free(&c);
}

/* txCount goes 1 -> 2 with graduationThreshold=3: 2 < 3 post-increment => stays
 * tier 1 (the pre-increment txCount=2 would have met the threshold, so this pins
 * that graduation is keyed on the POST-increment count). */
static void test_tier_stays_one_under_threshold(void)
{
    agent_tea_t c;
    build_instance(&c, "86400", "3", "1", "0", "1000", "1", "0");

    bn_t *amount = bn_dec("10");
    agent_tea_state_t next; memset(&next, 0, sizeof next);
    TEST_ASSERT_EQUAL_INT(BNS_OK, agent_tea_apply_action(&c, amount, 1001, &next));

    assert_bn_eq(next.tx_count, "2");
    assert_bn_eq(next.tier,     "1");          /* not yet graduated */

    agent_tea_state_free(&next);
    bn_free(amount);
    agent_tea_free(&c);
}

/* An already-graduated tier (2) is never demoted, even if the txCount comparison
 * would re-trigger. */
static void test_tier_two_is_not_demoted(void)
{
    agent_tea_t c;
    build_instance(&c, "86400", "3", "9", "0", "1000", "2", "0");

    bn_t *amount = bn_dec("10");
    agent_tea_state_t next; memset(&next, 0, sizeof next);
    TEST_ASSERT_EQUAL_INT(BNS_OK, agent_tea_apply_action(&c, amount, 1001, &next));

    assert_bn_eq(next.tx_count, "10");
    assert_bn_eq(next.tier,     "2");          /* preserved */
    /* recoveryCount carried forward unchanged. */
    assert_bn_eq(next.recovery_count, "0");

    agent_tea_state_free(&next);
    bn_free(amount);
    agent_tea_free(&c);
}

/* NULL-arg guard returns BNS_EINVAL. */
static void test_null_args_rejected(void)
{
    agent_tea_t c;
    build_instance(&c, "86400", "3", "0", "0", "1000", "1", "0");
    bn_t *amount = bn_dec("10");
    agent_tea_state_t next; memset(&next, 0, sizeof next);

    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, agent_tea_apply_action(NULL, amount, 1, &next));
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, agent_tea_apply_action(&c, NULL, 1, &next));
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, agent_tea_apply_action(&c, amount, 1, NULL));

    bn_free(amount);
    agent_tea_free(&c);
}

/* ============================================================================ */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_window_roll_at_exact_boundary);
    RUN_TEST(test_window_no_roll_one_second_under);
    RUN_TEST(test_spent_accumulates_within_window);
    RUN_TEST(test_tier_graduates_at_threshold_post_increment);
    RUN_TEST(test_tier_stays_one_under_threshold);
    RUN_TEST(test_tier_two_is_not_demoted);
    RUN_TEST(test_null_args_rejected);
    return UNITY_END();
}
