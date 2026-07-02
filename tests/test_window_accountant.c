/*
 * test_window_accountant.c — Unity port of
 *   chain/tests/priscilla/windowAccountant.test.ts
 *
 * Pins the off-chain rolling-window meter arithmetic (the broker's twin of the
 * contract-side metering): within-cap allow + window-state report, non-positive
 * reject, per-call reject, rolling accumulation/reject, the >= window-roll
 * boundary, and the "denied charge consumes no budget" invariant.
 *
 * Real API: include/broker/authorization_envelope.h
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>

#include "unity.h"
#include "common/error.h"
#include "broker/authorization_envelope.h"

/* TS: envelopeFromIdentity({perTxLimit:100, dailyLimit:250, windowDuration:86400}, []) */
static authorization_envelope_t g_env;

void setUp(void)
{
    identity_params_t params = {
        .per_tx_limit    = 100,
        .daily_limit     = 250,
        .window_duration = 86400,
    };
    int rc = envelope_from_identity(&params, NULL, 0, &g_env);
    TEST_ASSERT_EQUAL_INT(BNS_OK, rc);
}

void tearDown(void)
{
    authorization_envelope_free(&g_env);
}

/* it('allows a charge within caps and reports the window state') */
static void test_allows_within_caps_reports_state(void)
{
    window_accountant_t acc;
    window_accountant_init(&acc, &g_env);

    charge_result_t r;
    window_accountant_charge(&acc, 40, 1000, &r);

    TEST_ASSERT_TRUE(r.allowed);
    TEST_ASSERT_EQUAL_INT64(40, r.spent_in_window);
    TEST_ASSERT_EQUAL_INT64(1000, r.window_start);
}

/* it('rejects a non-positive amount') — reason matches /positive/ */
static void test_rejects_non_positive(void)
{
    window_accountant_t acc;
    window_accountant_init(&acc, &g_env);

    charge_result_t r;
    window_accountant_charge(&acc, 0, 1000, &r);

    TEST_ASSERT_FALSE(r.allowed);
    TEST_ASSERT_NOT_NULL(r.reason);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(r.reason, "positive"),
                                 "reason should mention 'positive'");
}

/* it('rejects over the per-call cap') — reason matches /per-call/ */
static void test_rejects_over_per_call(void)
{
    window_accountant_t acc;
    window_accountant_init(&acc, &g_env);

    charge_result_t r;
    window_accountant_charge(&acc, 101, 1000, &r);

    TEST_ASSERT_FALSE(r.allowed);
    TEST_ASSERT_NOT_NULL(r.reason);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(r.reason, "per-call"),
                                 "reason should mention 'per-call'");
}

/* it('accumulates within a window and rejects when rolling cap exceeded') */
static void test_accumulates_then_rejects_rolling(void)
{
    window_accountant_t acc;
    window_accountant_init(&acc, &g_env);

    charge_result_t r;
    window_accountant_charge(&acc, 100, 1000, &r); /* spent 100 */
    TEST_ASSERT_TRUE(r.allowed);
    window_accountant_charge(&acc, 100, 1001, &r); /* spent 200 */
    TEST_ASSERT_TRUE(r.allowed);

    window_accountant_charge(&acc, 100, 1002, &r); /* 300 > 250 */
    TEST_ASSERT_FALSE(r.allowed);
    TEST_ASSERT_NOT_NULL(r.reason);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(r.reason, "window"),
                                 "reason should mention 'window'");
}

/* it('resets the window at EXACTLY windowDuration elapsed (>= boundary)') */
static void test_window_reset_at_exact_boundary(void)
{
    window_accountant_t acc;
    window_accountant_init(&acc, &g_env);

    charge_result_t r;
    window_accountant_charge(&acc, 100, 1000, &r);  /* window opens at 1000 */
    window_accountant_charge(&acc, 100, 1001, &r);  /* spent 200 */

    /* now - windowStart == windowDuration exactly => reset, fresh budget */
    window_accountant_charge(&acc, 100, 1000 + 86400, &r);
    TEST_ASSERT_TRUE(r.allowed);
    TEST_ASSERT_EQUAL_INT64(100, r.spent_in_window);       /* prior 200 wiped */
    TEST_ASSERT_EQUAL_INT64(1000 + 86400, r.window_start);
}

/* it('a denied charge consumes no budget') */
static void test_denied_charge_no_budget_consumed(void)
{
    window_accountant_t acc;
    window_accountant_init(&acc, &g_env);

    charge_result_t r;
    window_accountant_charge(&acc, 100, 1000, &r); /* spent 100 */
    TEST_ASSERT_TRUE(r.allowed);
    window_accountant_charge(&acc, 100, 1001, &r); /* spent 200 */
    TEST_ASSERT_TRUE(r.allowed);
    window_accountant_charge(&acc, 100, 1002, &r); /* 300 > 250 -> denied */
    TEST_ASSERT_FALSE(r.allowed);

    /* denial must not have consumed budget: 200 + 50 = 250 fits */
    window_accountant_charge(&acc, 50, 1003, &r);
    TEST_ASSERT_TRUE(r.allowed);
    TEST_ASSERT_EQUAL_INT64(250, r.spent_in_window);

    int64_t spent = 0, start = 0;
    window_accountant_snapshot(&acc, &spent, &start);
    TEST_ASSERT_EQUAL_INT64(250, spent);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_allows_within_caps_reports_state);
    RUN_TEST(test_rejects_non_positive);
    RUN_TEST(test_rejects_over_per_call);
    RUN_TEST(test_accumulates_then_rejects_rolling);
    RUN_TEST(test_window_reset_at_exact_boundary);
    RUN_TEST(test_denied_charge_no_budget_consumed);
    return UNITY_END();
}
