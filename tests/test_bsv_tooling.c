/*
 * test_bsv_tooling.c — Unity port of
 *   chain/tests/priscilla/bsvTooling.test.ts
 *
 * Three subsystems, all pure (no network):
 *   - BSV fee arithmetic (bsv_fees.h): feeForSize rounding + negative guard, the
 *     send-time fee window reproduced from the live revoke saga, isFeeInSendWindow
 *     inclusive boundaries, needsFeeBump inclusive floor + custom floor, and
 *     cpfpChildFee package lift + dust floor.
 *   - UTXO ranking (utxo_select.h): confirmed-first / largest-first stable order,
 *     confirmedOnly filter, minSats dust filter, confirmed flag.
 *   - Tx status interpretation (woc_client.h interpret_tx_status): conf>=1 ->
 *     confirmed (boundary at exactly 1), missing blockheight -> null fallback,
 *     mempool and unknown cases.
 *
 * Real API: include/chainSources/bsv_fees.h, utxo_select.h, woc_client.h.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>
#include <stdio.h>

#include "unity.h"
#include "common/error.h"
#include "chainSources/bsv_fees.h"
#include "chainSources/utxo_select.h"
#include "chainSources/woc_client.h"

void setUp(void) {}
void tearDown(void) {}

/* ============================ BSV fee helpers ============================ */

/* it('feeForSize rounds up to whole sats') */
static void test_fee_for_size_rounds_up(void)
{
    int64_t fee = -1;
    TEST_ASSERT_EQUAL_INT(BNS_OK, fee_for_size(15268, 100, &fee));
    TEST_ASSERT_EQUAL_INT64(1527, fee); /* 15.268 KB * 100 */
    TEST_ASSERT_EQUAL_INT(BNS_OK, fee_for_size(1000, 100, &fee));
    TEST_ASSERT_EQUAL_INT64(100, fee);
    TEST_ASSERT_EQUAL_INT(BNS_OK, fee_for_size(1, 100, &fee));
    TEST_ASSERT_EQUAL_INT64(1, fee);
    TEST_ASSERT_EQUAL_INT(BNS_OK, fee_for_size(0, 100, &fee));
    TEST_ASSERT_EQUAL_INT64(0, fee);
}

/* it('feeForSize rejects negative inputs (defensive guard)') */
static void test_fee_for_size_rejects_negative(void)
{
    int64_t fee = 0;
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, fee_for_size(-1, 100, &fee));
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, fee_for_size(1000, -1, &fee));
}

/* it('reproduces the revoke send-time window exactly') */
static void test_send_time_fee_window(void)
{
    fee_window_t w;
    TEST_ASSERT_EQUAL_INT(BNS_OK, send_time_fee_window(15268, 100, &w));
    TEST_ASSERT_EQUAL_INT64(1527, w.min);
    TEST_ASSERT_EQUAL_INT64(4581, w.max); /* 3 * min */
    TEST_ASSERT_TRUE(w.recommended >= w.min && w.recommended <= w.max);
}

/* it('classifies the fees from the live saga correctly') */
static void test_is_fee_in_send_window_saga(void)
{
    const int64_t bytes = 15268;
    bool ok = false;
    TEST_ASSERT_EQUAL_INT(BNS_OK, is_fee_in_send_window(7000, bytes, 100, &ok));
    TEST_ASSERT_FALSE(ok);
    TEST_ASSERT_EQUAL_INT(BNS_OK, is_fee_in_send_window(2000, bytes, 100, &ok));
    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL_INT(BNS_OK, is_fee_in_send_window(500, bytes, 100, &ok));
    TEST_ASSERT_FALSE(ok);
    /* boundaries are inclusive */
    TEST_ASSERT_EQUAL_INT(BNS_OK, is_fee_in_send_window(1527, bytes, 100, &ok));
    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL_INT(BNS_OK, is_fee_in_send_window(4581, bytes, 100, &ok));
    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL_INT(BNS_OK, is_fee_in_send_window(4582, bytes, 100, &ok));
    TEST_ASSERT_FALSE(ok);
}

/* it('the recommended fee is always accepted by the window check') */
static void test_recommended_always_accepted(void)
{
    const int64_t bytes_cases[] = {200, 15268, 30833};
    const int64_t rate_cases[]  = {50, 100, 500};
    for (size_t i = 0; i < 3; i++) {
        for (size_t j = 0; j < 3; j++) {
            fee_window_t w;
            TEST_ASSERT_EQUAL_INT(BNS_OK,
                send_time_fee_window(bytes_cases[i], rate_cases[j], &w));
            bool ok = false;
            TEST_ASSERT_EQUAL_INT(BNS_OK,
                is_fee_in_send_window(w.recommended, bytes_cases[i], rate_cases[j], &ok));
            char msg[64];
            snprintf(msg, sizeof msg, "%lld@%lld",
                     (long long)bytes_cases[i], (long long)rate_cases[j]);
            TEST_ASSERT_TRUE_MESSAGE(ok, msg);
        }
    }
}

/* it('needsFeeBump flags the stuck low feerates') */
static void test_needs_fee_bump_flags_low(void)
{
    TEST_ASSERT_TRUE(needs_fee_bump(1, BONSAI_FEE_BUMP_FLOOR_DEFAULT));   /* ~1 sat/KB */
    TEST_ASSERT_FALSE(needs_fee_bump(100, BONSAI_FEE_BUMP_FLOOR_DEFAULT));
    TEST_ASSERT_FALSE(needs_fee_bump(500, BONSAI_FEE_BUMP_FLOOR_DEFAULT));
}

/* it('needsFeeBump treats the floor as the inclusive pass line and honors a custom floor') */
static void test_needs_fee_bump_floor_inclusive_and_custom(void)
{
    TEST_ASSERT_FALSE(needs_fee_bump(50, BONSAI_FEE_BUMP_FLOOR_DEFAULT)); /* exactly at default floor */
    TEST_ASSERT_TRUE(needs_fee_bump(49, BONSAI_FEE_BUMP_FLOOR_DEFAULT));  /* one below default floor */
    TEST_ASSERT_TRUE(needs_fee_bump(100, 120));  /* custom floor 120: 100 < 120 */
    TEST_ASSERT_FALSE(needs_fee_bump(120, 120)); /* custom floor 120: exactly at it */
}

/* it('cpfpChildFee lifts a package to the target feerate') */
static void test_cpfp_child_fee_lifts_package(void)
{
    int64_t fee = 0;
    /* parent 15268 B paid ~16 sats; child ~192 B; target 120 sats/KB */
    TEST_ASSERT_EQUAL_INT(BNS_OK, cpfp_child_fee(15268, 16, 192, 120, &fee));
    double pkg_feerate = ((double)(16 + fee) / (double)(15268 + 192)) * 1000.0;
    TEST_ASSERT_TRUE(pkg_feerate >= 120.0);
    TEST_ASSERT_TRUE(fee >= 546); /* never below dust-safe floor */
}

/* it('cpfpChildFee floors at dust when the parent already overpays the target') */
static void test_cpfp_child_fee_dust_floor(void)
{
    int64_t fee = 0;
    TEST_ASSERT_EQUAL_INT(BNS_OK, cpfp_child_fee(15268, 100000, 192, 120, &fee));
    TEST_ASSERT_EQUAL_INT64(546, fee);
}

/* ============================ UTXO ranking ============================ */

/* Mirrors the TS fixture:
 *   {a,0,100,h0}  unconfirmed big
 *   {b,1, 50,h900} confirmed small
 *   {c,0, 80,h901} confirmed bigger
 *   {d,2,500,h0}  unconfirmed biggest
 */
static void fill_fixture(woc_utxo_t u[4])
{
    memset(u, 0, sizeof(woc_utxo_t) * 4);
    strcpy(u[0].tx_hash, "a"); u[0].tx_pos = 0; u[0].value = 100; u[0].height = 0;
    strcpy(u[1].tx_hash, "b"); u[1].tx_pos = 1; u[1].value = 50;  u[1].height = 900;
    strcpy(u[2].tx_hash, "c"); u[2].tx_pos = 0; u[2].value = 80;  u[2].height = 901;
    strcpy(u[3].tx_hash, "d"); u[3].tx_pos = 2; u[3].value = 500; u[3].height = 0;
}

static void assert_order(const funding_utxos_t *f, const char *const *expect, size_t n)
{
    TEST_ASSERT_EQUAL_size_t(n, f->count);
    for (size_t i = 0; i < n; i++)
        TEST_ASSERT_EQUAL_STRING(expect[i], f->items[i].tx_id);
}

/* it('prefers confirmed UTXOs, then by descending value') */
static void test_rank_confirmed_first_then_value(void)
{
    woc_utxo_t u[4]; fill_fixture(u);
    funding_utxos_t f;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rank_funding_utxos(u, 4, NULL, &f));
    const char *exp[] = {"c", "b", "d", "a"};
    assert_order(&f, exp, 4);
    funding_utxos_free(&f);
}

/* it('confirmedOnly drops unconfirmed candidates') */
static void test_rank_confirmed_only(void)
{
    woc_utxo_t u[4]; fill_fixture(u);
    rank_opts_t opts = {0};
    opts.confirmed_only = true; opts.has_confirmed_only = true;
    funding_utxos_t f;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rank_funding_utxos(u, 4, &opts, &f));
    const char *exp[] = {"c", "b"};
    assert_order(&f, exp, 2);
    funding_utxos_free(&f);
}

/* it('minSats filters dust') */
static void test_rank_min_sats(void)
{
    woc_utxo_t u[4]; fill_fixture(u);
    rank_opts_t opts = {0};
    opts.min_sats = 90; opts.has_min_sats = true;
    funding_utxos_t f;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rank_funding_utxos(u, 4, &opts, &f));
    const char *exp[] = {"d", "a"}; /* only >=90, conf-first (both unconfirmed -> by value) */
    assert_order(&f, exp, 2);
    funding_utxos_free(&f);
}

/* it('marks the confirmed flag') */
static void test_rank_confirmed_flag(void)
{
    woc_utxo_t u[4]; fill_fixture(u);
    funding_utxos_t f;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rank_funding_utxos(u, 4, NULL, &f));
    bool found_c = false, found_a = false;
    for (size_t i = 0; i < f.count; i++) {
        if (strcmp(f.items[i].tx_id, "c") == 0) { found_c = true; TEST_ASSERT_TRUE(f.items[i].confirmed); }
        if (strcmp(f.items[i].tx_id, "a") == 0) { found_a = true; TEST_ASSERT_FALSE(f.items[i].confirmed); }
    }
    TEST_ASSERT_TRUE(found_c && found_a);
    funding_utxos_free(&f);
}

/* ======================= Tx status interpretation ======================= */

/* it('confirmations >= 1 -> confirmed (even if raw is absent)') */
static void test_interpret_confirmed_raw_absent(void)
{
    tx_status_t s;
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        interpret_tx_status(false, 3, 952937, true, &s));
    TEST_ASSERT_EQUAL_INT(TX_STATE_CONFIRMED, s.state);
    TEST_ASSERT_TRUE(s.has_block_height);
    TEST_ASSERT_EQUAL_INT64(952937, s.block_height);
}

/* it('recognizes confirmation at EXACTLY 1 conf, and tolerates a missing blockheight') */
static void test_interpret_boundary_one_conf_and_null_height(void)
{
    tx_status_t one;
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        interpret_tx_status(false, 1, 952940, true, &one));
    TEST_ASSERT_EQUAL_INT(TX_STATE_CONFIRMED, one.state);
    TEST_ASSERT_TRUE(one.has_block_height);
    TEST_ASSERT_EQUAL_INT64(952940, one.block_height);

    /* confirmed but no blockheight in body -> blockHeight falls back to null */
    tx_status_t no_height;
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        interpret_tx_status(true, 2, 0, false, &no_height));
    TEST_ASSERT_EQUAL_INT(TX_STATE_CONFIRMED, no_height.state);
    TEST_ASSERT_FALSE(no_height.has_block_height); /* TS blockHeight === null */
}

/* it('raw present + no confirmations -> mempool (the /tx/hash-404 case)') */
static void test_interpret_mempool(void)
{
    tx_status_t s;
    /* TS interpretTxStatus(true, null): no hash body -> confirmations 0 */
    TEST_ASSERT_EQUAL_INT(BNS_OK, interpret_tx_status(true, 0, 0, false, &s));
    TEST_ASSERT_EQUAL_INT(TX_STATE_MEMPOOL, s.state);
    TEST_ASSERT_EQUAL_INT(BNS_OK, interpret_tx_status(true, 0, 0, false, &s));
    TEST_ASSERT_EQUAL_INT(TX_STATE_MEMPOOL, s.state);
}

/* it('raw absent + no confirmations -> unknown (never broadcast / evicted)') */
static void test_interpret_unknown(void)
{
    tx_status_t s;
    TEST_ASSERT_EQUAL_INT(BNS_OK, interpret_tx_status(false, 0, 0, false, &s));
    TEST_ASSERT_EQUAL_INT(TX_STATE_UNKNOWN, s.state);
    TEST_ASSERT_EQUAL_INT(BNS_OK, interpret_tx_status(false, 0, 0, false, &s));
    TEST_ASSERT_EQUAL_INT(TX_STATE_UNKNOWN, s.state);
}

int main(void)
{
    UNITY_BEGIN();
    /* fees */
    RUN_TEST(test_fee_for_size_rounds_up);
    RUN_TEST(test_fee_for_size_rejects_negative);
    RUN_TEST(test_send_time_fee_window);
    RUN_TEST(test_is_fee_in_send_window_saga);
    RUN_TEST(test_recommended_always_accepted);
    RUN_TEST(test_needs_fee_bump_flags_low);
    RUN_TEST(test_needs_fee_bump_floor_inclusive_and_custom);
    RUN_TEST(test_cpfp_child_fee_lifts_package);
    RUN_TEST(test_cpfp_child_fee_dust_floor);
    /* utxo ranking */
    RUN_TEST(test_rank_confirmed_first_then_value);
    RUN_TEST(test_rank_confirmed_only);
    RUN_TEST(test_rank_min_sats);
    RUN_TEST(test_rank_confirmed_flag);
    /* tx status */
    RUN_TEST(test_interpret_confirmed_raw_absent);
    RUN_TEST(test_interpret_boundary_one_conf_and_null_height);
    RUN_TEST(test_interpret_mempool);
    RUN_TEST(test_interpret_unknown);
    return UNITY_END();
}
