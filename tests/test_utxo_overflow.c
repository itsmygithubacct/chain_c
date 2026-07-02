/*
 * test_utxo_overflow.c — Gap-3 hardening: integer-overflow of summed UTXO values.
 *
 * Background (deep-review coverage gap): woc_json_i64 bounds a SINGLE WhatsOnChain
 * `value` to 2^53, but a malicious/buggy response can carry MANY large entries
 * whose SUM overflows (or merely exceeds the BSV money supply) once the wallet /
 * broadcast layer accumulates them. These tests pin the fail-CLOSED guards added
 * across the parse/selection/change layers:
 *
 *   - chainSources/utxo_select.c  funding_utxos_total() — overflow-safe sum,
 *                                  rank_funding_utxos() drops value > MAX_MONEY.
 *   - bsv/tx_change.c             update_change_output() — bounds the seeded
 *                                  totalIn and the running output sum.
 *
 * Every guard must fail with BNS_ERANGE (never wrap), while legitimate small
 * sums/selections must still succeed unchanged.
 *
 * BONSAI_MAX_MONEY = 21,000,000 BSV * 1e8 = 2,100,000,000,000,000 sats.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "common/error.h"
#include "common/bytes.h"
#include "bsv/tx.h"
#include "bsv/tx_change.h"
#include "chainSources/utxo_select.h"

void setUp(void) {}
void tearDown(void) {}

/* Build a funding_utxo_t with a given satoshi value (other fields irrelevant to
 * the summation/selection arithmetic under test). */
static funding_utxo_t fu(int64_t sats)
{
    funding_utxo_t f;
    memset(&f, 0, sizeof f);
    f.tx_id[0]     = '\0';
    f.output_index = 0;
    f.satoshis     = sats;
    f.confirmed    = true;
    return f;
}

/* Build a woc_utxo_t with a given value (confirmed via height 1). */
static woc_utxo_t wu(int64_t value)
{
    woc_utxo_t u;
    memset(&u, 0, sizeof u);
    u.tx_hash[0] = '\0';
    u.tx_pos     = 0;
    u.value      = value;
    u.height     = 1;
    return u;
}

/* ============================================================================
 * funding_utxos_total — overflow-safe accumulation.
 * ========================================================================= */

/* Happy path: a small list of legitimate values sums exactly. */
static void test_total_small_ok(void)
{
    funding_utxo_t items[3] = { fu(1000), fu(2000), fu(3000) };
    uint64_t total = 0;
    TEST_ASSERT_EQUAL_INT(BNS_OK, funding_utxos_total(items, 3, &total));
    TEST_ASSERT_EQUAL_UINT64(6000, total);
}

/* Empty list sums to zero. */
static void test_total_empty_ok(void)
{
    uint64_t total = 123;
    TEST_ASSERT_EQUAL_INT(BNS_OK, funding_utxos_total(NULL, 0, &total));
    TEST_ASSERT_EQUAL_UINT64(0, total);
}

/* A single value exactly at MAX_MONEY is allowed. */
static void test_total_single_at_cap_ok(void)
{
    funding_utxo_t items[1] = { fu(BONSAI_MAX_MONEY) };
    uint64_t total = 0;
    TEST_ASSERT_EQUAL_INT(BNS_OK, funding_utxos_total(items, 1, &total));
    TEST_ASSERT_EQUAL_UINT64((uint64_t)BONSAI_MAX_MONEY, total);
}

/* A single value just above MAX_MONEY fails closed (never silently accepted). */
static void test_total_single_over_cap_eranges(void)
{
    funding_utxo_t items[1] = { fu((int64_t)BONSAI_MAX_MONEY + 1) };
    uint64_t total = 999;
    TEST_ASSERT_EQUAL_INT(BNS_ERANGE, funding_utxos_total(items, 1, &total));
}

/* A negative value fails closed. */
static void test_total_negative_eranges(void)
{
    funding_utxo_t items[2] = { fu(1000), fu(-5) };
    uint64_t total = 0;
    TEST_ASSERT_EQUAL_INT(BNS_ERANGE, funding_utxos_total(items, 2, &total));
}

/* Many entries, each individually <= MAX_MONEY, whose RUNNING SUM crosses
 * MAX_MONEY: the guard must trip BEFORE the accumulator passes the cap (this is
 * the precise gap — each value is "valid" alone but the sum is not). */
static void test_total_running_sum_over_cap_eranges(void)
{
    /* half + half + 2 > MAX_MONEY (and half*2 == MAX_MONEY exactly). */
    int64_t half = BONSAI_MAX_MONEY / 2;
    funding_utxo_t items[3] = { fu(half), fu(half), fu(2) };
    uint64_t total = 0;
    TEST_ASSERT_EQUAL_INT(BNS_ERANGE, funding_utxos_total(items, 3, &total));
}

/* The accumulator must never wrap: feeding values whose naive int64/uint64 sum
 * would overflow (each at MAX_MONEY, 8000+ of them would wrap uint64) is caught
 * on the 2nd entry — we assert it fails closed rather than wrapping to a small
 * "valid" total. */
static void test_total_no_wrap(void)
{
    funding_utxo_t items[3] = {
        fu(BONSAI_MAX_MONEY), fu(BONSAI_MAX_MONEY), fu(BONSAI_MAX_MONEY)
    };
    uint64_t total = 0;
    TEST_ASSERT_EQUAL_INT(BNS_ERANGE, funding_utxos_total(items, 3, &total));
}

/* NULL out-param is rejected. */
static void test_total_null_guard(void)
{
    funding_utxo_t items[1] = { fu(1) };
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, funding_utxos_total(items, 1, NULL));
    uint64_t total = 0;
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, funding_utxos_total(NULL, 1, &total));
}

/* ============================================================================
 * rank_funding_utxos — drops an out-of-range (> MAX_MONEY) value fail-closed,
 * while a normal mix ranks as before.
 * ========================================================================= */

/* A normal selection: two legit UTXOs both survive and the resulting total is
 * computable (sums correctly). */
static void test_rank_normal_then_total_ok(void)
{
    woc_utxo_t in[2] = { wu(5000), wu(9000) };
    funding_utxos_t ranked;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rank_funding_utxos(in, 2, NULL, &ranked));
    TEST_ASSERT_EQUAL_UINT(2, ranked.count);

    uint64_t total = 0;
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        funding_utxos_total(ranked.items, ranked.count, &total));
    TEST_ASSERT_EQUAL_UINT64(14000, total);
    funding_utxos_free(&ranked);
}

/* An inflated value (> MAX_MONEY) is dropped during ranking, so it can never
 * reach a downstream funding sum; only the legitimate entry survives. */
static void test_rank_drops_over_cap(void)
{
    woc_utxo_t in[2] = { wu((int64_t)BONSAI_MAX_MONEY + 1), wu(7000) };
    funding_utxos_t ranked;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rank_funding_utxos(in, 2, NULL, &ranked));
    TEST_ASSERT_EQUAL_UINT(1, ranked.count);
    TEST_ASSERT_EQUAL_INT64(7000, ranked.items[0].satoshis);

    uint64_t total = 0;
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        funding_utxos_total(ranked.items, ranked.count, &total));
    TEST_ASSERT_EQUAL_UINT64(7000, total);
    funding_utxos_free(&ranked);
}

/* ============================================================================
 * update_change_output — fail-closed on inflated seed / output sum.
 * ========================================================================= */

/* Minimal 1-in / 2-out tx; outputs[1] is the change slot seeded with totalIn. */
static void build_tx2(bsv_tx_t *tx, uint64_t pay_sats, uint64_t change_seed)
{
    tx_init(tx);
    tx->version  = 1;
    tx->locktime = 0;

    tx->num_inputs = 1;
    tx->inputs = calloc(1, sizeof(bsv_txin_t));
    TEST_ASSERT_NOT_NULL(tx->inputs);
    tx->inputs[0].vout     = 0;
    tx->inputs[0].sequence = 0xffffffffu;
    byte_buf_init(&tx->inputs[0].script_sig);
    for (int i = 0; i < 107; i++)
        TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append_byte(&tx->inputs[0].script_sig, 0xab));

    tx->num_outputs = 2;
    tx->outputs = calloc(2, sizeof(bsv_txout_t));
    TEST_ASSERT_NOT_NULL(tx->outputs);
    tx->outputs[0].satoshis = pay_sats;
    byte_buf_init(&tx->outputs[0].script);
    for (int i = 0; i < 25; i++)
        TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append_byte(&tx->outputs[0].script, 0xab));
    tx->outputs[1].satoshis = change_seed;
    byte_buf_init(&tx->outputs[1].script);
    for (int i = 0; i < 25; i++)
        TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append_byte(&tx->outputs[1].script, 0xab));
}

/* Happy path still works: small seed settles change normally. */
static void test_change_normal_ok(void)
{
    bsv_tx_t tx;
    build_tx2(&tx, 5000, 10000);              /* available 5000; fee@50 = 12 */
    TEST_ASSERT_EQUAL_INT(BNS_OK, update_change_output(&tx, 1, 50));
    TEST_ASSERT_EQUAL_UINT64(4988, tx.outputs[1].satoshis);
    tx_free(&tx);
}

/* An inflated seeded totalIn (> MAX_MONEY) fails closed, never carried into the
 * subtraction. */
static void test_change_seed_over_cap_eranges(void)
{
    bsv_tx_t tx;
    build_tx2(&tx, 5000, (uint64_t)BONSAI_MAX_MONEY + 1);
    TEST_ASSERT_EQUAL_INT(BNS_ERANGE, update_change_output(&tx, 1, 50));
    tx_free(&tx);
}

/* An inflated NON-change output value (> MAX_MONEY) fails closed rather than
 * wrapping the uint64 output-sum accumulator. */
static void test_change_output_over_cap_eranges(void)
{
    bsv_tx_t tx;
    build_tx2(&tx, (uint64_t)BONSAI_MAX_MONEY + 1, (uint64_t)BONSAI_MAX_MONEY);
    TEST_ASSERT_EQUAL_INT(BNS_ERANGE, update_change_output(&tx, 1, 50));
    tx_free(&tx);
}

/* ============================================================================ */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_total_small_ok);
    RUN_TEST(test_total_empty_ok);
    RUN_TEST(test_total_single_at_cap_ok);
    RUN_TEST(test_total_single_over_cap_eranges);
    RUN_TEST(test_total_negative_eranges);
    RUN_TEST(test_total_running_sum_over_cap_eranges);
    RUN_TEST(test_total_no_wrap);
    RUN_TEST(test_total_null_guard);
    RUN_TEST(test_rank_normal_then_total_ok);
    RUN_TEST(test_rank_drops_over_cap);
    RUN_TEST(test_change_normal_ok);
    RUN_TEST(test_change_seed_over_cap_eranges);
    RUN_TEST(test_change_output_over_cap_eranges);
    return UNITY_END();
}
