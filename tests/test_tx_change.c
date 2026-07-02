/*
 * test_tx_change.c — Unity coverage for bsv/tx_change.c
 * (include/bsv/tx_change.h: estimate_size / sendtime_fee_window /
 * update_change_output).
 *
 * Pins the fee/change arithmetic that decides spendable change, including the
 * operator-order trap (divide-by-1000 BEFORE the multiply, in double precision)
 * and the dust / zero-change boundary where the change output is dropped.
 *
 * The model's bsv_txin_t carries no prevout value, so update_change_output's
 * contract is: outputs[change_index].satoshis is SEEDED with the full input
 * total, and the function settles it to (totalIn - non-change-outputs - fee), or
 * removes it when that would be < DUST_AMOUNT (1 sat in this bsv build).
 *
 * Reference tx geometry used below (1 input, 2 outputs, all scripts < 253 bytes
 * so every varint is 1 byte):
 *   input_size  = 32 + 4 + varint(107)=1 + 107 + 4            = 148
 *   output_size = 8 + varint(25)=1 + 25                       =  34  (x2 = 68)
 *   header      = 8 (ver+locktime) + varint(1)=1 + varint(2)=1 =  10
 *   estimate_size                                              = 226
 *   fee@50/KB   = ceil(226/1000 * 50)  = ceil(11.3) = 12
 *   fee@100/KB  = ceil(226/1000 * 100) = ceil(22.6) = 23
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

void setUp(void) {}
void tearDown(void) {}

/* Append `n` filler bytes to a fresh script buffer (content is irrelevant to the
 * size/fee math; only the length matters). */
static void make_script(byte_buf_t *b, size_t n)
{
    byte_buf_init(b);
    for (size_t i = 0; i < n; i++)
        TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append_byte(b, 0xab));
}

/* Build a 1-input / 2-output tx. outputs[0] is the payment; outputs[1] is the
 * change slot, SEEDED with `change_seed_sats` (the input total, per the
 * update_change_output contract). tx_free releases everything. */
static void build_tx(bsv_tx_t *tx,
                     size_t   in_script_len,
                     uint64_t pay_sats,    size_t pay_script_len,
                     uint64_t change_seed_sats, size_t change_script_len)
{
    tx_init(tx);
    tx->version  = 1;
    tx->locktime = 0;

    tx->num_inputs = 1;
    tx->inputs = calloc(1, sizeof(bsv_txin_t));
    TEST_ASSERT_NOT_NULL(tx->inputs);
    tx->inputs[0].vout     = 0;
    tx->inputs[0].sequence = 0xffffffffu;
    make_script(&tx->inputs[0].script_sig, in_script_len);

    tx->num_outputs = 2;
    tx->outputs = calloc(2, sizeof(bsv_txout_t));
    TEST_ASSERT_NOT_NULL(tx->outputs);
    tx->outputs[0].satoshis = pay_sats;
    make_script(&tx->outputs[0].script, pay_script_len);
    tx->outputs[1].satoshis = change_seed_sats;
    make_script(&tx->outputs[1].script, change_script_len);
}

/* ============================================================================
 * estimate_size — exact byte accounting.
 * ========================================================================= */
static void test_estimate_size_exact(void)
{
    bsv_tx_t tx;
    build_tx(&tx, 107, 5000, 25, 10000, 25);

    size_t sz = 0;
    TEST_ASSERT_EQUAL_INT(BNS_OK, estimate_size(&tx, &sz));
    TEST_ASSERT_EQUAL_UINT(226, sz);

    tx_free(&tx);
}

static void test_estimate_size_null_guard(void)
{
    size_t sz = 0;
    bsv_tx_t tx; tx_init(&tx);
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, estimate_size(NULL, &sz));
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, estimate_size(&tx, NULL));
}

/* ============================================================================
 * sendtime_fee_window — [min, 3*min] window + recommended, operator order.
 * ========================================================================= */
static void test_fee_window_basic_50(void)
{
    fee_window_t w; memset(&w, 0, sizeof w);
    TEST_ASSERT_EQUAL_INT(BNS_OK, sendtime_fee_window(226, 50, &w));
    /* min = ceil(226/1000*50) = 12; max = 36; rec = ceil(12*1.3)=16. */
    TEST_ASSERT_EQUAL_UINT64(12, w.min);
    TEST_ASSERT_EQUAL_UINT64(36, w.max);
    TEST_ASSERT_EQUAL_UINT64(16, w.recommended);
    TEST_ASSERT_EQUAL_UINT(226, w.signed_bytes);
    TEST_ASSERT_EQUAL_UINT64(50, w.fee_per_kb);
}

static void test_fee_window_basic_100(void)
{
    fee_window_t w; memset(&w, 0, sizeof w);
    TEST_ASSERT_EQUAL_INT(BNS_OK, sendtime_fee_window(226, 100, &w));
    /* min = ceil(226/1000*100) = 23; max = 69; rec = ceil(23*1.3)=ceil(29.9)=30. */
    TEST_ASSERT_EQUAL_UINT64(23, w.min);
    TEST_ASSERT_EQUAL_UINT64(69, w.max);
    TEST_ASSERT_EQUAL_UINT64(30, w.recommended);
}

/* Operator-order pin: divide-by-1000 BEFORE the multiply, in double precision.
 * ceil((500/1000)*3) = ceil(0.5*3) = ceil(1.5) = 2; an integer (500*3)/1000
 * would floor to 1. This guards the documented OPERATOR-ORDER TRAP. */
static void test_fee_window_operator_order_edge(void)
{
    fee_window_t w; memset(&w, 0, sizeof w);
    TEST_ASSERT_EQUAL_INT(BNS_OK, sendtime_fee_window(500, 3, &w));
    TEST_ASSERT_EQUAL_UINT64(2, w.min);
}

static void test_fee_window_null_guard(void)
{
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, sendtime_fee_window(226, 50, NULL));
}

/* ============================================================================
 * update_change_output — change = totalIn - non-change-outputs - fee.
 * ========================================================================= */
static void test_change_basic_rate50(void)
{
    bsv_tx_t tx;
    /* seed totalIn = 10000, payment = 5000 => available = 5000; fee@50 = 12. */
    build_tx(&tx, 107, 5000, 25, 10000, 25);

    TEST_ASSERT_EQUAL_INT(BNS_OK, update_change_output(&tx, 1, 50));
    TEST_ASSERT_EQUAL_UINT(2, tx.num_outputs);
    TEST_ASSERT_EQUAL_UINT64(4988, tx.outputs[1].satoshis); /* 5000 - 12 */

    tx_free(&tx);
}

static void test_change_basic_rate100(void)
{
    bsv_tx_t tx;
    build_tx(&tx, 107, 5000, 25, 10000, 25);

    TEST_ASSERT_EQUAL_INT(BNS_OK, update_change_output(&tx, 1, 100));
    TEST_ASSERT_EQUAL_UINT(2, tx.num_outputs);
    TEST_ASSERT_EQUAL_UINT64(4977, tx.outputs[1].satoshis); /* 5000 - 23 */

    tx_free(&tx);
}

/* Dust boundary (KEPT): change == DUST_AMOUNT (1 sat) is retained.
 * seed = payment + fee + 1 = 5000 + 12 + 1 = 5013 => change = 1. */
static void test_change_dust_boundary_kept(void)
{
    bsv_tx_t tx;
    build_tx(&tx, 107, 5000, 25, 5013, 25);

    TEST_ASSERT_EQUAL_INT(BNS_OK, update_change_output(&tx, 1, 50));
    TEST_ASSERT_EQUAL_UINT(2, tx.num_outputs);            /* change retained */
    TEST_ASSERT_EQUAL_UINT64(1, tx.outputs[1].satoshis);  /* exactly 1 sat   */

    tx_free(&tx);
}

/* Zero-change boundary (REMOVED): change would be 0 (< DUST_AMOUNT) => the
 * change output is dropped. seed = payment + fee = 5000 + 12 = 5012. */
static void test_change_zero_removed(void)
{
    bsv_tx_t tx;
    build_tx(&tx, 107, 5000, 25, 5012, 25);

    TEST_ASSERT_EQUAL_INT(BNS_OK, update_change_output(&tx, 1, 50));
    TEST_ASSERT_EQUAL_UINT(1, tx.num_outputs);            /* change dropped */
    /* the surviving output is the original payment. */
    TEST_ASSERT_EQUAL_UINT64(5000, tx.outputs[0].satoshis);

    tx_free(&tx);
}

/* Cannot cover the fee: available (11) < fee (12) => BNS_ERANGE.
 * seed = payment + fee - 1 = 5000 + 12 - 1 = 5011. */
static void test_change_insufficient_for_fee(void)
{
    bsv_tx_t tx;
    build_tx(&tx, 107, 5000, 25, 5011, 25);

    TEST_ASSERT_EQUAL_INT(BNS_ERANGE, update_change_output(&tx, 1, 50));

    tx_free(&tx);
}

/* Non-change outputs exceed the seeded total => insufficient funds (BNS_ERANGE).
 * seed totalIn = 4000 < payment 5000. */
static void test_change_insufficient_funds(void)
{
    bsv_tx_t tx;
    build_tx(&tx, 107, 5000, 25, 4000, 25);

    TEST_ASSERT_EQUAL_INT(BNS_ERANGE, update_change_output(&tx, 1, 50));

    tx_free(&tx);
}

static void test_change_bad_index(void)
{
    bsv_tx_t tx;
    build_tx(&tx, 107, 5000, 25, 10000, 25);

    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, update_change_output(&tx, 5, 50));
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, update_change_output(NULL, 1, 50));

    tx_free(&tx);
}

/* ============================================================================ */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_estimate_size_exact);
    RUN_TEST(test_estimate_size_null_guard);
    RUN_TEST(test_fee_window_basic_50);
    RUN_TEST(test_fee_window_basic_100);
    RUN_TEST(test_fee_window_operator_order_edge);
    RUN_TEST(test_fee_window_null_guard);
    RUN_TEST(test_change_basic_rate50);
    RUN_TEST(test_change_basic_rate100);
    RUN_TEST(test_change_dust_boundary_kept);
    RUN_TEST(test_change_zero_removed);
    RUN_TEST(test_change_insufficient_for_fee);
    RUN_TEST(test_change_insufficient_funds);
    RUN_TEST(test_change_bad_index);
    return UNITY_END();
}
