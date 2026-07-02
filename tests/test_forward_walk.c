/*
 * test_forward_walk.c — C port of chain/tests/priscilla/forwardWalk.test.ts.
 *
 * Theme B / DESIGN.md §2.2 #3: the forward walk must terminate by output-0
 * TEMPLATE (a P2PKH terminal spend), not by receipt-absence — so a receiptless
 * but state-recreating continuation (updateSlashCheckpoint / stake) is traversed
 * instead of silently truncating the identity's history.
 *
 * Mirrors:
 *  - isTerminalIdentitySpend: P2PKH out0 = terminal; recreated = continue
 *  - collects receipts ACROSS a receiptless continuation (B), not stopping at it
 *  - stops at a terminal (P2PKH) spend
 *  - treats a spend with NO output[0] as terminal (stops cleanly)
 */
#include <string.h>
#include <stdlib.h>
#include "unity.h"
#include "reputation_indexer.h"
#include "fixtures.h"
#include "mock_chain_source.h"

/* 32-byte receipt hashes (64-hex), analogous to the TS rA / rC literals. */
#define RA "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
#define RC "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"

/* Genesis txid: forward walk starts at (genesis, vout). The mock only needs a
 * spend link from genesis:0 — genesis raw is never fetched. */
#define GENESIS "0000000000000000000000000000000000000000000000000000000000009e51"
#define TXID_A  "1111111111111111111111111111111111111111111111111111111111111111"
#define TXID_B  "2222222222222222222222222222222222222222222222222222222222222222"
#define TXID_C  "3333333333333333333333333333333333333333333333333333333333333333"
#define TXID_R  "4444444444444444444444444444444444444444444444444444444444444444"
#define TXID_X  "5555555555555555555555555555555555555555555555555555555555555555"

void setUp(void) {}
void tearDown(void) {}

/* isTerminalIdentitySpend: P2PKH output[0] = terminal; recreated = continue. */
static void test_is_terminal_identity_spend(void) {
    char *p2pkh = NULL, *recreated = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, fix_raw_tx_p2pkh_terminal(&p2pkh));
    TEST_ASSERT_EQUAL_INT(BNS_OK, fix_raw_tx_recreated(RA, &recreated));

    TEST_ASSERT_TRUE(is_terminal_identity_spend(p2pkh));
    TEST_ASSERT_FALSE(is_terminal_identity_spend(recreated));

    free(p2pkh);
    free(recreated);
}

/* Collects receipts ACROSS a receiptless continuation (B), not stopping at it. */
static void test_collects_across_receiptless_continuation(void) {
    mock_chain_source_t *m = mock_chain_source_new(1700000000);
    TEST_ASSERT_NOT_NULL(m);

    /* A(receipt rA) -> B(recreated, NO receipt) -> C(receipt rC) -> unspent */
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_add_state_tx(m, TXID_A, RA));
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_add_state_tx(m, TXID_B, NULL));
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_add_state_tx(m, TXID_C, RC));
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_link(m, GENESIS, 0, TXID_A));
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_link(m, TXID_A, 0, TXID_B));
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_link(m, TXID_B, 0, TXID_C));
    /* C unspent -> end of chain */

    chain_source_t src;
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_as_source(m, &src));

    tea_receipts_t receipts = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        collect_receipts(GENESIS, 0, &src, NULL, NULL, &receipts));

    /* Both A and C are collected even though B carries no receipt. */
    TEST_ASSERT_EQUAL_size_t(2, receipts.count);
    TEST_ASSERT_EQUAL_STRING(RA, receipts.items[0].receipt_hash);
    TEST_ASSERT_EQUAL_STRING(RC, receipts.items[1].receipt_hash);

    tea_receipts_free(&receipts);
    mock_chain_source_free(m);
}

/* Stops at a terminal (P2PKH) spend. */
static void test_stops_at_terminal_p2pkh(void) {
    mock_chain_source_t *m = mock_chain_source_new(1700000000);
    TEST_ASSERT_NOT_NULL(m);

    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_add_state_tx(m, TXID_A, RA));
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_add_terminal_tx(m, TXID_R));
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_link(m, GENESIS, 0, TXID_A));
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_link(m, TXID_A, 0, TXID_R));

    chain_source_t src;
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_as_source(m, &src));

    tea_receipts_t receipts = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        collect_receipts(GENESIS, 0, &src, NULL, NULL, &receipts));

    TEST_ASSERT_EQUAL_size_t(1, receipts.count);
    TEST_ASSERT_EQUAL_STRING(RA, receipts.items[0].receipt_hash);

    tea_receipts_free(&receipts);
    mock_chain_source_free(m);
}

/* Treats a spend with NO output[0] as terminal (stops cleanly, keeps priors). */
static void test_no_output_spend_is_terminal(void) {
    mock_chain_source_t *m = mock_chain_source_new(1700000000);
    TEST_ASSERT_NOT_NULL(m);

    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_add_state_tx(m, TXID_A, RA));
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_add_no_output_tx(m, TXID_X));
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_link(m, GENESIS, 0, TXID_A));
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_link(m, TXID_A, 0, TXID_X));

    chain_source_t src;
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_as_source(m, &src));

    tea_receipts_t receipts = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        collect_receipts(GENESIS, 0, &src, NULL, NULL, &receipts));

    TEST_ASSERT_EQUAL_size_t(1, receipts.count);
    TEST_ASSERT_EQUAL_STRING(RA, receipts.items[0].receipt_hash);

    tea_receipts_free(&receipts);
    mock_chain_source_free(m);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_is_terminal_identity_spend);
    RUN_TEST(test_collects_across_receiptless_continuation);
    RUN_TEST(test_stops_at_terminal_p2pkh);
    RUN_TEST(test_no_output_spend_is_terminal);
    return UNITY_END();
}
