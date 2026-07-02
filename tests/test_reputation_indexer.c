/*
 * test_reputation_indexer.c — C port of chain/tests/reputationIndexer.test.ts.
 *
 * Covers the off-chain reputation indexer (Sgantzos & Ferrara 2026 Def 2.6):
 *  - parseReceiptHash: find the 32-byte OP_RETURN receipt; null when absent;
 *    skip a wrong-length OP_RETURN but still find the real one
 *  - collectReceipts: forward walk, in-order, terminal-stop
 *  - reputationScore / computeReputation: rho, decay, future-clamp, half-life,
 *    empty-history, lambda<=0 rejection
 *  - parsePrevout, collectReceiptsBackward, computeReputationBackward,
 *    terminal-tip rejection, loud hop-limit failure, forward needs spend index
 *
 * Note on receipt-hash values: the TS suite uses sha256(toByteString('rN')) as
 * receipt-hash literals; their exact bytes are irrelevant to the behaviours
 * pinned here (ordering / counting / decay), so we use distinct 64-hex literals.
 */
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include "unity.h"
#include "reputation_indexer.h"
#include "bsv/tx.h"
#include "bsv/script_utils.h"
#include "common/bytes.h"
#include "common/hex.h"
#include "fixtures.h"
#include "mock_chain_source.h"

/* ---- receipt-hash literals (distinct 32-byte / 64-hex values) ------------ */
#define R1 "1111111111111111111111111111111111111111111111111111111111111111"
#define R2 "2222222222222222222222222222222222222222222222222222222222222222"
#define R3 "3333333333333333333333333333333333333333333333333333333333333333"
#define RAA "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define RBB "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

#define GENESIS "00000000000000000000000000000000000000000000000000000000000067e5"
#define ID1 "1111111111111111111111111111111111111111111111111111111111111111"
#define ID2 "2222222222222222222222222222222222222222222222222222222222222222"
#define ID3 "3333333333333333333333333333333333333333333333333333333333333333"

void setUp(void) {}
void tearDown(void) {}

/* Unity's double asserts are compiled out unless UNITY_INCLUDE_DOUBLE is set at
 * unity.c build time (the suite's CMake does not set it). Use a libm fabs()
 * tolerance check instead so these pass under both the standalone and CMake
 * builds. */
#define ASSERT_CLOSE(expected, actual, tol) \
    TEST_ASSERT_TRUE(fabs((double)(actual) - (double)(expected)) <= (double)(tol))

/* ---- forward mock: genesis -> id1 -> id2 -> id3 (tip unspent) ------------ */
/* Returns the mock; receipts r1/r2/r3 on the three txs, times 1000/2000/3000. */
static mock_chain_source_t *build_forward_chain(void) {
    mock_chain_source_t *m = mock_chain_source_new(1700000000);
    if (!m) return NULL;
    mock_chain_source_add_state_tx(m, ID1, R1);
    mock_chain_source_add_state_tx(m, ID2, R2);
    mock_chain_source_add_state_tx(m, ID3, R3);
    mock_chain_source_set_time(m, ID1, 1000);
    mock_chain_source_set_time(m, ID2, 2000);
    mock_chain_source_set_time(m, ID3, 3000);
    mock_chain_source_link(m, GENESIS, 0, ID1);
    mock_chain_source_link(m, ID1, 0, ID2);
    mock_chain_source_link(m, ID2, 0, ID3);
    mock_chain_source_link(m, ID3, 0, NULL); /* tip unspent */
    return m;
}

/* ========================================================================= */
/* parseReceiptHash                                                          */
/* ========================================================================= */

static void test_parse_receipt_hash_found(void) {
    char *raw = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, fix_raw_tx_recreated(RAA, &raw));
    char *out = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, indexer_parse_receipt_hash(raw, &out));
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_EQUAL_STRING(RAA, out);
    free(out);
    free(raw);
}

/* returns null for a tx with no receipt output (P2PKH terminal, no OP_RETURN) */
static void test_parse_receipt_hash_none(void) {
    char *raw = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, fix_raw_tx_p2pkh_terminal(&raw));
    char *out = (char *)0x1;
    TEST_ASSERT_EQUAL_INT(BNS_OK, indexer_parse_receipt_hash(raw, &out));
    TEST_ASSERT_NULL(out); /* TS: null */
    free(raw);
}

/* skips a non-32-byte OP_RETURN but still finds the real 32-byte receipt that
 * follows it in the same tx. Built manually: out0=OP_1, out1=OP_RETURN(4-byte),
 * out2=OP_RETURN(32-byte real receipt). */
static void test_parse_receipt_hash_skips_wrong_length(void) {
    bsv_tx_t tx;
    tx_init(&tx);
    tx.version = 1;
    tx.locktime = 0;
    tx.num_outputs = 3;
    tx.outputs = calloc(3, sizeof(bsv_txout_t));
    TEST_ASSERT_NOT_NULL(tx.outputs);

    /* out0: OP_1 recreated identity */
    byte_buf_init(&tx.outputs[0].script);
    byte_buf_append_byte(&tx.outputs[0].script, 0x51);
    tx.outputs[0].satoshis = 1;

    /* out1: OP_RETURN of a 4-byte value (deadbeef) — wrong length, must skip */
    {
        uint8_t four[4] = {0xde, 0xad, 0xbe, 0xef};
        byte_buf_init(&tx.outputs[1].script);
        TEST_ASSERT_EQUAL_INT(BNS_OK,
            build_opreturn_script(four, sizeof(four), &tx.outputs[1].script));
        tx.outputs[1].satoshis = 0;
    }

    /* out2: OP_RETURN of the genuine 32-byte receipt */
    {
        byte_buf_t rh; byte_buf_init(&rh);
        TEST_ASSERT_EQUAL_INT(BNS_OK, hex_decode(RBB, &rh));
        byte_buf_init(&tx.outputs[2].script);
        TEST_ASSERT_EQUAL_INT(BNS_OK,
            build_opreturn_script(rh.data, rh.len, &tx.outputs[2].script));
        tx.outputs[2].satoshis = 0;
        byte_buf_free(&rh);
    }

    byte_buf_t wire; byte_buf_init(&wire);
    TEST_ASSERT_EQUAL_INT(BNS_OK, tx_serialize(&tx, &wire));
    char *raw_hex = hex_encode_buf(&wire);
    TEST_ASSERT_NOT_NULL(raw_hex);

    char *out = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, indexer_parse_receipt_hash(raw_hex, &out));
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_EQUAL_STRING(RBB, out); /* found the real 32-byte one, not deadbeef */

    free(out);
    free(raw_hex);
    byte_buf_free(&wire);
    tx_free(&tx);
}

/* ========================================================================= */
/* collectReceipts (forward)                                                 */
/* ========================================================================= */

static void test_collect_receipts_in_order(void) {
    mock_chain_source_t *m = build_forward_chain();
    TEST_ASSERT_NOT_NULL(m);
    chain_source_t src;
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_as_source(m, &src));

    tea_receipts_t r = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK, collect_receipts(GENESIS, 0, &src, NULL, NULL, &r));
    TEST_ASSERT_EQUAL_size_t(3, r.count);
    TEST_ASSERT_EQUAL_STRING(R1, r.items[0].receipt_hash);
    TEST_ASSERT_EQUAL_STRING(R2, r.items[1].receipt_hash);
    TEST_ASSERT_EQUAL_STRING(R3, r.items[2].receipt_hash);
    for (size_t i = 0; i < r.count; i++) TEST_ASSERT_TRUE(r.items[i].valid);

    tea_receipts_free(&r);
    mock_chain_source_free(m);
}

/* stops at a terminal revoke/slash spend instead of following payout history. */
static void test_collect_receipts_stops_at_terminal(void) {
    mock_chain_source_t *m = mock_chain_source_new(1000);
    TEST_ASSERT_NOT_NULL(m);
    const char *t1 = ID1, *terminal = ID2, *unrelated = ID3;
    mock_chain_source_add_state_tx(m, t1, RAA);          /* valid identity receipt */
    mock_chain_source_add_terminal_tx(m, terminal);      /* P2PKH payout */
    mock_chain_source_add_state_tx(m, unrelated, RBB);   /* unrelated wallet receipt */
    mock_chain_source_link(m, GENESIS, 0, t1);
    mock_chain_source_link(m, t1, 0, terminal);
    mock_chain_source_link(m, terminal, 0, unrelated);
    mock_chain_source_link(m, unrelated, 0, NULL);

    chain_source_t src;
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_as_source(m, &src));

    tea_receipts_t r = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK, collect_receipts(GENESIS, 0, &src, NULL, NULL, &r));
    TEST_ASSERT_EQUAL_size_t(1, r.count); /* only the valid one before the terminal */
    TEST_ASSERT_EQUAL_STRING(RAA, r.items[0].receipt_hash);

    tea_receipts_free(&r);
    mock_chain_source_free(m);
}

/* ========================================================================= */
/* reputationScore / computeReputation                                       */
/* ========================================================================= */

static void test_compute_reputation_all_valid(void) {
    mock_chain_source_t *m = build_forward_chain();
    TEST_ASSERT_NOT_NULL(m);
    chain_source_t src;
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_as_source(m, &src));

    reputation_score_t s = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        compute_reputation(GENESIS, 0, &src, 3000, 1e-3, NULL, NULL, &s, NULL));
    TEST_ASSERT_EQUAL_size_t(3, s.count);
    ASSERT_CLOSE(1.0, s.rho, 1e-9);

    mock_chain_source_free(m);
}

/* markValid predicate: dispute one receipt by hash. */
static bool mv_not_r1(void *u, const char *txid, int64_t t, const char *rh) {
    (void)u; (void)txid; (void)t;
    return strcmp(rh, R1) != 0;
}
static bool mv_not_r3(void *u, const char *txid, int64_t t, const char *rh) {
    (void)u; (void)txid; (void)t;
    return strcmp(rh, R3) != 0;
}

/* weights a recent dispute more heavily than an old one (decay). */
static void test_decay_recent_dispute_heavier(void) {
    chain_source_t src;
    reputation_score_t old_disp = {0}, new_disp = {0};

    mock_chain_source_t *m1 = build_forward_chain();
    TEST_ASSERT_NOT_NULL(m1);
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_as_source(m1, &src));
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        compute_reputation(GENESIS, 0, &src, 3000, 1e-2, mv_not_r1, NULL, &old_disp, NULL));

    mock_chain_source_t *m2 = build_forward_chain();
    TEST_ASSERT_NOT_NULL(m2);
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_as_source(m2, &src));
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        compute_reputation(GENESIS, 0, &src, 3000, 1e-2, mv_not_r3, NULL, &new_disp, NULL));

    /* disputing the OLD receipt (r1) leaves rho higher than disputing the new one */
    TEST_ASSERT_TRUE(old_disp.rho > new_disp.rho);
    TEST_ASSERT_TRUE(old_disp.rho < 1.0);
    TEST_ASSERT_TRUE(new_disp.rho > 0.0);

    mock_chain_source_free(m1);
    mock_chain_source_free(m2);
}

/* rho = 0 for an identity with no receipts. */
static void test_reputation_empty(void) {
    tea_receipts_t empty = {0};
    reputation_score_t s = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK, reputation_score(&empty, 1000, 1e-3, &s));
    ASSERT_CLOSE(0.0, s.rho, 1e-12);
    TEST_ASSERT_EQUAL_size_t(0, s.count);
}

/* clamps future-dated receipts to weight 1 (no outsized weight). */
static void test_reputation_future_clamp(void) {
    int64_t now = 1000;
    tea_receipt_t items[2] = {0};
    items[0].time = now;            items[0].valid = true; strcpy(items[0].receipt_hash, RAA);
    items[1].time = now + 10000;    items[1].valid = true; strcpy(items[1].receipt_hash, RBB);
    tea_receipts_t r = { .items = items, .count = 2 };

    reputation_score_t s = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK, reputation_score(&r, now, 1e-2, &s));
    /* both weights clamped/at 1 => total EXACTLY 2; without clamp future ~ e^100 */
    ASSERT_CLOSE(2.0, s.weight_total, 1e-9);
    ASSERT_CLOSE(1.0, s.rho, 1e-9);
}

/* calibrated decay lambda yields ~30-day half-life. */
static void test_reputation_half_life(void) {
    const double LAMBDA = 2.7e-7;
    const int64_t HALF_LIFE = 30LL * 24 * 3600;
    const int64_t now = 2000000000LL;

    tea_receipt_t fresh = {0}; fresh.time = now;             fresh.valid = true; strcpy(fresh.receipt_hash, RAA);
    tea_receipt_t aged  = {0}; aged.time  = now - HALF_LIFE; aged.valid  = true; strcpy(aged.receipt_hash, RBB);

    tea_receipts_t rf = { .items = &fresh, .count = 1 };
    tea_receipts_t ra = { .items = &aged,  .count = 1 };

    reputation_score_t sf = {0}, sa = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK, reputation_score(&rf, now, LAMBDA, &sf));
    TEST_ASSERT_EQUAL_INT(BNS_OK, reputation_score(&ra, now, LAMBDA, &sa));
    ASSERT_CLOSE(1.0, sf.weight_total, 1e-9);  /* present receipt weighs 1 */
    ASSERT_CLOSE(0.5, sa.weight_total / sf.weight_total, 0.01); /* ~half */
}

/* rejects a non-positive decay rate. */
static void test_reputation_rejects_nonpositive_lambda(void) {
    tea_receipts_t empty = {0};
    reputation_score_t s = {0};
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, reputation_score(&empty, 0, 0.0, &s));
}

/* ========================================================================= */
/* backward walk                                                             */
/* ========================================================================= */

/* Build a tx whose input[0] spends (prev_txid:0), output[0]=OP_1 recreated,
 * optional output[1]=OP_RETURN(receipt32). If terminal!=0, output[0] is P2PKH
 * (25-byte) and there is no receipt. Returns malloc'd raw hex via *out_hex and
 * the computed display txid via *out_txid (caller frees both). */
static int build_linked_tx(const char *prev_txid, const char *receipt_hex,
                           int terminal, char **out_hex, char **out_txid) {
    bsv_tx_t tx; tx_init(&tx);
    tx.version = 1; tx.locktime = 0;

    tx.num_inputs = 1;
    tx.inputs = calloc(1, sizeof(bsv_txin_t));
    if (!tx.inputs) { tx_free(&tx); return BNS_ENOMEM; }
    strncpy(tx.inputs[0].prev_txid_display, prev_txid, 64);
    tx.inputs[0].prev_txid_display[64] = '\0';
    tx.inputs[0].vout = 0;
    tx.inputs[0].sequence = 0xffffffff;
    byte_buf_init(&tx.inputs[0].script_sig); /* empty unlocking script */

    size_t nout = (receipt_hex && !terminal) ? 2 : 1;
    tx.num_outputs = nout;
    tx.outputs = calloc(nout, sizeof(bsv_txout_t));
    if (!tx.outputs) { tx_free(&tx); return BNS_ENOMEM; }

    byte_buf_init(&tx.outputs[0].script);
    if (terminal) {
        /* canonical 25-byte P2PKH: 76 a9 14 <20B> 88 ac */
        uint8_t p2pkh[25] = {0x76, 0xa9, 0x14};
        for (int i = 0; i < 20; i++) p2pkh[3 + i] = 0xab;
        p2pkh[23] = 0x88; p2pkh[24] = 0xac;
        byte_buf_append(&tx.outputs[0].script, p2pkh, sizeof(p2pkh));
    } else {
        byte_buf_append_byte(&tx.outputs[0].script, 0x51); /* OP_1 recreated */
    }
    tx.outputs[0].satoshis = 1;

    if (nout == 2) {
        byte_buf_t rh; byte_buf_init(&rh);
        if (hex_decode(receipt_hex, &rh) != BNS_OK) { byte_buf_free(&rh); tx_free(&tx); return BNS_EPARSE; }
        byte_buf_init(&tx.outputs[1].script);
        if (build_opreturn_script(rh.data, rh.len, &tx.outputs[1].script) != BNS_OK) {
            byte_buf_free(&rh); tx_free(&tx); return BNS_EPARSE;
        }
        tx.outputs[1].satoshis = 0;
        byte_buf_free(&rh);
    }

    byte_buf_t wire; byte_buf_init(&wire);
    if (tx_serialize(&tx, &wire) != BNS_OK) { byte_buf_free(&wire); tx_free(&tx); return BNS_ENOMEM; }
    *out_hex = hex_encode_buf(&wire);
    byte_buf_free(&wire);
    if (!*out_hex) { tx_free(&tx); return BNS_ENOMEM; }

    int rc = tx_id(&tx, out_txid);
    tx_free(&tx);
    if (rc != BNS_OK) { free(*out_hex); *out_hex = NULL; return rc; }
    return BNS_OK;
}

/* backward chain: genesis <- t1 <- t2 <- t3(tip). Fills mock + ids[3]. */
static mock_chain_source_t *build_backward_chain(const char *genesis,
                                                 char ids[3][65]) {
    mock_chain_source_t *m = mock_chain_source_new(0);
    if (!m) return NULL;
    const char *rhs[3] = { R1, R2, R3 };
    int64_t times[3] = { 1000, 2000, 3000 };
    char prev[65];
    strncpy(prev, genesis, 65);
    for (int i = 0; i < 3; i++) {
        char *hex = NULL, *txid = NULL;
        if (build_linked_tx(prev, rhs[i], 0, &hex, &txid) != BNS_OK) {
            mock_chain_source_free(m); return NULL;
        }
        mock_chain_source_add_raw(m, txid, hex);
        mock_chain_source_set_time(m, txid, times[i]);
        snprintf(ids[i], 65, "%s", txid);
        snprintf(prev, 65, "%s", txid);
        free(hex); free(txid);
    }
    return m;
}

/* parsePrevout reads input[0] outpoint. */
static void test_parse_prevout(void) {
    const char *genesis = "abababababababababababababababababababababababababababababababab";
    char ids[3][65];
    mock_chain_source_t *m = build_backward_chain(genesis, ids);
    TEST_ASSERT_NOT_NULL(m);

    char *hex = NULL;
    chain_source_t src;
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_as_source(m, &src));
    TEST_ASSERT_EQUAL_INT(BNS_OK, src.get_raw_tx(src.ctx, ids[0], &hex));

    indexer_prevout_t p;
    TEST_ASSERT_EQUAL_INT(BNS_OK, indexer_parse_prevout(hex, 0, &p));
    TEST_ASSERT_EQUAL_STRING(genesis, p.txid);
    TEST_ASSERT_EQUAL_UINT32(0, p.vout);

    free(hex);
    mock_chain_source_free(m);
}

/* walks tip -> genesis and returns receipts oldest-first. */
static void test_backward_walk_oldest_first(void) {
    const char *genesis = "abababababababababababababababababababababababababababababababab";
    char ids[3][65];
    mock_chain_source_t *m = build_backward_chain(genesis, ids);
    TEST_ASSERT_NOT_NULL(m);
    chain_source_t src;
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_as_source(m, &src));

    tea_receipts_t r = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        collect_receipts_backward(ids[2], genesis, &src, 0, NULL, NULL, 0, &r));
    TEST_ASSERT_EQUAL_size_t(3, r.count);
    TEST_ASSERT_EQUAL_STRING(R1, r.items[0].receipt_hash);
    TEST_ASSERT_EQUAL_STRING(R2, r.items[1].receipt_hash);
    TEST_ASSERT_EQUAL_STRING(R3, r.items[2].receipt_hash);

    tea_receipts_free(&r);
    mock_chain_source_free(m);
}

/* rejects a tip whose tx is a terminal (revoke/slash) spend. */
static void test_backward_rejects_terminal_tip(void) {
    const char *genesis = "abababababababababababababababababababababababababababababababab";
    char *hex = NULL, *tid = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, build_linked_tx(genesis, NULL, 1, &hex, &tid));

    mock_chain_source_t *m = mock_chain_source_new(0);
    TEST_ASSERT_NOT_NULL(m);
    mock_chain_source_add_raw(m, tid, hex);
    chain_source_t src;
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_as_source(m, &src));

    tea_receipts_t r = {0};
    int rc = collect_receipts_backward(tid, genesis, &src, 0, NULL, NULL, 0, &r);
    TEST_ASSERT_EQUAL_INT(BNS_EPARSE, rc); /* TS: throws /terminal (revoke\/slash) spend/ */

    tea_receipts_free(&r);
    free(hex); free(tid);
    mock_chain_source_free(m);
}

/* fails LOUD when genesis is not reached within maxHops (3-deep, cap 2). */
static void test_backward_hop_limit_loud(void) {
    const char *genesis = "abababababababababababababababababababababababababababababababab";
    char ids[3][65];
    mock_chain_source_t *m = build_backward_chain(genesis, ids);
    TEST_ASSERT_NOT_NULL(m);
    chain_source_t src;
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_as_source(m, &src));

    tea_receipts_t r = {0};
    int rc = collect_receipts_backward(ids[2], genesis, &src, 0, NULL, NULL, 2, &r);
    TEST_ASSERT_EQUAL_INT(BNS_EHOPLIMIT, rc); /* TS: /not reached within 2 hops/ */

    tea_receipts_free(&r);
    mock_chain_source_free(m);
}

/* computeReputationBackward yields rho = 1 for an all-valid chain. */
static void test_compute_reputation_backward_all_valid(void) {
    const char *genesis = "abababababababababababababababababababababababababababababababab";
    char ids[3][65];
    mock_chain_source_t *m = build_backward_chain(genesis, ids);
    TEST_ASSERT_NOT_NULL(m);
    chain_source_t src;
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_as_source(m, &src));

    reputation_score_t s = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        compute_reputation_backward(ids[2], genesis, &src, 3000, 1e-3, 0,
                                    NULL, NULL, &s, NULL));
    TEST_ASSERT_EQUAL_size_t(3, s.count);
    ASSERT_CLOSE(1.0, s.rho, 1e-9);

    mock_chain_source_free(m);
}

/* markValid on the backward walk: a disputed receipt lowers rho. */
static void test_compute_reputation_backward_dispute(void) {
    const char *genesis = "abababababababababababababababababababababababababababababababab";
    char ids[3][65];
    mock_chain_source_t *m = build_backward_chain(genesis, ids);
    TEST_ASSERT_NOT_NULL(m);
    chain_source_t src;
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_as_source(m, &src));

    reputation_score_t s = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        compute_reputation_backward(ids[2], genesis, &src, 3000, 1e-3, 0,
                                    mv_not_r3, NULL, &s, NULL)); /* dispute newest */
    TEST_ASSERT_EQUAL_size_t(3, s.count); /* all three still walked */
    TEST_ASSERT_TRUE(s.rho < 1.0);
    TEST_ASSERT_TRUE(s.rho > 0.0);

    mock_chain_source_free(m);
}

/* forward collectReceipts throws when the source has no spend index. */
static void test_forward_needs_spend_index(void) {
    const char *genesis = "abababababababababababababababababababababababababababababababab";
    char ids[3][65];
    mock_chain_source_t *m = build_backward_chain(genesis, ids);
    TEST_ASSERT_NOT_NULL(m);
    chain_source_t src;
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_as_source(m, &src));
    mock_chain_source_disable_spend_index(&src); /* no get_spending_txid */

    tea_receipts_t r = {0};
    int rc = collect_receipts(genesis, 0, &src, NULL, NULL, &r);
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, rc); /* TS: /needs ChainSource.getSpendingTxid/ */

    tea_receipts_free(&r);
    mock_chain_source_free(m);
}

int main(void) {
    UNITY_BEGIN();
    /* parseReceiptHash */
    RUN_TEST(test_parse_receipt_hash_found);
    RUN_TEST(test_parse_receipt_hash_none);
    RUN_TEST(test_parse_receipt_hash_skips_wrong_length);
    /* forward collect */
    RUN_TEST(test_collect_receipts_in_order);
    RUN_TEST(test_collect_receipts_stops_at_terminal);
    /* score / compute */
    RUN_TEST(test_compute_reputation_all_valid);
    RUN_TEST(test_decay_recent_dispute_heavier);
    RUN_TEST(test_reputation_empty);
    RUN_TEST(test_reputation_future_clamp);
    RUN_TEST(test_reputation_half_life);
    RUN_TEST(test_reputation_rejects_nonpositive_lambda);
    /* backward */
    RUN_TEST(test_parse_prevout);
    RUN_TEST(test_backward_walk_oldest_first);
    RUN_TEST(test_backward_rejects_terminal_tip);
    RUN_TEST(test_backward_hop_limit_loud);
    RUN_TEST(test_compute_reputation_backward_all_valid);
    RUN_TEST(test_compute_reputation_backward_dispute);
    RUN_TEST(test_forward_needs_spend_index);
    return UNITY_END();
}
