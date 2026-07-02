/*
 * reputation_indexer.h — the chain_source_t data-source vtable (FROZEN here) +
 * the off-chain reputation indexer (Sgantzos & Ferrara 2026 Def 2.6).
 *
 * Two things live here:
 *  1. chain_source_t — the data-source interface (getRawTx / getTime /
 *     optional getSpendingTxid) satisfied by the WhatsOnChain adapter and by
 *     test mocks, and consumed by the indexer, identity_chain_view, and
 *     chain_revocation_oracle. Frozen so brokers build against a stable contract
 *     while the WoC adapter is implemented separately.
 *  2. The reputation walker/scorer: parse executeTea OP_RETURN "Third Entry"
 *     receipts along an identity's append-only UTXO chain (forward via a spend
 *     index, or backward from a tip via input[0] prevouts), annotate
 *     crypto-shred erasure markers, and compute the exponentially-decayed
 *     weighted reputation score rho.
 *
 * TS origin: src/reputationIndexer.ts (ChainSource, TeaReceipt, shredMarkerHex,
 * isShredMarkerFor, annotateErasure, parseReceiptHash, parsePrevout,
 * isTerminalIdentitySpend, collectReceipts(+Backward), reputationScore,
 * computeReputation(+Backward)).
 *
 * BYTE/FLOAT-EXACTNESS PINS (plan.risks #7, #13 and module notes):
 *  - prevTxId ENDIANNESS: the next txid passed to get_raw_tx is bsv's
 *    prevTxId.toString('hex') == the DISPLAY (big-endian) hex. The shared tx
 *    parser (chain/tx_parse.h, bsv/tx.h) already reverses the LE wire outpoint;
 *    use prev_txid_display verbatim — do NOT reverse again.
 *  - reputationScore is IEEE-754 double: w = exp(-lambda*max(0, now-t)); keep
 *    the accumulation order (den then conditional num) identical to TS. Use
 *    libm exp() and double — never long double.
 *  - parseReceiptHash: script hex starts '006a' AND last chunk is EXACTLY 32B.
 *  - shredMarkerHex MUST byte-match PrivateEnclave.shredMarker ('SHRED_V1').
 */
#ifndef BONSAI_REPUTATION_INDEXER_H
#define BONSAI_REPUTATION_INDEXER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"

/* Forward/backward walk caps. TS: MAX_HOPS / MAX_BACKWARD_HOPS. */
#define BONSAI_INDEXER_MAX_HOPS          5000000  /* forward walk cap            */
#define BONSAI_INDEXER_MAX_BACKWARD_HOPS 100000   /* backward default cap        */

/* ---- chain_source_t vtable (FROZEN interface) --------------------------- */

/* A chain data source. All txids are 64-char lowercase DISPLAY hex strings.
 * Fallible methods return int (bonsai_err_t) with results via out-params.
 * `get_spending_txid` is OPTIONAL (NULL when the provider has no spend index —
 * only forward walking needs it); callers must check it for NULL.
 * TS: src/reputationIndexer.ts::ChainSource. */
typedef struct chain_source_s chain_source_t;
struct chain_source_s {
    void *ctx; /* implementation-private state (e.g. WhatsOnChainSource handle)   */

    /* getRawTx(txid): raw tx hex into *out_hex (freshly malloc'd, caller frees).
     * BNS_OK / BNS_ENET / BNS_ENOTFOUND / BNS_ENOMEM. TS: getRawTx. */
    int (*get_raw_tx)(void *ctx, const char *txid, char **out_hex);

    /* getTime(txid): unix-seconds ledger time into *out_time. Errors (not 0) if
     * no usable timestamp. BNS_OK / BNS_ENET / BNS_EPARSE. TS: getTime. */
    int (*get_time)(void *ctx, const char *txid, int64_t *out_time);

    /* getSpendingTxid(txid, vout) [OPTIONAL — may be NULL]: spend index lookup.
     * On success sets *out_spender to a freshly malloc'd 64-hex txid (caller
     * frees) OR to NULL when the output is unspent (the sentinel — still BNS_OK).
     * BNS_OK / BNS_ENET. TS: getSpendingTxid (404 -> null). */
    int (*get_spending_txid)(void *ctx, const char *txid, uint32_t vout,
                             char **out_spender);
};

/* ---- receipts ----------------------------------------------------------- */

/* A parsed "Third Entry" receipt. TS: src/reputationIndexer.ts::TeaReceipt. */
typedef struct {
    char    txid[65];        /* 64-hex DISPLAY txid + NUL                         */
    int64_t time;            /* unix-seconds ledger time                          */
    char    receipt_hash[65];/* 32-byte receiptHash as 64-hex (no 0x) + NUL       */
    bool    valid;           /* validity (default true)                           */
    bool    erased;          /* crypto-shred erasure flag (annotateErasure)       */
} tea_receipt_t;

/* An owned, ordered (oldest-first) receipt list. */
typedef struct {
    tea_receipt_t *items;
    size_t         count;
} tea_receipts_t;

/* Free a receipt list (NULL-safe). */
void tea_receipts_free(tea_receipts_t *r);

/* An outpoint an input spends. TS: src/reputationIndexer.ts::Prevout. */
typedef struct {
    char     txid[65]; /* 64-hex DISPLAY prev txid + NUL                          */
    uint32_t vout;     /* previous output index                                   */
} indexer_prevout_t;

/* Def 2.6 score result. TS: { rho; weightTotal; count }. */
typedef struct {
    double rho;          /* sum(w_i*valid_i)/sum(w_i); 0 if no weight             */
    double weight_total; /* sum(w_i)                                              */
    size_t count;        /* number of receipts                                    */
} reputation_score_t;

/* ---- shred markers ------------------------------------------------------ */

/* shredMarkerHex(identityId) = hex(SHA256("SHRED_V1" || identityId)). Writes a
 * freshly malloc'd 64-hex string to *out (caller frees). MUST byte-match
 * PrivateEnclave.shredMarker. TS: shredMarkerHex. BNS_OK / BNS_ENOMEM. */
int shred_marker_hex(const char *identity_id, char **out);

/* Lowercased equality of an OP_RETURN 32-byte hex value against
 * shredMarkerHex(identityId). Pure predicate. TS: isShredMarkerFor. */
bool is_shred_marker_for(const char *opreturn32_hex, const char *identity_id);

/* Set erased=true on every receipt whose receipt_hash is the shred marker for
 * `identity_id`; leaves `valid` untouched (data gone, receipt stands). Sets
 * *out_erased_at to the EARLIEST erased receipt time, or -1 if none erased
 * (the nullable in TS). Mutates `receipts` in place. TS: annotateErasure.
 * BNS_OK / BNS_EINVAL. */
int annotate_erasure(tea_receipts_t *receipts, const char *identity_id,
                     int64_t *out_erased_at);

/* ---- tx-shape helpers (over a raw tx hex) ------------------------------- */

/* Extract the 32-byte OP_RETURN receipt hash from a raw tx: the first 0-sat
 * output whose script starts '006a' and whose LAST chunk is EXACTLY 32 bytes.
 * On success writes a freshly malloc'd 64-hex string to *out_hex (caller frees);
 * on no-match sets *out_hex = NULL and returns BNS_OK (the TS `null`).
 * TS: parseReceiptHash. BNS_OK / BNS_EPARSE (malformed tx) / BNS_ENOMEM. */
int indexer_parse_receipt_hash(const char *raw_tx_hex, char **out_hex);

/* True iff output[0] is a standard P2PKH OR there are no outputs — i.e. the
 * spend does NOT recreate the identity (revoke/slash refund/bounty), so the
 * walk terminates. Pure predicate; fail-closed (false) on parse error is the
 * caller's concern — see notes. TS: isTerminalIdentitySpend. */
bool is_terminal_identity_spend(const char *raw_tx_hex);

/* Return the outpoint spent by input[inputIndex] (default 0). Uses the parser's
 * DISPLAY-hex prevTxId verbatim. BNS_OK / BNS_EPARSE (no such input).
 * TS: parsePrevout. */
int indexer_parse_prevout(const char *raw_tx_hex, size_t input_index,
                          indexer_prevout_t *out);

/* ---- walks -------------------------------------------------------------- */

/* Optional per-receipt validity hook. Returns the `valid` flag for a candidate
 * receipt (given its txid/time/receiptHash). NULL => default ()=>true.
 * TS: markValid(Omit<TeaReceipt,'valid'>). */
typedef bool (*indexer_mark_valid_fn)(void *user,
                                      const char *txid, int64_t time,
                                      const char *receipt_hash);

/* Forward walk: start at (genesis_txid, identity_vout), follow output[0] via
 * source->get_spending_txid; collect receipts oldest-first; stop on unspent tip
 * or terminal P2PKH spend. Genesis carries no receipt (walk starts at its
 * spender). Requires source->get_spending_txid != NULL (else BNS_EINVAL).
 * TS: collectReceipts. *out (caller frees via tea_receipts_free).
 * BNS_OK / BNS_EINVAL (no spend index) / BNS_ENET / BNS_EPARSE / BNS_ENOMEM. */
int collect_receipts(const char *genesis_txid, uint32_t identity_vout,
                     const chain_source_t *source,
                     indexer_mark_valid_fn mark_valid, void *mark_valid_user,
                     tea_receipts_t *out);

/* Backward walk: tip -> genesis via input[input_index] (default 0) prevouts (no
 * spend index needed). Throws (BNS_EPARSE/BNS_EHOPLIMIT) on a terminal spend
 * mid-walk or if genesis is not reached within max_hops (wrong tip fails loudly,
 * never returns partial). Stops WITHOUT including genesis; result is oldest-first.
 * `max_hops` == 0 => BONSAI_INDEXER_MAX_BACKWARD_HOPS. TS: collectReceiptsBackward.
 * BNS_OK / BNS_EHOPLIMIT / BNS_EPARSE / BNS_ENET / BNS_ENOMEM. */
int collect_receipts_backward(const char *tip_txid, const char *genesis_txid,
                              const chain_source_t *source,
                              size_t input_index,
                              indexer_mark_valid_fn mark_valid,
                              void *mark_valid_user,
                              size_t max_hops,
                              tea_receipts_t *out);

/* Def 2.6 score: rho = sum(w_i*valid_i)/sum(w_i), w_i = exp(-lambda*max(0,
 * now - t_i)); rho = 0 if total weight is 0. IEEE-754 double; keep TS order.
 * TS: reputationScore. BNS_OK / BNS_EINVAL (lambda <= 0). */
int reputation_score(const tea_receipts_t *receipts, int64_t now,
                     double lambda, reputation_score_t *out);

/* End-to-end forward: collect_receipts then reputation_score. Optionally also
 * returns the collected receipts via *out_receipts (NULL to discard).
 * TS: computeReputation. BNS_OK / (errors of the two stages). */
int compute_reputation(const char *genesis_txid, uint32_t identity_vout,
                       const chain_source_t *source,
                       int64_t now, double lambda,
                       indexer_mark_valid_fn mark_valid, void *mark_valid_user,
                       reputation_score_t *out_score,
                       tea_receipts_t *out_receipts);

/* End-to-end backward: collect_receipts_backward then reputation_score
 * (preferred for spend-index-less providers such as WhatsOnChain).
 * `max_hops` == 0 => default. TS: computeReputationBackward. */
int compute_reputation_backward(const char *tip_txid, const char *genesis_txid,
                                const chain_source_t *source,
                                int64_t now, double lambda, size_t max_hops,
                                indexer_mark_valid_fn mark_valid,
                                void *mark_valid_user,
                                reputation_score_t *out_score,
                                tea_receipts_t *out_receipts);

#endif /* BONSAI_REPUTATION_INDEXER_H */
