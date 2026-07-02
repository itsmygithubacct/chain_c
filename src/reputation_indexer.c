/*
 * reputation_indexer.c — off-chain reputation indexer (Sgantzos & Ferrara 2026
 * Definition 2.6).
 *
 * Faithful port of src/reputationIndexer.ts. Walks an identity's append-only
 * UTXO chain (forward via a spend index, or backward from a tip via input[0]
 * prevouts), parses each executeTea OP_RETURN "Third Entry" receipt, annotates
 * crypto-shred erasure markers, and computes the exponentially-decayed weighted
 * reputation score rho.
 *
 * BYTE/FLOAT-EXACTNESS:
 *  - shred_marker_hex: SHA256("SHRED_V1" || identityId), lowercase hex.
 *  - parse_receipt_hash: first 0-sat output whose script starts 006a and whose
 *    LAST chunk is exactly 32 bytes (delegates to bsv/script.h).
 *  - prevTxId is the DISPLAY (big-endian) hex from the shared tx parser — never
 *    reversed again here.
 *  - reputation_score: w = exp(-lambda * max(0, now - t)); accumulate den then
 *    conditionally num, in TS order, with IEEE-754 double + libm exp().
 */
#include "reputation_indexer.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "bsv/tx.h"
#include "bsv/script.h"
#include "chain/tx_parse.h"
#include "crypto/hash.h"
#include "common/hex.h"

/* ---- receipts list ------------------------------------------------------ */

void tea_receipts_free(tea_receipts_t *r)
{
    if (r == NULL) {
        return;
    }
    free(r->items);
    r->items = NULL;
    r->count = 0;
}

/* Append one receipt to an owned, growing list. Returns BNS_OK / BNS_ENOMEM. */
static int receipts_push(tea_receipts_t *r, const tea_receipt_t *item)
{
    /* Geometric growth; r->count doubles as the count we track for the result. */
    tea_receipt_t *grown =
        realloc(r->items, (r->count + 1) * sizeof(*r->items));
    if (grown == NULL) {
        return BNS_ENOMEM;
    }
    r->items = grown;
    r->items[r->count] = *item;
    r->count += 1;
    return BNS_OK;
}

/* ---- shred markers ------------------------------------------------------ */

/* TS: createHash('sha256').update('SHRED_V1').update(identityId).digest('hex') */
int shred_marker_hex(const char *identity_id, char **out)
{
    if (identity_id == NULL || out == NULL) {
        return BNS_EINVAL;
    }
    *out = NULL;

    /* SHA256 over the concatenation "SHRED_V1" || identityId (UTF-8 bytes). */
    static const char marker[] = "SHRED_V1"; /* 8 bytes, no NUL */
    size_t id_len = strlen(identity_id);
    size_t total = 8 + id_len;

    uint8_t *buf = malloc(total == 0 ? 1 : total);
    if (buf == NULL) {
        return BNS_ENOMEM;
    }
    memcpy(buf, marker, 8);
    if (id_len > 0) {
        memcpy(buf + 8, identity_id, id_len);
    }

    uint8_t digest[BONSAI_SHA256_LEN];
    sha256(buf, total, digest);
    free(buf);

    char *hex = hex_encode(digest, BONSAI_SHA256_LEN);
    if (hex == NULL) {
        return BNS_ENOMEM;
    }
    *out = hex;
    return BNS_OK;
}

/* TS: opReturn32Hex.toLowerCase() === shredMarkerHex(identityId).
 * hex_encode already yields lowercase; lowercase the input for comparison. */
bool is_shred_marker_for(const char *opreturn32_hex, const char *identity_id)
{
    if (opreturn32_hex == NULL || identity_id == NULL) {
        return false;
    }

    char *marker = NULL;
    if (shred_marker_hex(identity_id, &marker) != BNS_OK || marker == NULL) {
        return false;
    }

    bool eq = true;
    size_t i = 0;
    for (;; i++) {
        char a = opreturn32_hex[i];
        char b = marker[i];
        /* lowercase a (ASCII) to mirror JS String.toLowerCase on hex */
        if (a >= 'A' && a <= 'Z') {
            a = (char)(a - 'A' + 'a');
        }
        if (a != b) {
            eq = false;
            break;
        }
        if (a == '\0') {
            /* both reached NUL simultaneously => equal */
            break;
        }
    }

    free(marker);
    return eq;
}

/* TS: annotateErasure — set erased=true on shred-marker receipts; out_erased_at
 * is the EARLIEST erased time (or -1 if none). valid is left untouched. */
int annotate_erasure(tea_receipts_t *receipts, const char *identity_id,
                     int64_t *out_erased_at)
{
    if (receipts == NULL || identity_id == NULL) {
        return BNS_EINVAL;
    }

    int64_t erased_at = -1; /* the TS `null` */
    bool have = false;

    for (size_t i = 0; i < receipts->count; i++) {
        tea_receipt_t *r = &receipts->items[i];
        if (is_shred_marker_for(r->receipt_hash, identity_id)) {
            r->erased = true;
            /* erasedAt = erasedAt === null ? r.time : Math.min(erasedAt, r.time) */
            if (!have) {
                erased_at = r->time;
                have = true;
            } else if (r->time < erased_at) {
                erased_at = r->time;
            }
        }
    }

    if (out_erased_at != NULL) {
        *out_erased_at = erased_at;
    }
    return BNS_OK;
}

/* ---- tx-shape helpers --------------------------------------------------- */

/* TS: parseReceiptHash(rawTxHex) — scan outputs, first 0-sat output whose script
 * hex starts '006a' and whose LAST chunk is exactly 32 bytes wins; else null. */
int indexer_parse_receipt_hash(const char *raw_tx_hex, char **out_hex)
{
    if (raw_tx_hex == NULL || out_hex == NULL) {
        return BNS_EPARSE;
    }
    *out_hex = NULL;

    bsv_tx_t tx;
    tx_init(&tx);
    if (tx_deserialize(raw_tx_hex, &tx) != BNS_OK) {
        tx_free(&tx);
        return BNS_EPARSE;
    }

    for (size_t i = 0; i < tx.num_outputs; i++) {
        const bsv_txout_t *o = &tx.outputs[i];
        /* Number(out.satoshis) === 0 */
        if (o->satoshis != 0) {
            continue;
        }
        /* parse_receipt_hash enforces both the '006a' prefix and the exactly-32
         * last-chunk rule; BNS_EPARSE means this output doesn't qualify — skip
         * it and keep scanning (TS skips non-matching outputs and continues). */
        uint8_t hash32[32];
        int rc = parse_receipt_hash(o->script.data, o->script.len, hash32);
        if (rc == BNS_OK) {
            char *hex = hex_encode(hash32, 32);
            if (hex == NULL) {
                tx_free(&tx);
                return BNS_ENOMEM;
            }
            *out_hex = hex;
            tx_free(&tx);
            return BNS_OK;
        }
        if (rc == BNS_ENOMEM) {
            tx_free(&tx);
            return BNS_ENOMEM;
        }
        /* BNS_EPARSE / BNS_EINVAL: not a qualifying receipt output, continue. */
    }

    tx_free(&tx);
    return BNS_OK; /* TS: return null */
}

/* TS: isTerminalIdentitySpend — delegates to the shared parser. */
bool is_terminal_identity_spend(const char *raw_tx_hex)
{
    return is_terminal_spend(raw_tx_hex);
}

/* TS: parsePrevout — delegates to the shared parser (DISPLAY-hex prevTxId). */
int indexer_parse_prevout(const char *raw_tx_hex, size_t input_index,
                          indexer_prevout_t *out)
{
    if (out == NULL) {
        return BNS_EPARSE;
    }
    tx_prevout_t p;
    int rc = parse_prevout(raw_tx_hex, input_index, &p);
    if (rc != BNS_OK) {
        return rc;
    }
    memcpy(out->txid, p.txid, sizeof(out->txid));
    out->txid[sizeof(out->txid) - 1] = '\0';
    out->vout = p.vout;
    return BNS_OK;
}

/* ---- walks -------------------------------------------------------------- */

/* TS: collectReceipts — forward walk following output[0] via getSpendingTxid. */
int collect_receipts(const char *genesis_txid, uint32_t identity_vout,
                     const chain_source_t *source,
                     indexer_mark_valid_fn mark_valid, void *mark_valid_user,
                     tea_receipts_t *out)
{
    if (genesis_txid == NULL || source == NULL || out == NULL) {
        return BNS_EINVAL;
    }
    out->items = NULL;
    out->count = 0;

    /* TS: if (!source.getSpendingTxid) throw ... */
    if (source->get_spending_txid == NULL) {
        return BNS_EINVAL;
    }

    int rc = BNS_OK;
    char *txid = strdup(genesis_txid);
    if (txid == NULL) {
        return BNS_ENOMEM;
    }
    uint32_t vout = identity_vout;

    for (size_t hops = 0; hops < (size_t)BONSAI_INDEXER_MAX_HOPS && txid != NULL;
         hops++) {
        char *next_txid = NULL;
        rc = source->get_spending_txid(source->ctx, txid, vout, &next_txid);
        if (rc != BNS_OK) {
            break;
        }
        if (next_txid == NULL) {
            /* identity currently unspent -> end of chain */
            break;
        }

        char *raw_tx = NULL;
        rc = source->get_raw_tx(source->ctx, next_txid, &raw_tx);
        if (rc != BNS_OK) {
            free(next_txid);
            break;
        }

        /* Terminate by template, not by receipt-absence. */
        if (is_terminal_identity_spend(raw_tx)) {
            free(raw_tx);
            free(next_txid);
            break;
        }

        char *receipt_hash = NULL;
        rc = indexer_parse_receipt_hash(raw_tx, &receipt_hash);
        if (rc != BNS_OK) {
            free(raw_tx);
            free(next_txid);
            break;
        }
        free(raw_tx);

        if (receipt_hash != NULL) {
            int64_t time = 0;
            rc = source->get_time(source->ctx, next_txid, &time);
            if (rc != BNS_OK) {
                free(receipt_hash);
                free(next_txid);
                break;
            }

            tea_receipt_t r;
            memset(&r, 0, sizeof(r));
            /* next_txid is 64-hex DISPLAY; copy into fixed buffer. */
            strncpy(r.txid, next_txid, sizeof(r.txid) - 1);
            r.txid[sizeof(r.txid) - 1] = '\0';
            r.time = time;
            strncpy(r.receipt_hash, receipt_hash, sizeof(r.receipt_hash) - 1);
            r.receipt_hash[sizeof(r.receipt_hash) - 1] = '\0';
            r.erased = false;
            /* valid = markValid(base); default ()=>true */
            r.valid = (mark_valid != NULL)
                          ? mark_valid(mark_valid_user, r.txid, r.time,
                                       r.receipt_hash)
                          : true;

            free(receipt_hash);

            rc = receipts_push(out, &r);
            if (rc != BNS_OK) {
                free(next_txid);
                break;
            }
        }

        /* The identity is recreated at output[0]; keep walking down it. */
        free(txid);
        txid = next_txid;
        vout = 0;
    }

    free(txid);

    if (rc != BNS_OK) {
        tea_receipts_free(out);
    }
    return rc;
}

/* TS: collectReceiptsBackward — tip -> genesis via input[input_index] prevouts.
 * Collects newest-first then reverses to oldest-first. */
int collect_receipts_backward(const char *tip_txid, const char *genesis_txid,
                              const chain_source_t *source,
                              size_t input_index,
                              indexer_mark_valid_fn mark_valid,
                              void *mark_valid_user,
                              size_t max_hops,
                              tea_receipts_t *out)
{
    if (tip_txid == NULL || genesis_txid == NULL || source == NULL ||
        out == NULL) {
        return BNS_EINVAL;
    }
    out->items = NULL;
    out->count = 0;

    if (max_hops == 0) {
        max_hops = BONSAI_INDEXER_MAX_BACKWARD_HOPS;
    }

    int rc = BNS_OK;
    char *txid = strdup(tip_txid);
    if (txid == NULL) {
        return BNS_ENOMEM;
    }

    /* TS: for (hops=0; txid && txid !== genesisTxid; hops++) */
    for (size_t hops = 0; txid != NULL && strcmp(txid, genesis_txid) != 0;
         hops++) {
        if (hops >= max_hops) {
            /* wrong tip must fail loudly, never return a partial history */
            rc = BNS_EHOPLIMIT;
            break;
        }

        char *raw_tx = NULL;
        rc = source->get_raw_tx(source->ctx, txid, &raw_tx);
        if (rc != BNS_OK) {
            break;
        }

        /* Terminal guard: a mid-walk terminal spend means a wrong/forged tip. */
        if (is_terminal_identity_spend(raw_tx)) {
            free(raw_tx);
            rc = BNS_EPARSE;
            break;
        }

        char *receipt_hash = NULL;
        rc = indexer_parse_receipt_hash(raw_tx, &receipt_hash);
        if (rc != BNS_OK) {
            free(raw_tx);
            break;
        }

        if (receipt_hash != NULL) {
            int64_t time = 0;
            rc = source->get_time(source->ctx, txid, &time);
            if (rc != BNS_OK) {
                free(receipt_hash);
                free(raw_tx);
                break;
            }

            tea_receipt_t r;
            memset(&r, 0, sizeof(r));
            strncpy(r.txid, txid, sizeof(r.txid) - 1);
            r.txid[sizeof(r.txid) - 1] = '\0';
            r.time = time;
            strncpy(r.receipt_hash, receipt_hash, sizeof(r.receipt_hash) - 1);
            r.receipt_hash[sizeof(r.receipt_hash) - 1] = '\0';
            r.erased = false;
            r.valid = (mark_valid != NULL)
                          ? mark_valid(mark_valid_user, r.txid, r.time,
                                       r.receipt_hash)
                          : true;

            free(receipt_hash);

            rc = receipts_push(out, &r);
            if (rc != BNS_OK) {
                free(raw_tx);
                break;
            }
        }

        /* Step back to the previous identity tx via input[input_index]. */
        indexer_prevout_t prev;
        rc = indexer_parse_prevout(raw_tx, input_index, &prev);
        free(raw_tx);
        if (rc != BNS_OK) {
            break;
        }

        char *prev_txid = strdup(prev.txid);
        if (prev_txid == NULL) {
            rc = BNS_ENOMEM;
            break;
        }
        free(txid);
        txid = prev_txid;
    }

    free(txid);

    if (rc != BNS_OK) {
        tea_receipts_free(out);
        return rc;
    }

    /* TS: newestFirst.reverse() -> oldest-first. */
    for (size_t i = 0, j = out->count; i + 1 <= j && j > 0; i++) {
        j--;
        if (i >= j) {
            break;
        }
        tea_receipt_t tmp = out->items[i];
        out->items[i] = out->items[j];
        out->items[j] = tmp;
    }

    return BNS_OK;
}

/* ---- score (Def 2.6) ---------------------------------------------------- */

/* TS: reputationScore(receipts, now, lambda):
 *   if (lambda <= 0) throw
 *   for r: w = Math.exp(-lambda * Math.max(0, now - r.time));
 *          den += w; if (r.valid) num += w
 *   rho = den === 0 ? 0 : num/den; weightTotal = den; count = receipts.length
 * IEEE-754 double, libm exp(), same accumulation order. */
int reputation_score(const tea_receipts_t *receipts, int64_t now,
                     double lambda, reputation_score_t *out)
{
    if (out == NULL) {
        return BNS_EINVAL;
    }
    if (lambda <= 0) {
        return BNS_EINVAL;
    }

    double num = 0.0;
    double den = 0.0;
    size_t count = 0;

    if (receipts != NULL) {
        count = receipts->count;
        for (size_t i = 0; i < receipts->count; i++) {
            const tea_receipt_t *r = &receipts->items[i];
            /* Math.max(0, now - r.time): future-clamp. JS computes this as a
             * Number (double); now-r.time may exceed int64 only at absurd scale,
             * compute in int64 then clamp, then promote to double — matching the
             * JS double arithmetic for all realistic inputs. */
            int64_t delta = now - r->time;
            double age = (delta > 0) ? (double)delta : 0.0;
            double w = exp(-lambda * age);
            den += w;
            if (r->valid) {
                num += w;
            }
        }
    }

    out->rho = (den == 0.0) ? 0.0 : (num / den);
    out->weight_total = den;
    out->count = count;
    return BNS_OK;
}

/* ---- end-to-end --------------------------------------------------------- */

/* TS: computeReputation — collectReceipts then reputationScore. */
int compute_reputation(const char *genesis_txid, uint32_t identity_vout,
                       const chain_source_t *source,
                       int64_t now, double lambda,
                       indexer_mark_valid_fn mark_valid, void *mark_valid_user,
                       reputation_score_t *out_score,
                       tea_receipts_t *out_receipts)
{
    tea_receipts_t receipts = {0};
    int rc = collect_receipts(genesis_txid, identity_vout, source, mark_valid,
                              mark_valid_user, &receipts);
    if (rc != BNS_OK) {
        return rc;
    }

    if (out_score != NULL) {
        rc = reputation_score(&receipts, now, lambda, out_score);
        if (rc != BNS_OK) {
            tea_receipts_free(&receipts);
            return rc;
        }
    }

    if (out_receipts != NULL) {
        *out_receipts = receipts; /* transfer ownership */
    } else {
        tea_receipts_free(&receipts);
    }
    return BNS_OK;
}

/* TS: computeReputationBackward — collectReceiptsBackward then reputationScore. */
int compute_reputation_backward(const char *tip_txid, const char *genesis_txid,
                                const chain_source_t *source,
                                int64_t now, double lambda, size_t max_hops,
                                indexer_mark_valid_fn mark_valid,
                                void *mark_valid_user,
                                reputation_score_t *out_score,
                                tea_receipts_t *out_receipts)
{
    tea_receipts_t receipts = {0};
    int rc = collect_receipts_backward(tip_txid, genesis_txid, source, 0,
                                       mark_valid, mark_valid_user, max_hops,
                                       &receipts);
    if (rc != BNS_OK) {
        return rc;
    }

    if (out_score != NULL) {
        rc = reputation_score(&receipts, now, lambda, out_score);
        if (rc != BNS_OK) {
            tea_receipts_free(&receipts);
            return rc;
        }
    }

    if (out_receipts != NULL) {
        *out_receipts = receipts; /* transfer ownership */
    } else {
        tea_receipts_free(&receipts);
    }
    return BNS_OK;
}
