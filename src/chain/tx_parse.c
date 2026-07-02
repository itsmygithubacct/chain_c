/*
 * tx_parse.c — shared tx-shape parser (parse_prevout / is_terminal_spend).
 *
 * Delegates to the frozen bsv/tx.h model, inheriting its DISPLAY-hex
 * (big-endian) prevTxId convention. TS origin: src/reputationIndexer.ts
 * parsePrevout / isTerminalIdentitySpend.
 */
#include "chain/tx_parse.h"

#include <string.h>

#include "bsv/tx.h"
#include "bsv/script.h"

/* TS: parsePrevout(rawTxHex, inputIndex):
 *   const tx = new bsv.Transaction(rawTxHex)
 *   const inp = tx.inputs[inputIndex]
 *   if (!inp) throw new Error(`no input at index ${inputIndex}`)
 *   return { txid: inp.prevTxId.toString('hex'), vout: inp.outputIndex }
 * inp.prevTxId.toString('hex') is the DISPLAY (big-endian) hex, which tx_deserialize
 * already stores in prev_txid_display. */
int parse_prevout(const char *raw_tx_hex, size_t input_index, tx_prevout_t *out)
{
    if (raw_tx_hex == NULL || out == NULL) {
        return BNS_EPARSE;
    }

    bsv_tx_t tx;
    tx_init(&tx);

    int rc = tx_deserialize(raw_tx_hex, &tx);
    if (rc != BNS_OK) {
        tx_free(&tx);
        return BNS_EPARSE;
    }

    if (input_index >= tx.num_inputs) {
        /* TS: throw new Error(`no input at index ${inputIndex}`) */
        tx_free(&tx);
        return BNS_EPARSE;
    }

    const bsv_txin_t *inp = &tx.inputs[input_index];

    /* prev_txid_display is the 64-char DISPLAY hex + NUL. */
    memcpy(out->txid, inp->prev_txid_display, sizeof(out->txid));
    out->txid[sizeof(out->txid) - 1] = '\0';
    out->vout = inp->vout;

    tx_free(&tx);
    return BNS_OK;
}

/* TS: isTerminalIdentitySpend(rawTxHex):
 *   const tx = new bsv.Transaction(rawTxHex)
 *   const out0 = tx.outputs[0]
 *   if (!out0) return true
 *   return out0.script.isPublicKeyHashOut()
 * Fail-closed on malformed tx (returns false) per the header contract. */
bool is_terminal_spend(const char *raw_tx_hex)
{
    if (raw_tx_hex == NULL) {
        return false;
    }

    bsv_tx_t tx;
    tx_init(&tx);

    if (tx_deserialize(raw_tx_hex, &tx) != BNS_OK) {
        /* Malformed tx: fail-closed. */
        tx_free(&tx);
        return false;
    }

    bool terminal;
    if (tx.num_outputs == 0) {
        /* if (!out0) return true */
        terminal = true;
    } else {
        const bsv_txout_t *out0 = &tx.outputs[0];
        terminal = is_p2pkh_out(out0->script.data, out0->script.len, NULL);
    }

    tx_free(&tx);
    return terminal;
}
