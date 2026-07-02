/*
 * tx_builder.c — incremental transaction builder.
 *
 * Accumulates inputs/outputs onto a bsv_tx_t and serializes to raw hex.
 *
 * TS origin: bsv.Transaction builder chain (.addInput/.addOutput/.from/
 * .change/.lockUntilDate/sequence) used by the tx builders and cpfp/agentd.
 *
 * The model stores txids as 64-char DISPLAY (big-endian) hex (see bsv/tx.h);
 * tx_serialize reverses to LE on the wire. A fresh bsv.Transaction defaults to
 * version 1, locktime 0 (matches bsv.js Transaction.CURRENT_VERSION = 1).
 */
#include "bsv/tx_builder.h"

#include <stdlib.h>
#include <string.h>

#include "common/hex.h"

/* new bsv.Transaction(): version 1, no inputs/outputs, locktime 0. */
void tx_builder_init(tx_builder_t *b)
{
    if (!b) return;
    tx_init(&b->tx);
    b->tx.version = 1;
    b->tx.locktime = 0;
}

void tx_builder_free(tx_builder_t *b)
{
    if (!b) return;
    tx_free(&b->tx);
}

/* tx.addInput(...) — append one input spending prev_txid_display:vout. */
int tx_builder_add_input(tx_builder_t *b, const char *prev_txid_display,
                         uint32_t vout, const uint8_t *script_sig,
                         size_t script_sig_len, uint32_t sequence)
{
    if (!b || !prev_txid_display) return BNS_EINVAL;
    /* DISPLAY txid must be exactly 64 lowercase/uppercase hex chars. */
    if (!is_hex_len(prev_txid_display, 32)) return BNS_EINVAL;

    size_t n = b->tx.num_inputs;
    bsv_txin_t *grown =
        realloc(b->tx.inputs, (n + 1) * sizeof(*b->tx.inputs));
    if (!grown) return BNS_ENOMEM;
    b->tx.inputs = grown;

    bsv_txin_t *in = &b->tx.inputs[n];
    memset(in, 0, sizeof(*in));

    /* Store the DISPLAY txid lowercased (the model's canonical form). */
    for (size_t i = 0; i < 64; i++) {
        char c = prev_txid_display[i];
        if (c >= 'A' && c <= 'F') c = (char)(c - 'A' + 'a');
        in->prev_txid_display[i] = c;
    }
    in->prev_txid_display[64] = '\0';
    in->vout = vout;
    in->sequence = sequence;

    byte_buf_init(&in->script_sig);
    if (script_sig && script_sig_len) {
        int rc = byte_buf_append(&in->script_sig, script_sig, script_sig_len);
        if (rc != BNS_OK) {
            byte_buf_free(&in->script_sig);
            return rc;
        }
    }

    b->tx.num_inputs = n + 1;
    return BNS_OK;
}

/* tx.addOutput(new Output({script, satoshis})). */
int tx_builder_add_output(tx_builder_t *b, const uint8_t *script,
                          size_t script_len, uint64_t satoshis)
{
    if (!b) return BNS_EINVAL;

    size_t n = b->tx.num_outputs;
    bsv_txout_t *grown =
        realloc(b->tx.outputs, (n + 1) * sizeof(*b->tx.outputs));
    if (!grown) return BNS_ENOMEM;
    b->tx.outputs = grown;

    bsv_txout_t *out = &b->tx.outputs[n];
    memset(out, 0, sizeof(*out));
    out->satoshis = satoshis;

    byte_buf_init(&out->script);
    if (script && script_len) {
        int rc = byte_buf_append(&out->script, script, script_len);
        if (rc != BNS_OK) {
            byte_buf_free(&out->script);
            return rc;
        }
    }

    b->tx.num_outputs = n + 1;
    return BNS_OK;
}

/* tx.lockUntilDate / nLockTime. */
void tx_builder_set_locktime(tx_builder_t *b, uint32_t locktime)
{
    if (!b) return;
    b->tx.locktime = locktime;
}

/* input.sequenceNumber = seq. */
int tx_builder_set_sequence(tx_builder_t *b, size_t index, uint32_t sequence)
{
    if (!b) return BNS_EINVAL;
    if (index >= b->tx.num_inputs) return BNS_EINVAL;
    b->tx.inputs[index].sequence = sequence;
    return BNS_OK;
}

/* tx.uncheckedSerialize() -> lowercase raw-tx hex string (*out, caller frees). */
int tx_builder_build_hex(const tx_builder_t *b, char **out)
{
    if (!b || !out) return BNS_EINVAL;
    *out = NULL;

    byte_buf_t raw;
    byte_buf_init(&raw);
    int rc = tx_serialize(&b->tx, &raw);
    if (rc != BNS_OK) {
        byte_buf_free(&raw);
        return rc;
    }

    char *hex = hex_encode(raw.data, raw.len);
    byte_buf_free(&raw);
    if (!hex) return BNS_ENOMEM;

    *out = hex;
    return BNS_OK;
}
