/*
 * sighash.c — BIP143/FORKID sighash preimage + digest for BSV signing.
 *
 * Implements include/bsv/sighash.h. Builds the BSV (BIP143-style, FORKID)
 * sighash preimage and its double-SHA256 digest.
 *
 * Preimage field order (BIP143):
 *   nVersion(4 LE) | hashPrevouts(32) | hashSequence(32) |
 *   outpoint(txid 32 LE ‖ vout 4 LE) | scriptCode(varint len ‖ bytes) |
 *   amount(8 LE) | nSequence(4 LE) | hashOutputs(32) |
 *   nLocktime(4 LE) | sighashType(4 LE)
 *
 * For SIGHASH_ALL | FORKID (0x41) — the only flag this port signs with — none of
 * the ANYONECANPAY / SINGLE / NONE special-cases apply, so:
 *   hashPrevouts = sha256d( for each input: outpoint(txid 32 LE ‖ vout 4 LE) )
 *   hashSequence = sha256d( for each input: nSequence 4 LE )
 *   hashOutputs  = sha256d( for each output: amount 8 LE ‖ varint scriptLen ‖ script )
 *
 * Outpoint txid is written little-endian on the wire: reverse of the 64-char
 * big-endian DISPLAY hex stored in bsv_txin_t.prev_txid_display (see tx.h).
 */
#include "bsv/sighash.h"

#include <string.h>

#include "bsv/varint.h"
#include "common/hex.h"
#include "crypto/hash.h"

/* ---- little-endian fixed-width appenders -------------------------------- */

static int append_u32_le(byte_buf_t *out, uint32_t v) {
    uint8_t b[4] = {
        (uint8_t)(v & 0xff),
        (uint8_t)((v >> 8) & 0xff),
        (uint8_t)((v >> 16) & 0xff),
        (uint8_t)((v >> 24) & 0xff),
    };
    return byte_buf_append(out, b, sizeof b);
}

static int append_u64_le(byte_buf_t *out, uint64_t v) {
    uint8_t b[8];
    for (int i = 0; i < 8; i++) {
        b[i] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
    return byte_buf_append(out, b, sizeof b);
}

/* Append a single input's wire outpoint: txid (32 LE) ‖ vout (4 LE).
 * prev_txid_display is 64-char big-endian DISPLAY hex; reverse to LE wire. */
static int append_outpoint(byte_buf_t *out, const bsv_txin_t *in) {
    uint8_t be[BONSAI_SHA256_LEN];
    int rc = hex_decode_fixed(in->prev_txid_display, be, sizeof be);
    if (rc != BNS_OK) return rc;
    uint8_t le[BONSAI_SHA256_LEN];
    for (size_t i = 0; i < sizeof be; i++)
        le[i] = be[sizeof be - 1 - i];
    rc = byte_buf_append(out, le, sizeof le);
    if (rc != BNS_OK) return rc;
    return append_u32_le(out, in->vout);
}

/* ---- the three BIP143 mid-state double-hashes --------------------------- */

static int hash_prevouts(const bsv_tx_t *tx, uint8_t out[BONSAI_SHA256_LEN]) {
    byte_buf_t acc;
    byte_buf_init(&acc);
    int rc = BNS_OK;
    for (size_t i = 0; i < tx->num_inputs; i++) {
        rc = append_outpoint(&acc, &tx->inputs[i]);
        if (rc != BNS_OK) goto done;
    }
    sha256d(acc.data, acc.len, out);
done:
    byte_buf_free(&acc);
    return rc;
}

static int hash_sequence(const bsv_tx_t *tx, uint8_t out[BONSAI_SHA256_LEN]) {
    byte_buf_t acc;
    byte_buf_init(&acc);
    int rc = BNS_OK;
    for (size_t i = 0; i < tx->num_inputs; i++) {
        rc = append_u32_le(&acc, tx->inputs[i].sequence);
        if (rc != BNS_OK) goto done;
    }
    sha256d(acc.data, acc.len, out);
done:
    byte_buf_free(&acc);
    return rc;
}

static int hash_outputs(const bsv_tx_t *tx, uint8_t out[BONSAI_SHA256_LEN]) {
    byte_buf_t acc;
    byte_buf_init(&acc);
    int rc = BNS_OK;
    for (size_t i = 0; i < tx->num_outputs; i++) {
        const bsv_txout_t *o = &tx->outputs[i];
        rc = append_u64_le(&acc, o->satoshis);
        if (rc != BNS_OK) goto done;
        rc = write_varint(o->script.len, &acc);
        if (rc != BNS_OK) goto done;
        rc = byte_buf_append(&acc, o->script.data, o->script.len);
        if (rc != BNS_OK) goto done;
    }
    sha256d(acc.data, acc.len, out);
done:
    byte_buf_free(&acc);
    return rc;
}

/* ---- public API --------------------------------------------------------- */

int bip143_preimage(const bsv_tx_t *tx, size_t input_index,
                    const uint8_t *script_code, size_t script_code_len,
                    uint64_t input_satoshis, uint8_t sighash_type,
                    byte_buf_t *out) {
    if (tx == NULL || out == NULL) return BNS_EINVAL;
    if (input_index >= tx->num_inputs) return BNS_EINVAL;
    if (script_code_len != 0 && script_code == NULL) return BNS_EINVAL;

    uint8_t hp[BONSAI_SHA256_LEN], hs[BONSAI_SHA256_LEN], ho[BONSAI_SHA256_LEN];
    int rc = hash_prevouts(tx, hp);
    if (rc != BNS_OK) return rc;
    rc = hash_sequence(tx, hs);
    if (rc != BNS_OK) return rc;
    rc = hash_outputs(tx, ho);
    if (rc != BNS_OK) return rc;

    const bsv_txin_t *in = &tx->inputs[input_index];

    /* nVersion */
    rc = append_u32_le(out, tx->version);
    if (rc != BNS_OK) return rc;
    /* hashPrevouts | hashSequence */
    rc = byte_buf_append(out, hp, sizeof hp);
    if (rc != BNS_OK) return rc;
    rc = byte_buf_append(out, hs, sizeof hs);
    if (rc != BNS_OK) return rc;
    /* outpoint (txid 32 LE ‖ vout 4 LE) */
    rc = append_outpoint(out, in);
    if (rc != BNS_OK) return rc;
    /* scriptCode: varint length ‖ bytes */
    rc = write_varint(script_code_len, out);
    if (rc != BNS_OK) return rc;
    rc = byte_buf_append(out, script_code, script_code_len);
    if (rc != BNS_OK) return rc;
    /* amount (8 LE) | nSequence (4 LE) */
    rc = append_u64_le(out, input_satoshis);
    if (rc != BNS_OK) return rc;
    rc = append_u32_le(out, in->sequence);
    if (rc != BNS_OK) return rc;
    /* hashOutputs */
    rc = byte_buf_append(out, ho, sizeof ho);
    if (rc != BNS_OK) return rc;
    /* nLocktime (4 LE) | sighashType (4 LE) */
    rc = append_u32_le(out, tx->locktime);
    if (rc != BNS_OK) return rc;
    /* sighashType is the full 4-byte LE value; high bytes are 0 for 0x41. */
    rc = append_u32_le(out, (uint32_t)sighash_type);
    if (rc != BNS_OK) return rc;

    return BNS_OK;
}

int bip143_sighash(const bsv_tx_t *tx, size_t input_index,
                   const uint8_t *script_code, size_t script_code_len,
                   uint64_t input_satoshis, uint8_t sighash_type,
                   uint8_t out_digest32[BONSAI_SHA256_LEN]) {
    if (out_digest32 == NULL) return BNS_EINVAL;
    byte_buf_t pre;
    byte_buf_init(&pre);
    int rc = bip143_preimage(tx, input_index, script_code, script_code_len,
                             input_satoshis, sighash_type, &pre);
    if (rc != BNS_OK) {
        byte_buf_free(&pre);
        return rc;
    }
    sha256d(pre.data, pre.len, out_digest32);
    byte_buf_free(&pre);
    return BNS_OK;
}
