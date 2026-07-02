/*
 * tx.c — BSV transaction model: parse, serialize, txid.
 *
 * Ports bsv.Transaction (fromString / uncheckedSerialize / .id):
 *   serialize = version(4 LE) ‖ varint(nin) ‖ inputs ‖ varint(nout)
 *               ‖ outputs ‖ locktime(4 LE)
 *   input     = prevTxId(32, WIRE little-endian) ‖ vout(4 LE)
 *               ‖ varint(scriptlen) ‖ scriptSig ‖ sequence(4 LE)
 *   output    = satoshis(8 LE) ‖ varint(scriptlen) ‖ script
 *   txid      = REVERSED sha256d(serialized), as lowercase DISPLAY hex.
 *
 * prevTxId endianness (see tx.h header note): the model stores the 64-char
 * DISPLAY (big-endian) hex; the wire stores it little-endian (reversed). We
 * reverse on both deserialize (wire -> display) and serialize (display ->
 * wire). Same reversal yields the DISPLAY txid from sha256d (which is the
 * "hash", little-endian display when shown forward).
 */
#include "bsv/tx.h"
#include "bsv/varint.h"
#include "common/hex.h"
#include "crypto/hash.h"

#include <stdlib.h>
#include <string.h>

/* ---- little-endian fixed-width helpers ---------------------------------- */

static int append_u32_le(byte_buf_t *out, uint32_t v) {
    uint8_t b[4] = {
        (uint8_t)(v & 0xff),
        (uint8_t)((v >> 8) & 0xff),
        (uint8_t)((v >> 16) & 0xff),
        (uint8_t)((v >> 24) & 0xff),
    };
    return byte_buf_append(out, b, 4);
}

static int append_u64_le(byte_buf_t *out, uint64_t v) {
    uint8_t b[8];
    for (int i = 0; i < 8; i++) {
        b[i] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
    return byte_buf_append(out, b, 8);
}

/* Read a fixed-width LE integer; returns BNS_OK / BNS_EPARSE on truncation. */
static int read_u32_le(const uint8_t *data, size_t len, size_t off,
                       uint32_t *out) {
    if (off + 4 > len) return BNS_EPARSE;
    *out = (uint32_t)data[off]
         | ((uint32_t)data[off + 1] << 8)
         | ((uint32_t)data[off + 2] << 16)
         | ((uint32_t)data[off + 3] << 24);
    return BNS_OK;
}

static int read_u64_le(const uint8_t *data, size_t len, size_t off,
                       uint64_t *out) {
    if (off + 8 > len) return BNS_EPARSE;
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | data[off + (size_t)i];
    *out = v;
    return BNS_OK;
}

/* ---- lifecycle ---------------------------------------------------------- */

void tx_init(bsv_tx_t *tx) {
    if (!tx) return;
    tx->version = 0;
    tx->inputs = NULL;
    tx->num_inputs = 0;
    tx->outputs = NULL;
    tx->num_outputs = 0;
    tx->locktime = 0;
}

void tx_free(bsv_tx_t *tx) {
    if (!tx) return;
    if (tx->inputs) {
        for (size_t i = 0; i < tx->num_inputs; i++)
            byte_buf_free(&tx->inputs[i].script_sig);
        free(tx->inputs);
    }
    if (tx->outputs) {
        for (size_t i = 0; i < tx->num_outputs; i++)
            byte_buf_free(&tx->outputs[i].script);
        free(tx->outputs);
    }
    tx_init(tx);
}

/* ---- deserialize -------------------------------------------------------- */

int tx_deserialize(const char *hex, bsv_tx_t *tx) {
    if (!hex || !tx) return BNS_EINVAL;

    byte_buf_t raw;
    byte_buf_init(&raw);
    int rc = hex_decode(hex, &raw);
    if (rc != BNS_OK) {
        byte_buf_free(&raw);
        return BNS_EPARSE;
    }

    tx_init(tx);

    const uint8_t *d = raw.data;
    const size_t len = raw.len;
    size_t off = 0;
    varint_read_t vr;

    /* version (4 LE) */
    rc = read_u32_le(d, len, off, &tx->version);
    if (rc != BNS_OK) goto fail;
    off += 4;

    /* input count */
    rc = read_varint(d, len, off, &vr);
    if (rc != BNS_OK) goto fail;
    off += vr.consumed;
    tx->num_inputs = (size_t)vr.value;

    /* DoS guard: each input needs >=41 bytes (32+4+1+4); reject impossible counts */
    if (tx->num_inputs > (len - off) / 41) { rc = BNS_EPARSE; goto fail; }

    if (tx->num_inputs > 0) {
        tx->inputs = calloc(tx->num_inputs, sizeof(bsv_txin_t));
        if (!tx->inputs) { rc = BNS_ENOMEM; goto fail; }
        for (size_t i = 0; i < tx->num_inputs; i++)
            byte_buf_init(&tx->inputs[i].script_sig);
    }

    for (size_t i = 0; i < tx->num_inputs; i++) {
        bsv_txin_t *in = &tx->inputs[i];

        /* prevTxId: 32 wire bytes (LE) -> reverse -> DISPLAY hex */
        if (len - off < 32) { rc = BNS_EPARSE; goto fail; }
        uint8_t disp[32];
        for (size_t j = 0; j < 32; j++) disp[j] = d[off + 31 - j];
        rc = hex_encode_to(disp, 32, in->prev_txid_display,
                           sizeof(in->prev_txid_display));
        if (rc != BNS_OK) goto fail;
        off += 32;

        /* vout (4 LE) */
        rc = read_u32_le(d, len, off, &in->vout);
        if (rc != BNS_OK) goto fail;
        off += 4;

        /* scriptSig length + bytes */
        rc = read_varint(d, len, off, &vr);
        if (rc != BNS_OK) goto fail;
        off += vr.consumed;
        size_t slen = (size_t)vr.value;
        if (slen > len - off) { rc = BNS_EPARSE; goto fail; }
        rc = byte_buf_append(&in->script_sig, d + off, slen);
        if (rc != BNS_OK) goto fail;
        off += slen;

        /* sequence (4 LE) */
        rc = read_u32_le(d, len, off, &in->sequence);
        if (rc != BNS_OK) goto fail;
        off += 4;
    }

    /* output count */
    rc = read_varint(d, len, off, &vr);
    if (rc != BNS_OK) goto fail;
    off += vr.consumed;
    tx->num_outputs = (size_t)vr.value;

    /* DoS guard: each output needs >=9 bytes (8+1); reject impossible counts */
    if (tx->num_outputs > (len - off) / 9) { rc = BNS_EPARSE; goto fail; }

    if (tx->num_outputs > 0) {
        tx->outputs = calloc(tx->num_outputs, sizeof(bsv_txout_t));
        if (!tx->outputs) { rc = BNS_ENOMEM; goto fail; }
        for (size_t i = 0; i < tx->num_outputs; i++)
            byte_buf_init(&tx->outputs[i].script);
    }

    for (size_t i = 0; i < tx->num_outputs; i++) {
        bsv_txout_t *o = &tx->outputs[i];

        /* satoshis (8 LE) */
        rc = read_u64_le(d, len, off, &o->satoshis);
        if (rc != BNS_OK) goto fail;
        off += 8;

        /* script length + bytes */
        rc = read_varint(d, len, off, &vr);
        if (rc != BNS_OK) goto fail;
        off += vr.consumed;
        size_t slen = (size_t)vr.value;
        if (slen > len - off) { rc = BNS_EPARSE; goto fail; }
        rc = byte_buf_append(&o->script, d + off, slen);
        if (rc != BNS_OK) goto fail;
        off += slen;
    }

    /* locktime (4 LE) */
    rc = read_u32_le(d, len, off, &tx->locktime);
    if (rc != BNS_OK) goto fail;
    off += 4;

    /* A well-formed tx consumes exactly its bytes. Reject trailing data so two
     * distinct hex strings can't deserialize to the same tx (txid ambiguity on
     * untrusted rawtx). Canonical vectors end precisely at the locktime. */
    if (off != len) { rc = BNS_EPARSE; goto fail; }

    byte_buf_free(&raw);
    return BNS_OK;

fail:
    byte_buf_free(&raw);
    tx_free(tx);
    return rc;
}

/* ---- serialize ---------------------------------------------------------- */

int tx_serialize(const bsv_tx_t *tx, byte_buf_t *out) {
    if (!tx || !out) return BNS_EINVAL;
    int rc;

    rc = append_u32_le(out, tx->version);
    if (rc != BNS_OK) return rc;

    rc = write_varint(tx->num_inputs, out);
    if (rc != BNS_OK) return rc;

    for (size_t i = 0; i < tx->num_inputs; i++) {
        const bsv_txin_t *in = &tx->inputs[i];

        /* DISPLAY hex -> bytes -> reverse -> wire LE */
        uint8_t disp[32];
        rc = hex_decode_fixed(in->prev_txid_display, disp, 32);
        if (rc != BNS_OK) return BNS_EINVAL;
        uint8_t wire[32];
        for (size_t j = 0; j < 32; j++) wire[j] = disp[31 - j];
        rc = byte_buf_append(out, wire, 32);
        if (rc != BNS_OK) return rc;

        rc = append_u32_le(out, in->vout);
        if (rc != BNS_OK) return rc;

        rc = write_varint(in->script_sig.len, out);
        if (rc != BNS_OK) return rc;
        if (in->script_sig.len) {
            rc = byte_buf_append(out, in->script_sig.data, in->script_sig.len);
            if (rc != BNS_OK) return rc;
        }

        rc = append_u32_le(out, in->sequence);
        if (rc != BNS_OK) return rc;
    }

    rc = write_varint(tx->num_outputs, out);
    if (rc != BNS_OK) return rc;

    for (size_t i = 0; i < tx->num_outputs; i++) {
        const bsv_txout_t *o = &tx->outputs[i];

        rc = append_u64_le(out, o->satoshis);
        if (rc != BNS_OK) return rc;

        rc = write_varint(o->script.len, out);
        if (rc != BNS_OK) return rc;
        if (o->script.len) {
            rc = byte_buf_append(out, o->script.data, o->script.len);
            if (rc != BNS_OK) return rc;
        }
    }

    rc = append_u32_le(out, tx->locktime);
    if (rc != BNS_OK) return rc;

    return BNS_OK;
}

/* ---- txid --------------------------------------------------------------- */

int tx_id(const bsv_tx_t *tx, char **out) {
    if (!tx || !out) return BNS_EINVAL;
    *out = NULL;

    byte_buf_t raw;
    byte_buf_init(&raw);
    int rc = tx_serialize(tx, &raw);
    if (rc != BNS_OK) {
        byte_buf_free(&raw);
        return rc;
    }

    uint8_t hash[BONSAI_SHA256_LEN];
    sha256d(raw.data, raw.len, hash);
    byte_buf_free(&raw);

    /* DISPLAY txid == reversed sha256d */
    uint8_t disp[BONSAI_SHA256_LEN];
    for (size_t i = 0; i < BONSAI_SHA256_LEN; i++)
        disp[i] = hash[BONSAI_SHA256_LEN - 1 - i];

    char *hexstr = hex_encode(disp, BONSAI_SHA256_LEN);
    if (!hexstr) return BNS_ENOMEM;
    *out = hexstr;
    return BNS_OK;
}
