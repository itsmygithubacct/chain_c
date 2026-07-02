/*
 * varint.c — Bitcoin CompactSize (varint) encode/decode.
 *
 * Encoding (little-endian payload):
 *   n < 0xfd        -> 1 byte  n
 *   n <= 0xffff     -> 0xfd + u16 LE
 *   n <= 0xffffffff -> 0xfe + u32 LE
 *   else            -> 0xff + u64 LE
 *
 * TS origin: bsv BufferWriter.writeVarintNum / BufferReader.readVarintNum.
 */
#include "bsv/varint.h"

int write_varint(uint64_t n, byte_buf_t *out)
{
    if (out == NULL) {
        return BNS_EINVAL;
    }

    if (n < 0xfdULL) {
        return byte_buf_append_byte(out, (uint8_t)n);
    }

    int rc;
    if (n <= 0xffffULL) {
        if ((rc = byte_buf_append_byte(out, 0xfd)) != BNS_OK) return rc;
        uint8_t b[2];
        for (size_t i = 0; i < 2; i++) {
            b[i] = (uint8_t)(n >> (8 * i));
        }
        return byte_buf_append(out, b, sizeof(b));
    }
    if (n <= 0xffffffffULL) {
        if ((rc = byte_buf_append_byte(out, 0xfe)) != BNS_OK) return rc;
        uint8_t b[4];
        for (size_t i = 0; i < 4; i++) {
            b[i] = (uint8_t)(n >> (8 * i));
        }
        return byte_buf_append(out, b, sizeof(b));
    }
    if ((rc = byte_buf_append_byte(out, 0xff)) != BNS_OK) return rc;
    uint8_t b[8];
    for (size_t i = 0; i < 8; i++) {
        b[i] = (uint8_t)(n >> (8 * i));
    }
    return byte_buf_append(out, b, sizeof(b));
}

int read_varint(const uint8_t *data, size_t len, size_t off, varint_read_t *out)
{
    if (data == NULL || out == NULL) {
        return BNS_EINVAL;
    }
    if (off >= len) {
        return BNS_EPARSE; /* nothing to read */
    }

    uint8_t prefix = data[off];

    if (prefix < 0xfd) {
        out->value = prefix;
        out->consumed = 1;
        return BNS_OK;
    }

    size_t nbytes;
    switch (prefix) {
    case 0xfd: nbytes = 2; break;
    case 0xfe: nbytes = 4; break;
    default:   nbytes = 8; break; /* 0xff */
    }

    /* Need the prefix byte plus `nbytes` payload bytes available.
     * off < len here (data[off] read above); wrap-safe: avoid off+1 overflow. */
    if (off >= len || nbytes > len - off - 1) {
        return BNS_EPARSE; /* truncated */
    }

    uint64_t v = 0;
    for (size_t i = 0; i < nbytes; i++) {
        v |= (uint64_t)data[off + 1 + i] << (8 * i);
    }

    /* Reject non-minimal (overlong) CompactSize encodings: a value that would
     * fit in a shorter prefix MUST use that shorter form. Canonical bitcoin
     * serialization is always minimal; accepting an overlong form would let two
     * distinct byte strings decode to the same value (txid-ambiguity hazard on
     * untrusted rawtx). */
    uint64_t min_value;
    switch (prefix) {
    case 0xfd: min_value = 0xfdULL;       break; /* must be >= 0xfd      */
    case 0xfe: min_value = 0x10000ULL;    break; /* must be > 0xffff     */
    default:   min_value = 0x100000000ULL; break; /* 0xff: must be > 0xffffffff */
    }
    if (v < min_value) {
        return BNS_EPARSE; /* non-minimal encoding */
    }

    out->value = v;
    out->consumed = 1 + nbytes;
    return BNS_OK;
}
