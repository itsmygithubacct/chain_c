/*
 * script_utils.c — output-serialization builders: P2PKH / OP_RETURN scripts
 * and full tx outputs.
 *
 * Faithful port of scrypt-ts Utils:
 *   buildPublicKeyHashScript(h) = OP_DUP OP_HASH160 0x14 <20B h> OP_EQUALVERIFY
 *                                 OP_CHECKSIG  == 76a914<20>88ac
 *   buildOpreturnScript(data)   = OP_FALSE OP_RETURN <standard pushdata> <data>
 *                                 == 00 6a <push> <data>
 *   buildOutput(script, sats)   = int2ByteString(sats, 8) writeVarint(script)
 *                                 == <8-byte LE sats> <varint scriptLen> <script>
 *
 * Note: build_opreturn_script emits a STANDARD SCRIPT PUSHDATA for the payload —
 * a direct-push byte for len < 0x4c, OP_PUSHDATA1 for 76..255, OP_PUSHDATA2 (LE)
 * for 256..65535, BNS_ERANGE beyond (see the inline comment at the function). For
 * the <76-byte payloads every caller passes this is byte-identical to a single
 * length byte, so the parser in script.c reads the receipt form back correctly;
 * for 76..255 it correctly uses OP_PUSHDATA1 (a bare CompactSize varint there
 * would be 0x4c.. and be misread as an opcode).
 *
 * int2ByteString(n, 8) for the (always non-negative) satoshi amount reduces to
 * an 8-byte little-endian unsigned encoding (num2bin sign-magnitude with a
 * positive value and the value fitting in 8 bytes => plain LE).
 */
#include "bsv/script_utils.h"
#include "bsv/varint.h"
#include "bsv/script.h"

static int append_u64_le(uint64_t v, byte_buf_t *out)
{
    uint8_t le[8];
    for (int k = 0; k < 8; k++) {
        le[k] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
    return byte_buf_append(out, le, sizeof(le));
}

int build_p2pkh_script(const uint8_t hash160[20], byte_buf_t *out)
{
    if (hash160 == NULL || out == NULL) return BNS_EINVAL;

    int rc;
    if ((rc = byte_buf_append_byte(out, OP_DUP))         != BNS_OK) return rc;
    if ((rc = byte_buf_append_byte(out, OP_HASH160))     != BNS_OK) return rc;
    if ((rc = byte_buf_append_byte(out, 0x14))           != BNS_OK) return rc;
    if ((rc = byte_buf_append(out, hash160, 20))         != BNS_OK) return rc;
    if ((rc = byte_buf_append_byte(out, OP_EQUALVERIFY)) != BNS_OK) return rc;
    if ((rc = byte_buf_append_byte(out, OP_CHECKSIG))    != BNS_OK) return rc;
    return BNS_OK;
}

int build_opreturn_script(const uint8_t *data, size_t data_len, byte_buf_t *out)
{
    if (out == NULL) return BNS_EINVAL;
    if (data == NULL && data_len != 0) return BNS_EINVAL;

    int rc;
    if ((rc = byte_buf_append_byte(out, OP_0))      != BNS_OK) return rc; /* OP_FALSE */
    if ((rc = byte_buf_append_byte(out, OP_RETURN)) != BNS_OK) return rc;
    /* Push <data> with a STANDARD script pushdata encoding, NOT a CompactSize varint.
     * For data_len < 76 this is a single direct-push byte == data_len (byte-identical
     * to the old varint path for every current 4/8/32-byte caller); for 76..255 it is
     * OP_PUSHDATA1, for 256..65535 OP_PUSHDATA2. The old varint emitted 0xfd/0xfe for
     * >=253, which is not valid script — script_parse would misread it and
     * parse_receipt_hash could not recover the payload. */
    if (data_len < 0x4c) {
        if ((rc = byte_buf_append_byte(out, (uint8_t)data_len)) != BNS_OK) return rc;
    } else if (data_len <= 0xff) {
        if ((rc = byte_buf_append_byte(out, 0x4c)) != BNS_OK) return rc;            /* OP_PUSHDATA1 */
        if ((rc = byte_buf_append_byte(out, (uint8_t)data_len)) != BNS_OK) return rc;
    } else if (data_len <= 0xffff) {
        if ((rc = byte_buf_append_byte(out, 0x4d)) != BNS_OK) return rc;            /* OP_PUSHDATA2 (LE) */
        if ((rc = byte_buf_append_byte(out, (uint8_t)(data_len & 0xff))) != BNS_OK) return rc;
        if ((rc = byte_buf_append_byte(out, (uint8_t)((data_len >> 8) & 0xff))) != BNS_OK) return rc;
    } else {
        return BNS_ERANGE;   /* OP_RETURN payload too large for a single push */
    }
    if (data_len != 0) {
        if ((rc = byte_buf_append(out, data, data_len)) != BNS_OK) return rc;
    }
    return BNS_OK;
}

int build_output(const uint8_t *script, size_t script_len, uint64_t satoshis,
                 byte_buf_t *out)
{
    if (out == NULL) return BNS_EINVAL;
    if (script == NULL && script_len != 0) return BNS_EINVAL;

    int rc;
    if ((rc = append_u64_le(satoshis, out)) != BNS_OK) return rc;
    if ((rc = write_varint((uint64_t)script_len, out)) != BNS_OK) return rc;
    if (script_len != 0) {
        if ((rc = byte_buf_append(out, script, script_len)) != BNS_OK) return rc;
    }
    return BNS_OK;
}

int build_p2pkh_output(const uint8_t hash160[20], uint64_t satoshis,
                       byte_buf_t *out)
{
    if (hash160 == NULL || out == NULL) return BNS_EINVAL;

    /* Build the locking script into a temporary, then wrap as an output. */
    byte_buf_t script;
    byte_buf_init(&script);
    int rc = build_p2pkh_script(hash160, &script);
    if (rc != BNS_OK) {
        byte_buf_free(&script);
        return rc;
    }
    rc = build_output(script.data, script.len, satoshis, out);
    byte_buf_free(&script);
    return rc;
}
