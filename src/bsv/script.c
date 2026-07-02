/*
 * script.c — Bitcoin script chunk parsing + P2PKH / OP_RETURN receipt readers.
 *
 * Faithful port of @scrypt-inc/bsv Script chunk decoding (decodeScriptChunks),
 * Script.isPublicKeyHashOut, and reputationIndexer.parseReceiptHash.
 *
 * Chunk decoding (mirrors bsv decodeScriptChunks):
 *   opcode == 0x00            -> opcode chunk, no payload (len 0)
 *   0x01 <= opcode < 0x4c     -> direct push of `opcode` bytes
 *   opcode == 0x4c PUSHDATA1  -> 1-byte LE length, then payload
 *   opcode == 0x4d PUSHDATA2  -> 2-byte LE length, then payload
 *   opcode == 0x4e PUSHDATA4  -> 4-byte LE length, then payload
 *   else                      -> opcode chunk, no payload
 * A pushdata whose declared length runs past the buffer end is BNS_EPARSE
 * (the header contract; bsv silently clamps such truncations).
 */
#include "bsv/script.h"

#include <stdlib.h>
#include <string.h>

int script_parse(const uint8_t *script, size_t script_len,
                 script_chunk_t *chunks, size_t max_chunks, size_t *out_count)
{
    if (out_count) *out_count = 0;
    if (script == NULL && script_len != 0) return BNS_EINVAL;

    size_t i = 0;
    size_t count = 0;

    while (i < script_len) {
        uint8_t opcode = script[i];
        i += 1;

        const uint8_t *data = NULL;
        size_t data_len = 0;

        if (opcode == OP_0) {
            /* OP_0 / OP_FALSE: opcode chunk, no payload. */
        } else if (opcode < OP_PUSHDATA1) {
            /* Direct push of `opcode` bytes. */
            data_len = opcode;
            if (data_len > script_len - i) return BNS_EPARSE;
            data = script + i;
            i += data_len;
        } else if (opcode == OP_PUSHDATA1) {
            if (1 > script_len - i) return BNS_EPARSE;
            data_len = script[i];
            i += 1;
            if (data_len > script_len - i) return BNS_EPARSE;
            data = script + i;
            i += data_len;
        } else if (opcode == OP_PUSHDATA2) {
            if (2 > script_len - i) return BNS_EPARSE;
            data_len = (size_t)script[i] | ((size_t)script[i + 1] << 8);
            i += 2;
            if (data_len > script_len - i) return BNS_EPARSE;
            data = script + i;
            i += data_len;
        } else if (opcode == OP_PUSHDATA4) {
            if (4 > script_len - i) return BNS_EPARSE;
            data_len = (size_t)script[i]
                     | ((size_t)script[i + 1] << 8)
                     | ((size_t)script[i + 2] << 16)
                     | ((size_t)script[i + 3] << 24);
            i += 4;
            if (data_len > script_len - i) return BNS_EPARSE;
            data = script + i;
            i += data_len;
        } else {
            /* Plain opcode (OP_1NEGATE, OP_1..OP_16, OP_RETURN, etc.). */
        }

        if (count >= max_chunks) return BNS_ERANGE;
        chunks[count].opcode = opcode;
        chunks[count].data = data;
        chunks[count].data_len = data_len;
        count += 1;
    }

    if (out_count) *out_count = count;
    return BNS_OK;
}

bool is_p2pkh_out(const uint8_t *script, size_t script_len,
                  uint8_t out_hash160[20])
{
    /* Canonical 25-byte P2PKH: 76 a9 14 <20B> 88 ac.
     * Equivalent to bsv isPublicKeyHashOut: chunks
     *   [OP_DUP][OP_HASH160][20-byte push][OP_EQUALVERIFY][OP_CHECKSIG]. */
    if (script == NULL || script_len != 25) return false;
    if (script[0] != OP_DUP) return false;
    if (script[1] != OP_HASH160) return false;
    if (script[2] != 0x14) return false;        /* push exactly 20 bytes */
    if (script[23] != OP_EQUALVERIFY) return false;
    if (script[24] != OP_CHECKSIG) return false;

    if (out_hash160 != NULL) {
        memcpy(out_hash160, script + 3, 20);
    }
    return true;
}

int parse_opreturn(const uint8_t *script, size_t script_len, byte_buf_t *out_data)
{
    if (out_data == NULL) return BNS_EINVAL;
    if (script == NULL || script_len == 0) return BNS_EPARSE;

    /* Two accepted leading forms:
     *   OP_RETURN ...                 (bare data carrier)
     *   OP_0 OP_RETURN ...            ('006a'-prefixed 0-sat receipt form) */
    size_t start = 0;
    if (script[0] == OP_RETURN) {
        start = 0;
    } else if (script_len >= 2 && script[0] == OP_0 && script[1] == OP_RETURN) {
        start = 1; /* skip the leading OP_0; OP_RETURN is at index 1 */
    } else {
        return BNS_EPARSE;
    }

    /* Parse the whole script into chunks, then concatenate every pushdata
     * payload that follows the OP_RETURN. */
    /* Worst case: each byte is its own 1-byte opcode chunk. */
    script_chunk_t stack_chunks[64];
    script_chunk_t *chunks = stack_chunks;
    size_t max_chunks = sizeof(stack_chunks) / sizeof(stack_chunks[0]);
    size_t count = 0;
    int rc = script_parse(script, script_len, chunks, max_chunks, &count);

    if (rc == BNS_ERANGE) {
        /* Fall back to a heap buffer sized to the worst case. */
        chunks = malloc(script_len * sizeof(*chunks));
        if (chunks == NULL) return BNS_ENOMEM;
        max_chunks = script_len;
        rc = script_parse(script, script_len, chunks, max_chunks, &count);
    }
    if (rc != BNS_OK) {
        if (chunks != stack_chunks) free(chunks);
        return rc;
    }

    /* Locate the OP_RETURN chunk: it is the first chunk after the optional
     * leading OP_0. With start==0 it is chunk 0; with start==1 it is chunk 1. */
    size_t ret_idx = (start == 0) ? 0 : 1;
    if (ret_idx >= count || chunks[ret_idx].opcode != OP_RETURN) {
        if (chunks != stack_chunks) free(chunks);
        return BNS_EPARSE;
    }

    byte_buf_clear(out_data);
    for (size_t k = ret_idx + 1; k < count; k++) {
        if (chunks[k].data != NULL && chunks[k].data_len != 0) {
            rc = byte_buf_append(out_data, chunks[k].data, chunks[k].data_len);
            if (rc != BNS_OK) {
                if (chunks != stack_chunks) free(chunks);
                return rc;
            }
        }
    }

    if (chunks != stack_chunks) free(chunks);
    return BNS_OK;
}

int parse_receipt_hash(const uint8_t *script, size_t script_len,
                       uint8_t out_hash32[32])
{
    if (out_hash32 == NULL) return BNS_EINVAL;
    /* TS parseReceiptHash: the 0-sat output whose script hex starts with '006a'
     * and whose LAST script chunk is exactly 32 bytes. */
    if (script == NULL || script_len < 2) return BNS_EPARSE;
    if (script[0] != OP_0 || script[1] != OP_RETURN) return BNS_EPARSE;

    script_chunk_t stack_chunks[64];
    script_chunk_t *chunks = stack_chunks;
    size_t max_chunks = sizeof(stack_chunks) / sizeof(stack_chunks[0]);
    size_t count = 0;
    int rc = script_parse(script, script_len, chunks, max_chunks, &count);

    if (rc == BNS_ERANGE) {
        chunks = malloc(script_len * sizeof(*chunks));
        if (chunks == NULL) return BNS_ENOMEM;
        max_chunks = script_len;
        rc = script_parse(script, script_len, chunks, max_chunks, &count);
    }
    if (rc != BNS_OK) {
        if (chunks != stack_chunks) free(chunks);
        return rc;
    }

    if (count == 0) {
        if (chunks != stack_chunks) free(chunks);
        return BNS_EPARSE;
    }

    const script_chunk_t *last = &chunks[count - 1];
    if (last->data == NULL || last->data_len != 32) {
        if (chunks != stack_chunks) free(chunks);
        return BNS_EPARSE;
    }

    memcpy(out_hash32, last->data, 32);
    if (chunks != stack_chunks) free(chunks);
    return BNS_OK;
}
