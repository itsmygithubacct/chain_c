/*
 * script.h — Bitcoin script parsing + the receipt/OP_RETURN readers.
 *
 * Reads scripts into chunks (opcode + optional pushdata payload), classifies
 * P2PKH outputs, and extracts the OP_RETURN receipt-data the contracts commit
 * (the Third Entry: a 0-sat '006a'-prefixed output whose last chunk is exactly
 * the 32-byte receiptHash).
 *
 * TS origin: bsv.Script.fromHex / .chunks, Script.buildPublicKeyHashOut shape,
 * parseReceiptHash (agentd) / parseReceiptHash receipt readers.
 */
#ifndef BONSAI_BSV_SCRIPT_H
#define BONSAI_BSV_SCRIPT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"

/* Common opcodes referenced by the classifiers/builders. TS: bsv.Opcode. */
enum {
    OP_0           = 0x00,
    OP_PUSHDATA1   = 0x4c,
    OP_PUSHDATA2   = 0x4d,
    OP_PUSHDATA4   = 0x4e,
    OP_1NEGATE     = 0x4f,
    OP_1           = 0x51,
    OP_16          = 0x60,
    OP_RETURN      = 0x6a,
    OP_DUP         = 0x76,
    OP_EQUALVERIFY = 0x88,
    OP_HASH160     = 0xa9,
    OP_CHECKSIG    = 0xac
};

/* One parsed script chunk: an opcode and (for pushdata) a borrowed view into
 * the source script bytes. `data` points INTO the caller's script buffer (not
 * owned); valid only while that buffer lives. TS: bsv.Script chunk {opcodenum,
 * buf, len}. */
typedef struct {
    uint8_t        opcode;   /* the opcode / pushdata length byte */
    const uint8_t *data;     /* pushdata payload (NULL if pure opcode) */
    size_t         data_len; /* pushdata length in bytes */
} script_chunk_t;

/* Parse a script into chunks. Writes up to `max_chunks` into `chunks` and the
 * actual count into *out_count. TS: bsv.Script.fromBuffer(...).chunks.
 * BNS_OK / BNS_EPARSE (malformed/truncated) / BNS_ERANGE (more than max_chunks). */
int script_parse(const uint8_t *script, size_t script_len,
                 script_chunk_t *chunks, size_t max_chunks, size_t *out_count);

/* True iff `script` is a standard P2PKH locking script:
 * OP_DUP OP_HASH160 <20-byte push> OP_EQUALVERIFY OP_CHECKSIG (76a914..88ac).
 * If true and `out_hash160` != NULL, copies the 20-byte hash160 into it.
 * TS: matches bsv.Script.buildPublicKeyHashOut output shape. */
bool is_p2pkh_out(const uint8_t *script, size_t script_len,
                  uint8_t out_hash160[20]);

/* Parse an OP_RETURN data carrier. On success, `out_data` (init'd) receives the
 * concatenated pushdata payload after OP_RETURN (the committed data). Accepts
 * the '006a'-prefixed 0-sat form (leading OP_0 then OP_RETURN) used by receipts.
 * TS: parseReceiptHash / OP_RETURN readers.
 * BNS_OK / BNS_EPARSE (not an OP_RETURN script). */
int parse_opreturn(const uint8_t *script, size_t script_len, byte_buf_t *out_data);

/* Extract the receipt hash: the LAST pushdata chunk of a '006a'-prefixed 0-sat
 * OP_RETURN output, which must be exactly 32 bytes. Copies it to out_hash32.
 * TS: agentd parseReceiptHash. BNS_OK / BNS_EPARSE (wrong shape / not 32B). */
int parse_receipt_hash(const uint8_t *script, size_t script_len,
                       uint8_t out_hash32[32]);

#endif /* BONSAI_BSV_SCRIPT_H */
