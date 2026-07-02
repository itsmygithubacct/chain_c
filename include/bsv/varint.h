/*
 * varint.h — Bitcoin CompactSize (varint) encode/decode.
 *
 * The length-prefix used throughout tx serialization (input/output counts,
 * script lengths) and pushdata sizing.
 *
 * TS origin: bsv.encoding.BufferWriter.writeVarintNum / readVarintNum; the
 * write_varint shared helper referenced by script_utils.
 *
 * Encoding: n < 0xfd        -> 1 byte n
 *           n <= 0xffff     -> 0xfd + u16 LE
 *           n <= 0xffffffff -> 0xfe + u32 LE
 *           else            -> 0xff + u64 LE
 */
#ifndef BONSAI_BSV_VARINT_H
#define BONSAI_BSV_VARINT_H

#include <stddef.h>
#include <stdint.h>
#include "common/error.h"
#include "common/bytes.h"

/* Result of read_varint: decoded value + bytes consumed. */
typedef struct {
    uint64_t value;
    size_t   consumed;  /* bytes read from the buffer (1, 3, 5, or 9) */
} varint_read_t;

/* Append the CompactSize encoding of `n` to `out` (init'd).
 * TS: BufferWriter.writeVarintNum(n). BNS_OK / BNS_ENOMEM. */
int write_varint(uint64_t n, byte_buf_t *out);

/* Decode a CompactSize at byte offset `off` within `data`/`len`. Writes the
 * value and bytes-consumed into *out. TS: BufferReader.readVarintNum.
 * BNS_OK / BNS_EPARSE (truncated buffer). */
int read_varint(const uint8_t *data, size_t len, size_t off, varint_read_t *out);

#endif /* BONSAI_BSV_VARINT_H */
