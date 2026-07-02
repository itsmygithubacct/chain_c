/*
 * num2bin.h — the TWO distinct integer->bytes encoders that every receipt /
 * attestation / Rabin-message preimage depends on. A single header so a caller
 * can NEVER pick the wrong one by accident (plan.risks: top porting trap).
 *
 * These two look interchangeable but are NOT:
 *
 *  1) int2bytestring_sized(bn, width)  — scrypt-ts int2ByteString(n, width):
 *     FIXED-WIDTH little-endian, two's-complement style with the SIGN BIT in the
 *     TOP byte (num2bin two-arg form). Width is exact; value must fit. This is
 *     the encoder used for the receipt preimage fields:
 *       int2ByteString(amount,8n), int2ByteString(txCount,8n),
 *       int2ByteString(now,4n) [signed 4-byte CScriptNum — do NOT widen], and
 *       the 8-byte LITTLE-ENDIAN seq in the Rabin attestation message.
 *
 *  2) int2bytestring_minimal(bn)       — scrypt-ts int2ByteString(n) one-arg /
 *     BN.toSM little-endian: SIGN-MAGNITUDE MINIMAL little-endian. Emits the
 *     magnitude in LE, drops redundant leading zero bytes, and appends a 0x00
 *     (positive) or 0x80 (negative) sign byte when the top magnitude byte's
 *     high bit is set. This is the CScriptNum minimal push body.
 *     GOLDEN (rabinSpike): oracle 12345678901234567890 ->
 *       magnitude '09d20a1feb8ca954ab', high bit of 0xab set -> append '00' ->
 *       'd20a1feb8ca954ab00'  (the int2hex pushdata prepends the 0x09 length).
 *
 * NOTE: the scrypt CONSTRUCTOR int encoder (OP_0/OP_1..OP_16/OP_1NEGATE
 * optimization) is a THIRD encoder and lives in scrypt/script_codec.h, NOT here.
 *
 * TS origin: scrypt-ts int2ByteString (both arities), bsv BN.toSM / num2bin.
 */
#ifndef BONSAI_BSV_NUM2BIN_H
#define BONSAI_BSV_NUM2BIN_H

#include <stddef.h>
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/bignum.h"

/* num2bin TWO-ARG: fixed `width` little-endian with sign in the top byte.
 * Appends exactly `width` bytes to `out` (init'd). Mirrors scrypt-ts
 * int2ByteString(n, BigInt(width)). BNS_OK / BNS_ERANGE (does not fit width) /
 * BNS_ENOMEM. */
int int2bytestring_sized(const bn_t *n, size_t width, byte_buf_t *out);

/* num2bin ONE-ARG / BN.toSM: minimal sign-magnitude little-endian with trailing
 * 0x00/0x80 sign byte. Appends the variable-length encoding to `out` (init'd).
 * Mirrors scrypt-ts int2ByteString(n). Zero encodes as empty (TS '' / 0n).
 * BNS_OK / BNS_ENOMEM. */
int int2bytestring_minimal(const bn_t *n, byte_buf_t *out);

#endif /* BONSAI_BSV_NUM2BIN_H */
