/*
 * hex.h — lowercase-hex <-> bytes, the ByteString string form.
 *
 * The TS layer passes payloads around as `ByteString` == a LOWERCASE hex string.
 * `Sha256` is a 64-hex-char string, `PubKey` a 66-hex-char (02/03 prefix)
 * compressed pubkey, `Ripemd160` a 40-hex-char string. These helpers are the
 * single contract for that conversion; getting case (always lowercase) and
 * validation right is load-bearing for every hash/commitment.
 */
#ifndef BONSAI_COMMON_HEX_H
#define BONSAI_COMMON_HEX_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/bytes.h"

/* Encode `len` bytes as a freshly malloc'd, NUL-terminated LOWERCASE hex string
 * of 2*len chars. Caller frees. Returns NULL on OOM. */
char *hex_encode(const uint8_t *data, size_t len);

/* Encode into a caller buffer `out` of size >= 2*len+1. Returns BNS_OK/BNS_EINVAL. */
int hex_encode_to(const uint8_t *data, size_t len, char *out, size_t out_sz);

/* Encode a byte_buf_t as hex (convenience). Caller frees the returned string. */
char *hex_encode_buf(const byte_buf_t *b);

/* Decode a hex string (even length, [0-9a-fA-F]) into `out` (init'd inside).
 * Accepts upper or lower case on input. Returns BNS_OK / BNS_EPARSE. */
int hex_decode(const char *hex, byte_buf_t *out);

/* Decode exactly `nbytes` bytes from `hex` (len must be 2*nbytes) into `buf`
 * (caller provides storage of nbytes). Returns BNS_OK / BNS_EPARSE. */
int hex_decode_fixed(const char *hex, uint8_t *buf, size_t nbytes);

/* True iff `s` is non-empty, even-length, and all hex digits. */
bool is_hex(const char *s);

/* True iff `s` is exactly 2*nbytes hex chars. */
bool is_hex_len(const char *s, size_t nbytes);

/* Validators mirroring the TS regexes:
 *   is_sha256_hex  : 64 hex chars
 *   is_pubkey_hex  : 66 hex chars beginning 02 or 03 (compressed SEC) */
bool is_sha256_hex(const char *s);
bool is_pubkey_hex(const char *s);

/* Return a freshly malloc'd lowercased copy of an ASCII hex string (TS often
 * does .toLowerCase() before hashing/comparison). Caller frees. */
char *hex_to_lower(const char *s);

#endif /* BONSAI_COMMON_HEX_H */
