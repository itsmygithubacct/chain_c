/*
 * base58.h — Base58 and Base58Check encode/decode.
 *
 * Base58Check appends a 4-byte checksum = first 4 bytes of double-SHA256 over
 * (version || payload). Used by address.h (P2PKH addresses) and WIF.
 *
 * TS origin: bsv.encoding.Base58 / Base58Check.{encode,decode}.
 */
#ifndef BONSAI_BSV_BASE58_H
#define BONSAI_BSV_BASE58_H

#include <stddef.h>
#include <stdint.h>
#include "common/error.h"
#include "common/bytes.h"

/* Base58-encode raw bytes -> freshly malloc'd NUL-terminated string (*out;
 * caller frees). TS: Base58.encode. BNS_OK / BNS_ENOMEM. */
int base58_encode(const uint8_t *data, size_t len, char **out);

/* Base58-decode a string into `out` (init'd). TS: Base58.decode.
 * BNS_OK / BNS_EPARSE (invalid char) / BNS_ENOMEM. */
int base58_decode(const char *str, byte_buf_t *out);

/* Base58Check-encode: appends a 4-byte double-SHA256 checksum to `data` then
 * Base58-encodes -> freshly malloc'd string (*out; caller frees).
 * TS: Base58Check.encode. BNS_OK / BNS_ENOMEM. */
int base58check_encode(const uint8_t *data, size_t len, char **out);

/* Base58Check-decode + verify the 4-byte checksum. On success writes the
 * payload (checksum stripped) into `out` (init'd). TS: Base58Check.decode.
 * BNS_OK / BNS_EPARSE (bad base58) / BNS_EINTEGRITY (checksum mismatch). */
int base58check_decode(const char *str, byte_buf_t *out);

#endif /* BONSAI_BSV_BASE58_H */
