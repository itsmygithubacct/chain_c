/*
 * bignum.h — the FROZEN arbitrary-precision integer contract (opaque bn_t).
 *
 * This is the single big-integer type used by rabin.h, ricardian_charter (slash
 * targets), and the zk layer (BN254/MiMC7 scalars). It wraps OpenSSL BIGNUM as
 * an OPAQUE handle — no <openssl/...> appears here so consumers never bind to a
 * third-party type. Freezing this lets rabin/charter/zk proceed in parallel.
 *
 * TS origin: JavaScript `bigint`, bsv `BN`, and OpenSSL BN_* (BN_bn2dec,
 * BN_bn2hex, BN_mod_*). The TS uses arbitrary-precision integers for Rabin
 * moduli/signatures, decimal RabinPubKey wire forms, slashing targets, and
 * scalar-field elements.
 *
 * Ownership: bn_t handles are heap-allocated; bn_free() releases. Functions that
 * "return" a bn_t set an out-param (*out) which the caller frees. Fallible fns
 * return int (bonsai_err_t); pure comparisons return their value directly.
 */
#ifndef BONSAI_CRYPTO_BIGNUM_H
#define BONSAI_CRYPTO_BIGNUM_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"

/* Opaque arbitrary-precision unsigned/signed integer (wraps OpenSSL BIGNUM). */
typedef struct bn_s bn_t;

/* ---- lifecycle ---------------------------------------------------------- */

/* Allocate a new zero-valued bn_t. Returns NULL on OOM. TS: 0n. */
bn_t *bn_new(void);

/* Release a bn_t (NULL-safe). TS: GC. */
void bn_free(bn_t *bn);

/* Release a bn_t, scrubbing the integer's bytes first (NULL-safe). Use for
 * SECRET values (Rabin primes / CRT intermediates) so key material is not left
 * in freed heap. Identical to bn_free except for the zeroizing release. */
void bn_clear_free(bn_t *bn);

/* Deep copy `src` into a fresh handle via *out. BNS_OK / BNS_ENOMEM. TS: BN clone. */
int bn_dup(const bn_t *src, bn_t **out);

/* ---- parse (string / bytes -> bn) --------------------------------------- */

/* Parse a base-10 DECIMAL string (optional leading '-'). TS: BigInt("123").
 * BNS_OK / BNS_EPARSE. */
int bn_parse_dec(const char *dec, bn_t **out);

/* Parse a hex string (optional "0x"/"0X" prefix, upper or lower case).
 * TS: BigInt("0x...") / BN_hex2bn. BNS_OK / BNS_EPARSE. */
int bn_parse_hex(const char *hex, bn_t **out);

/* Parse `len` bytes as an unsigned LITTLE-ENDIAN integer.
 * TS: toBigIntLE / fromLEUnsigned (used by Rabin rabinHashBytes). BNS_OK/BNS_ENOMEM. */
int bn_parse_le(const uint8_t *data, size_t len, bn_t **out);

/* Parse `len` bytes as an unsigned BIG-ENDIAN integer. TS: BN.fromBuffer.
 * BNS_OK / BNS_ENOMEM. */
int bn_parse_be(const uint8_t *data, size_t len, bn_t **out);

/* ---- serialize (bn -> string / bytes) ----------------------------------- */

/* Decimal string, BN_bn2dec semantics (the RabinPubKey canonical wire form).
 * Writes a freshly malloc'd NUL-terminated string to *out (caller frees).
 * TS: n.toString(10) / BN_bn2dec. BNS_OK / BNS_ENOMEM. */
int bn_to_dec(const bn_t *bn, char **out);

/* LOWERCASE hex, NO zero-padding, no "0x" (the Rabin `s` wire form). NOTE: this
 * deliberately differs from OpenSSL BN_bn2hex which uppercases and pads — must
 * lowercase + strip leading zeros to match JS BigInt.toString(16).
 * Writes a freshly malloc'd NUL-terminated string to *out (caller frees).
 * TS: n.toString(16). BNS_OK / BNS_ENOMEM. */
int bn_to_hex(const bn_t *bn, char **out);

/* Fixed-width unsigned LITTLE-ENDIAN bytes: append exactly `width` bytes to
 * `out` (init'd). Truncates/pads to `width`; high bytes zero-filled.
 * TS: int2ByteString fixed-width LE substrate / BN.toBuffer LE.
 * BNS_OK / BNS_ENOMEM / BNS_ERANGE (value wider than width). */
int bn_to_le_bytes(const bn_t *bn, size_t width, byte_buf_t *out);

/* Minimal-width unsigned BIG-ENDIAN bytes appended to `out` (init'd).
 * TS: BN.toBuffer BE. BNS_OK / BNS_ENOMEM. */
int bn_to_be_bytes(const bn_t *bn, byte_buf_t *out);

/* ---- modular arithmetic (all results via *out, which may alias inputs) --- */

/* *out = a mod m  (non-negative result). TS: a % m. BNS_OK / BNS_EINVAL (m==0). */
int bn_mod(const bn_t *a, const bn_t *m, bn_t **out);

/* *out = (a * b) mod m. TS: (a*b) % m. BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int bn_mod_mul(const bn_t *a, const bn_t *b, const bn_t *m, bn_t **out);

/* *out = (a * a) mod m  (Rabin verify s^2 mod n). TS: (s*s) % n.
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int bn_mod_sqr(const bn_t *a, const bn_t *m, bn_t **out);

/* *out = (base ^ exp) mod m  (square-and-multiply). TS: powerMod.
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int bn_mod_exp(const bn_t *base, const bn_t *exp, const bn_t *m, bn_t **out);

/* *out = modular inverse of a mod m (a^-1). TS: extended-Euclid inverse.
 * BNS_OK / BNS_EINVAL (no inverse / m==0) / BNS_ENOMEM. */
int bn_mod_inverse(const bn_t *a, const bn_t *m, bn_t **out);

/* ---- plain arithmetic --------------------------------------------------- */

/* *out = a + b. BNS_OK / BNS_ENOMEM. TS: a + b. */
int bn_add(const bn_t *a, const bn_t *b, bn_t **out);

/* *out = a - b (may be negative). BNS_OK / BNS_ENOMEM. TS: a - b. */
int bn_sub(const bn_t *a, const bn_t *b, bn_t **out);

/* *out = a * b. BNS_OK / BNS_ENOMEM. TS: a * b (e.g. n = p*q). */
int bn_mul(const bn_t *a, const bn_t *b, bn_t **out);

/* ---- comparison / predicates -------------------------------------------- */

/* Three-way compare: <0 if a<b, 0 if a==b, >0 if a>b. TS: bigint compare. */
int bn_cmp(const bn_t *a, const bn_t *b);

/* True iff bn == 0. TS: n === 0n. */
bool bn_is_zero(const bn_t *bn);

#endif /* BONSAI_CRYPTO_BIGNUM_H */
