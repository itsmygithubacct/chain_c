/*
 * hash.h — the single hashing contract for the whole port.
 *
 * Mirrors scrypt-ts/bsv hashing: sha256 (single), hash256/sha256d (double),
 * ripemd160 (vendored — see third_party/ripemd160), hash160 (sha256 then
 * ripemd160, == BSV pubkey-hash), and sha512. Used for receipts, txid, merkle
 * roots, hash160/address derivation, shred markers, and the charter hash.
 *
 * TS origin: scrypt-ts `sha256`/`hash256`/`hash160`/`Ripemd160`,
 * bsv.crypto.Hash.{sha256,sha256sha256,ripemd160,sha256ripemd160,sha512}.
 *
 * RISK (plan.risks): OpenSSL 3 RIPEMD160 lives in the legacy provider; this
 * port uses the vendored ripemd160 instead so hash160/address derivation never
 * silently fails. SHA256/SHA512 use the OpenSSL default provider.
 *
 * Convention: raw forms write into caller-provided fixed-size out arrays and
 * return void (they cannot fail). Hex-in/hex-out convenience forms parse hex
 * and so return int (bonsai_err_t) with the result via an out-param.
 */
#ifndef BONSAI_CRYPTO_HASH_H
#define BONSAI_CRYPTO_HASH_H

#include <stddef.h>
#include <stdint.h>
#include "common/error.h"
#include "common/bytes.h"

#define BONSAI_SHA256_LEN    32
#define BONSAI_SHA512_LEN    64
#define BONSAI_RIPEMD160_LEN 20
#define BONSAI_HASH160_LEN   20

/* ---- raw byte forms (out = caller-provided fixed buffer) ---------------- */

/* out = SHA256(data[0..len)). TS: scrypt-ts sha256 / bsv.crypto.Hash.sha256. */
void sha256(const uint8_t *data, size_t len, uint8_t out[BONSAI_SHA256_LEN]);

/* out = SHA256(SHA256(data)). TS: hash256 / bsv.crypto.Hash.sha256sha256.
 * Used for txid and BIP143 sighash double-hash (NOT for the charter). */
void sha256d(const uint8_t *data, size_t len, uint8_t out[BONSAI_SHA256_LEN]);

/* out = RIPEMD160(data). TS: scrypt-ts Ripemd160 / bsv ripemd160 (vendored). */
void ripemd160_hash(const uint8_t *data, size_t len,
                    uint8_t out[BONSAI_RIPEMD160_LEN]);

/* out = RIPEMD160(SHA256(data)). TS: scrypt-ts hash160 /
 * bsv.crypto.Hash.sha256ripemd160 — the BSV pubkey hash. */
void hash160(const uint8_t *data, size_t len, uint8_t out[BONSAI_HASH160_LEN]);

/* out = SHA512(data). TS: bsv.crypto.Hash.sha512. */
void sha512(const uint8_t *data, size_t len, uint8_t out[BONSAI_SHA512_LEN]);

/* ---- hex-in / hex-out convenience forms --------------------------------- */
/* Each decodes `hex_in` (lowercase or upper), hashes the decoded bytes, and
 * writes a freshly malloc'd lowercase-hex NUL-terminated string to *hex_out
 * (caller frees). Return BNS_OK / BNS_EPARSE (bad hex) / BNS_ENOMEM. */

/* hex_out = hex(SHA256(decode(hex_in))). */
int sha256_hex(const char *hex_in, char **hex_out);

/* hex_out = hex(SHA256(SHA256(decode(hex_in)))). */
int sha256d_hex(const char *hex_in, char **hex_out);

/* hex_out = hex(RIPEMD160(decode(hex_in))). */
int ripemd160_hex(const char *hex_in, char **hex_out);

/* hex_out = hex(RIPEMD160(SHA256(decode(hex_in)))). */
int hash160_hex(const char *hex_in, char **hex_out);

/* hex_out = hex(SHA512(decode(hex_in))). */
int sha512_hex(const char *hex_in, char **hex_out);

/* ---- byte_buf convenience ----------------------------------------------- */

/* Append SHA256(in) (32 bytes) to `out` (must be init'd). BNS_OK / BNS_ENOMEM.
 * Convenience for preimage builders that accumulate digests. */
int sha256_buf(const byte_buf_t *in, byte_buf_t *out);

#endif /* BONSAI_CRYPTO_HASH_H */
