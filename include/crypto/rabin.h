/*
 * rabin.h — the FROZEN, byte-exact Rabin signature contract.
 *
 * Shared by crypto, contracts (rabinSpike/ricardianTea/agentTea slashing/ARP
 * quorum), the verifier (rabin_attestor), and tests. Must be byte-exact vs
 * `rabinsig` + scrypt-ts-lib RabinVerifier; gate on test_rabin_spike before any
 * Rabin consumer.
 *
 * TS origin: tests/utils/rabin.ts, src/verifier/rabinAttestor.ts,
 * scrypt-ts-lib RabinVerifier.verifySig / Rabin.{sign,verify,hash}.
 *
 * BYTE-EXACTNESS PINS (plan.risks — off-by-one anywhere = total verify fail):
 *  - SECURITY_LEVEL = 6  -> rabin_hash expands to exactly 6 expandHash blocks
 *    = 384 bytes, then interpreted as a LITTLE-ENDIAN unsigned bigint.
 *  - bin2hash(b): h = SHA256(b); return SHA256(h[0:16]) || SHA256(h[16:32]).
 *    The split index is 16 (half of 32), NOT 32 — the classic off-by-one trap.
 *  - sign appends single 0x00 padding bytes until x is a QR, then CRT square
 *    root; paddingByteCount counts those bytes.
 *  - verify appends paddingByteCount zero bytes to msg BEFORE hashing, then
 *    checks (hash mod n) == (s*s mod n).
 *  - WIRE: pubkey n is DECIMAL (bn_to_dec); signature s is LOWERCASE HEX,
 *    NO zero-padding (bn_to_hex).
 *
 * Ownership: bn_t out-params and rabin handles are heap-allocated; *_free
 * releases. Fallible fns return int (bonsai_err_t); rabin_verify is a predicate.
 */
#ifndef BONSAI_CRYPTO_RABIN_H
#define BONSAI_CRYPTO_RABIN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/bignum.h"

/* scrypt-ts-lib default RabinVerifier security level (new Rabin() => 6). */
#define BONSAI_RABIN_SECURITY_LEVEL 6
/* rabin_hash output width in bytes (64 * SECURITY_LEVEL). */
#define BONSAI_RABIN_HASH_BYTES     384
/* bin2hash split index — half of the 32-byte SHA256 digest. */
#define BONSAI_RABIN_BIN2HASH_SPLIT 16

/* Rabin private key: the two prime factors p, q (n = p*q is the pubkey).
 * TS: RabinKey { p: bigint; q: bigint }. Owns its bn_t's; rabin_key_free frees. */
typedef struct {
    bn_t *p;   /* owned */
    bn_t *q;   /* owned */
} rabin_key_t;

/* Rabin signature wire shape. TS: RabinSig { s: bigint; padding } where padding
 * is `paddingByteCount` zero bytes. `s` is owned; rabin_sig_free frees it. */
typedef struct {
    bn_t  *s;                 /* owned signature value */
    size_t padding_byte_count;/* # of 0x00 bytes appended to msg before hashing */
} rabin_sig_t;

/* A legitimate Rabin padding count equals the signer's retry count (tiny — single
 * digits). Untrusted attestation strings can claim ~2^63, which would drive a
 * multi-GB byte_buf growth + SHA-256 in rabin_verify (memory-exhaustion DoS). Cap
 * it well above any real value; verify/parse fail closed past this bound. */
#define RABIN_MAX_PADDING_BYTES 4096u

/* ---- lifecycle ---------------------------------------------------------- */

/* Free both prime factors of a key (NULL-safe; also zeroes the struct fields). */
void rabin_key_free(rabin_key_t *key);

/* Free a signature's bn_t (NULL-safe). */
void rabin_sig_free(rabin_sig_t *sig);

/* ---- keygen (NON-deterministic; not on byte-exact paths) ---------------- */

/* Generate a fresh {p,q} keypair (seeds with 2048 random bytes via rand.h).
 * TS: rabin.generatePrivKey(). BNS_OK / BNS_ECRYPTO / BNS_ENOMEM. */
int rabin_keygen(rabin_key_t *out);

/* Derive the public modulus n = p*q. *out is a fresh bn_t (caller frees).
 * TS: rabin.privKeyToPubKey() / privKeyToPubKey. BNS_OK / BNS_ENOMEM. */
int rabin_pubkey(const rabin_key_t *key, bn_t **out);

/* ---- core hash ---------------------------------------------------------- */

/* rabinHashBytes(bytes) with SECURITY_LEVEL=6: result = bin2hash(in); repeat 5
 * times result ||= bin2hash(result) -> 384 bytes; interpret LITTLE-ENDIAN
 * unsigned -> *out (fresh bn_t, caller frees). TS: RabinVerifier.hash / rabin
 * rabinHashBytes. BNS_OK / BNS_ENOMEM. */
int rabin_hash(const uint8_t *data, size_t len, bn_t **out);

/* ---- sign / verify ------------------------------------------------------ */

/* Sign raw message bytes with private key. Loops: x = rabin_hash(msg||pad) mod
 * n; CRT square root; if s*s mod n != x append one 0x00 pad byte and retry.
 * Fills *out_sig (caller frees via rabin_sig_free). `msg` is the RAW message
 * bytes (e.g. the hex-decoded attestation message), NOT a hex string.
 * TS: rabin.sign(msgBytes, key) -> { signature, paddingByteCount }.
 * BNS_OK / BNS_ECRYPTO / BNS_ENOMEM. */
int rabin_sign(const uint8_t *msg, size_t msg_len,
               const rabin_key_t *key, rabin_sig_t *out_sig);

/* Verify a signature against the public modulus `n`. Reconstructs padded msg by
 * appending sig->padding_byte_count zero bytes, hashes, and returns
 * (hash mod n) == (s*s mod n). Pure predicate; fail-closed on any error.
 * TS: rabin.verify(msgBytes, {signature, paddingByteCount}, n). */
bool rabin_verify(const uint8_t *msg, size_t msg_len,
                  const rabin_sig_t *sig, const bn_t *n);

#endif /* BONSAI_CRYPTO_RABIN_H */
