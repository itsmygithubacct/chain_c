/*
 * ecdsa.h — secp256k1 ECDSA signing/verification (opaque handles).
 *
 * Wraps libsecp256k1 as OPAQUE handles (no <secp256k1.h> here). The signing
 * contract for the charter, every contract checkSig, cpfp, and deploy.
 *
 * TS origin: bsv.PrivateKey / bsv.PublicKey, bsv.crypto.ECDSA.{sign,verify},
 * bsv.crypto.Signature.{toDER,fromDER}.
 *
 * TWO DISTINCT HASHING CONVENTIONS (plan.risks — do not conflate):
 *  - CHARTER: bsv signs the ALREADY-SHA256'd 32-byte digest DIRECTLY (a single
 *    hash). ecdsa_sign_low_s() takes that 32-byte digest verbatim — DO NOT
 *    double-hash the charter.
 *  - TX SIGHASH: the digest fed in is the BIP143/FORKID double-SHA256 preimage
 *    hash with sighash flag 0x41 (SIGHASH_ALL|FORKID) — computed in sighash.h,
 *    then passed here as a 32-byte digest.
 * In both cases this module signs a 32-byte digest; it never hashes for you.
 *
 * Signatures are RFC6979 deterministic-k and LOW-S canonical DER (bsv/BIP62
 * default; libsecp256k1 normalizes on sign).
 *
 * Ownership: handles are heap-allocated; *_free releases. Fallible fns return
 * int (bonsai_err_t); the verify predicate returns bool.
 */
#ifndef BONSAI_CRYPTO_ECDSA_H
#define BONSAI_CRYPTO_ECDSA_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/hash.h"   /* BONSAI_SHA256_LEN (the digest width we sign over) */

#define BONSAI_ECDSA_PUBKEY_COMPRESSED_LEN 33  /* compressed SEC (02/03 prefix) */
#define BONSAI_ECDSA_SECKEY_LEN            32  /* raw private key               */

/* Opaque private key (secret scalar). TS: bsv.PrivateKey. */
typedef struct ecdsa_key_s ecdsa_key_t;

/* Opaque public key (curve point). TS: bsv.PublicKey. */
typedef struct ecdsa_pubkey_s ecdsa_pubkey_t;

/* ---- private key construction ------------------------------------------- */

/* Parse a WIF string -> private key. Also yields whether the WIF marked the key
 * compressed (out_compressed may be NULL). TS: bsv.PrivateKey.fromWIF.
 * BNS_OK / BNS_EPARSE (bad base58check/version) / BNS_ENOMEM. */
int ecdsa_key_from_wif(const char *wif, ecdsa_key_t **out, bool *out_compressed);

/* Build a private key from 32 raw secret bytes. TS: bsv.PrivateKey from BN.
 * BNS_OK / BNS_EINVAL (out of range / zero) / BNS_ENOMEM. */
int ecdsa_key_from_bytes(const uint8_t secret[BONSAI_ECDSA_SECKEY_LEN],
                         ecdsa_key_t **out);

/* Generate a cryptographically random private key (uses crypto/rand.h).
 * TS: bsv.PrivateKey.fromRandom. BNS_OK / BNS_ECRYPTO / BNS_ENOMEM. */
int ecdsa_key_random(ecdsa_key_t **out);

/* Release a private key (NULL-safe). */
void ecdsa_key_free(ecdsa_key_t *key);

/* Derive the compressed public key from a private key. TS: privKey.publicKey.
 * BNS_OK / BNS_ECRYPTO / BNS_ENOMEM. */
int ecdsa_key_derive_pubkey(const ecdsa_key_t *key, ecdsa_pubkey_t **out);

/* Serialize the private key's 32 raw secret bytes into `out`. BNS_OK. */
int ecdsa_key_to_bytes(const ecdsa_key_t *key,
                       uint8_t out[BONSAI_ECDSA_SECKEY_LEN]);

/* ---- public key parse / serialize --------------------------------------- */

/* Parse 33-byte compressed (or 65-byte uncompressed) SEC pubkey bytes.
 * TS: bsv.PublicKey.fromBuffer. BNS_OK / BNS_EPARSE / BNS_ENOMEM. */
int ecdsa_pubkey_parse(const uint8_t *sec, size_t len, ecdsa_pubkey_t **out);

/* Parse a pubkey from hex (compressed or uncompressed, normalizes to a valid
 * point). TS: bsv.PublicKey.fromString / fromHex.
 * BNS_OK / BNS_EPARSE / BNS_ENOMEM. */
int ecdsa_pubkey_from_hex(const char *hex, ecdsa_pubkey_t **out);

/* Serialize to 33-byte COMPRESSED SEC form into `out`. TS: pub.toBuffer (compressed).
 * BNS_OK / BNS_ECRYPTO. */
int ecdsa_pubkey_serialize_compressed(
        const ecdsa_pubkey_t *pub,
        uint8_t out[BONSAI_ECDSA_PUBKEY_COMPRESSED_LEN]);

/* Compressed pubkey as freshly malloc'd lowercase hex (66 chars, 02/03 prefix).
 * TS: pub.toString() / toHex(). Caller frees *out. BNS_OK / BNS_ENOMEM. */
int ecdsa_pubkey_to_hex(const ecdsa_pubkey_t *pub, char **out);

/* Release a public key (NULL-safe). */
void ecdsa_pubkey_free(ecdsa_pubkey_t *pub);

/* ---- sign / verify ------------------------------------------------------ */

/* Sign a 32-byte digest with RFC6979 deterministic-k, normalized to LOW-S, and
 * serialize as canonical DER bytes appended to `out` (init'd). The digest is
 * signed verbatim (NOT hashed again) — see header note on the two conventions.
 * TS: bsv.crypto.ECDSA.sign(hashBuf, key).toDER().
 * BNS_OK / BNS_ECRYPTO / BNS_ENOMEM. */
int ecdsa_sign_low_s(const uint8_t digest32[BONSAI_SHA256_LEN],
                     const ecdsa_key_t *key, byte_buf_t *out);

/* Verify a DER signature (`der`/`der_len`) over a 32-byte digest under `pub`.
 * Pure predicate. Accepts the low-S canonical form bsv emits.
 * TS: bsv.crypto.ECDSA.verify(hashBuf, Signature.fromDER(der), pub). */
bool ecdsa_verify(const uint8_t digest32[BONSAI_SHA256_LEN],
                  const uint8_t *der, size_t der_len,
                  const ecdsa_pubkey_t *pub);

#endif /* BONSAI_CRYPTO_ECDSA_H */
