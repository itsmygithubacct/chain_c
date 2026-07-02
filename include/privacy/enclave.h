/*
 * enclave.h — PrivateEnclave: the off-chain, per-identity AES-256-GCM-encrypted
 * store for an agent's action payloads/PII. The chain holds only H(action); the
 * plaintext lives here encrypted under a per-identity KeyVault key, and 'erasure'
 * (crypto-shredding) destroys the key while the on-chain receipt commitment
 * stands. Also derives the keyed on-chain actionHash and the shred-marker.
 *
 * TS origin: src/privacy/enclave.ts (SealedRecord, EnclaveOpts, PrivateEnclave,
 * ShreddedError, IntegrityError) over crypto/aes_gcm.h + crypto/hash.h.
 *
 * BYTE-EXACTNESS PINS (module notes):
 *  - AES-256-GCM: key=32B from vault; IV=12 CSPRNG bytes; AAD = UTF-8 bytes of
 *    identityId (binds identityId into the tag); tag=16B. ciphertext/iv/authTag
 *    serialized lowercase hex.
 *  - actionHash = SHA256 over EXACTLY three chunks, NO separators:
 *    ASCII "PRISCILLA_ACTION_V1" (19 bytes) || raw 32-byte key bytes (NOT hex)
 *    || raw plaintext payload bytes. Lowercase hex.
 *  - shredMarker = SHA256("SHRED_V1" (8B) || UTF-8 identityId). Lowercase hex.
 *    MUST byte-match reputation_indexer.h::shred_marker_hex.
 *  - string payload -> UTF-8 bytes before BOTH hashing and encryption.
 *  - provenanceHash = ZERO_PROVENANCE hex ("00"*32) when none, else
 *    compute_provenance_hash.
 *  - open() distinguishes exactly two failures: BNS_ESHREDDED (key gone) and
 *    BNS_EINTEGRITY (GCM auth failure); leak nothing further.
 */
#ifndef BONSAI_PRIVACY_ENCLAVE_H
#define BONSAI_PRIVACY_ENCLAVE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"
#include "privacy/key_vault.h"
#include "provenance.h"             /* provenance_record_t */

/* The literal action-commitment domain tag (19 ASCII bytes, no NUL/separator).
 * TS: enclave.ts actionCommitment domain. */
#define BONSAI_PRISCILLA_ACTION_DOMAIN "PRISCILLA_ACTION_V1"
/* The shred-marker domain tag (8 ASCII bytes). TS: enclave.ts shredMarker. */
#define BONSAI_SHRED_MARKER_DOMAIN "SHRED_V1"

/* A stored encrypted record: hex ciphertext/iv/authTag, unix-seconds sealedAt,
 * plus optional plaintext provenance metadata (has_provenance=false => none).
 * `ciphertext`/`iv`/`auth_tag` are OWNED lowercase-hex strings. TS:
 * enclave.ts::SealedRecord. */
typedef struct {
    char               *identity_id;  /* owned */
    char               *ciphertext;   /* owned lowercase hex */
    char               *iv;           /* owned lowercase hex (12 bytes => 24 hex) */
    char               *auth_tag;     /* owned lowercase hex (16 bytes => 32 hex) */
    int64_t             sealed_at;    /* unix seconds */
    provenance_record_t provenance;   /* valid iff has_provenance */
    bool                has_provenance;
} sealed_record_t;

/* Release the owned members of a sealed_record_t and zero it (NULL-safe). */
void sealed_record_free(sealed_record_t *rec);

/* Injectable clock returning unix seconds. NULL => Math.floor(Date.now()/1000).
 * TS: EnclaveOpts.now. */
typedef int64_t (*enclave_clock_fn)(void *user);

/* Opaque PrivateEnclave handle (borrows a KeyVault). TS: enclave.ts::PrivateEnclave. */
typedef struct private_enclave_s private_enclave_t;

/* ---- lifecycle ---------------------------------------------------------- */

/* Construct an enclave over a borrowed KeyVault (must outlive it) and an optional
 * injected clock (NULL => wall-clock seconds). *out freed via private_enclave_free.
 * TS: new PrivateEnclave(vault, opts). BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int private_enclave_new(const key_vault_t *vault,
                        enclave_clock_fn clock, void *clock_user,
                        private_enclave_t **out);

/* Release the enclave (NULL-safe; does not free the vault). */
void private_enclave_free(private_enclave_t *enc);

/* ---- seal / open -------------------------------------------------------- */

/* AES-256-GCM encrypt `plaintext` under vault.ensureKey(identityId) with a fresh
 * 12-byte CSPRNG IV and AAD = UTF-8(identityId); writes the SealedRecord to *out
 * (owned; release via sealed_record_free). `plaintext` is the raw payload bytes
 * (caller pre-UTF-8-encodes a string). TS: PrivateEnclave.seal.
 * BNS_OK / BNS_ECRYPTO / BNS_ENOMEM. */
int private_enclave_seal(private_enclave_t *enc, const char *identity_id,
                         const uint8_t *plaintext, size_t plaintext_len,
                         sealed_record_t *out);

/* Compute the keyed actionHash (see header note), seal the payload, attach the
 * optional provenance (provenance may be NULL => none), and compute the
 * provenanceHash. Writes the sealed record to *out_sealed (owned) and freshly
 * malloc'd lowercase-hex strings to *out_action_hash and *out_provenance_hash
 * (caller frees both). TS: PrivateEnclave.sealAction.
 * BNS_OK / BNS_ECRYPTO / BNS_ENOMEM. */
int private_enclave_seal_action(private_enclave_t *enc, const char *identity_id,
                                const uint8_t *payload, size_t payload_len,
                                const provenance_record_t *provenance,
                                sealed_record_t *out_sealed,
                                char **out_action_hash,
                                char **out_provenance_hash);

/* Recompute the keyed actionHash for auditor verification. Sets *out_found=false
 * (BNS_OK) once the key is shredded (the erasure property, NOT an error); else
 * writes a freshly malloc'd lowercase-hex string to *out_hex (caller frees).
 * TS: PrivateEnclave.recomputeActionHash. BNS_OK / BNS_ENOMEM. */
int private_enclave_recompute_action_hash(private_enclave_t *enc,
                                          const char *identity_id,
                                          const uint8_t *payload,
                                          size_t payload_len,
                                          char **out_hex, bool *out_found);

/* AES-256-GCM decrypt `record` with AAD = UTF-8(identityId) and the stored tag;
 * appends the recovered plaintext to `out` (init'd by caller). Returns
 * BNS_ESHREDDED if the key was shredded, BNS_EINTEGRITY on auth failure.
 * TS: PrivateEnclave.open. BNS_OK / BNS_ESHREDDED / BNS_EINTEGRITY / BNS_ENOMEM. */
int private_enclave_open(private_enclave_t *enc, const sealed_record_t *record,
                         byte_buf_t *out);

/* ---- shred / marker ----------------------------------------------------- */

/* Destroy the identity's key via vault.shred; sets *out_shredded to whether a
 * key was present, and writes the on-chain shred-marker commitment to *out_marker
 * (freshly malloc'd lowercase hex, caller frees). TS: PrivateEnclave.shred.
 * BNS_OK / BNS_ENOMEM. */
int private_enclave_shred(private_enclave_t *enc, const char *identity_id,
                          bool *out_shredded, char **out_marker);

/* Static shred-marker: SHA256("SHRED_V1" || UTF-8 identityId) as freshly
 * malloc'd lowercase hex (caller frees). MUST byte-match shred_marker_hex.
 * TS: PrivateEnclave.shredMarker (static). BNS_OK / BNS_ENOMEM. */
int private_enclave_shred_marker(const char *identity_id, char **out);

#endif /* BONSAI_PRIVACY_ENCLAVE_H */
