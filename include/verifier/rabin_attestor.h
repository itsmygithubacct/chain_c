/*
 * rabin_attestor.h — Rabin-signature attestation toolkit: the canonical
 * sequenced attestation message builder, the signing daemon half, wire-format
 * parsing, and the verifying half that plugs into ReleaseAnchorVerifier as its
 * AttestationVerifier. Uses Rabin (not ECDSA) so the same signature verifies
 * in-script on BSV via RabinVerifier.verifySig in the ARP-1 contracts.
 *
 * TS origin: src/verifier/rabinAttestor.ts (RabinAttestorKey,
 * generateAttestorKey, attestorPubKey, ATTEST_DOMAIN_HEX, attestationMsgHex,
 * RabinAttestorSigner, parseAttestation, RabinAttestationVerifier).
 *
 * The heavy Rabin math lives in crypto/rabin.h (SECURITY_LEVEL=6, bin2hash
 * split-at-16, sign/verify). This header is the attestation-wire adapter.
 *
 * BYTE-EXACTNESS PINS (module notes):
 *  - ATTESTATION MESSAGE = ATTEST_DOMAIN_HEX (ASCII "ARP1_ATTEST_V1", 14 bytes)
 *    || seq as 8-byte LITTLE-ENDIAN hex || digestHex.toLowerCase() (32 bytes).
 *    Total 54 bytes. Guards: seq in [0, 2^63); digest matches /^[0-9a-f]{64}$/i.
 *  - WIRE SIGNATURE = "<seq decimal>:<s lowercase hex, no 0x, no padding>:
 *    <paddingByteCount decimal>". parseAttestation splits on ':' requiring
 *    EXACTLY 3 parts; rejects negative seq / non-integer pad.
 *  - attestorPubKey = n = p*q as a base-10 DECIMAL string.
 *  - Verifier is FAIL-CLOSED: any parse/verify error => false.
 */
#ifndef BONSAI_VERIFIER_RABIN_ATTESTOR_H
#define BONSAI_VERIFIER_RABIN_ATTESTOR_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "crypto/bignum.h"                       /* bn_t                 */
#include "crypto/rabin.h"                        /* rabin_key_t, rabin_sig_t */
#include "verifier/release_anchor_verifier.h"    /* attestation_verifier_t */

/* Hex of ASCII "ARP1_ATTEST_V1" (14 bytes), the domain-tag prefix of every
 * attestation message. TS: rabinAttestor.ts::ATTEST_DOMAIN_HEX. */
#define BONSAI_ATTEST_DOMAIN_HEX "415250315f4154544553545f5631"

/* A Rabin attestor private key (the two prime factors). Reuses the frozen
 * crypto/rabin.h key shape. TS: rabinAttestor.ts::RabinAttestorKey {p,q}. */
typedef rabin_key_t rabin_attestor_key_t;

/* ---- keygen / pubkey (NON-deterministic; off the byte-exact path) ------- */

/* Generate a fresh keypair (rabin_keygen). *out freed via rabin_key_free.
 * TS: rabinAttestor.ts::generateAttestorKey. BNS_OK / BNS_ECRYPTO / BNS_ENOMEM. */
int generate_attestor_key(rabin_attestor_key_t *out);

/* attestorPubKey = n = p*q as a freshly malloc'd base-10 DECIMAL string (caller
 * frees) into *out. TS: rabinAttestor.ts::attestorPubKey. BNS_OK / BNS_ENOMEM. */
int attestor_pub_key(const rabin_attestor_key_t *key, char **out);

/* ---- message construction ----------------------------------------------- */

/* Build the exact hex message that is Rabin-signed: ATTEST_DOMAIN_HEX ||
 * seq(8-byte LE hex) || lowercase(digestHex). Writes a freshly malloc'd
 * NUL-terminated lowercase-hex string (108 chars / 54 bytes) to *out (caller
 * frees). Rejects seq >= 2^63 or a malformed 64-hex digest with BNS_EINVAL.
 * TS: rabinAttestor.ts::attestationMsgHex. BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int attestation_msg_hex(uint64_t seq, const char *digest_hex, char **out);

/* ---- signer ------------------------------------------------------------- */

/* Sign the digest at sequence `seq`: build the message, Rabin-sign it, and emit
 * the wire format "<seq>:<s hex>:<paddingByteCount>" into *out (freshly malloc'd,
 * caller frees). `key` is the attestor private key.
 * TS: rabinAttestor.ts::RabinAttestorSigner.signDigest.
 * BNS_OK / BNS_EINVAL (bad digest/seq) / BNS_ECRYPTO / BNS_ENOMEM. */
int rabin_attestor_sign_digest(const rabin_attestor_key_t *key,
                               const char *digest_hex, uint64_t seq,
                               char **out);

/* ---- wire parsing ------------------------------------------------------- */

/* A parsed attestation. `s` is an OWNED bn_t (release via bn_free).
 * TS: rabinAttestor.ts::parseAttestation return shape. */
typedef struct {
    uint64_t seq;
    bn_t    *s;                 /* owned signature value */
    size_t   padding_byte_count;
} parsed_attestation_t;

/* Parse the wire format "seq:sHex:padCount": seq decimal, s as hex (no 0x),
 * pad decimal. Sets *out_ok=false (BNS_OK) on ANY malformation (wrong part
 * count, bad numbers, negative seq/pad) — the TS null. On success *out_ok=true
 * and *out is filled (caller frees out->s). TS: rabinAttestor.ts::parseAttestation.
 * BNS_OK / BNS_ENOMEM. */
int parse_attestation(const char *signature, parsed_attestation_t *out,
                      bool *out_ok);

/* Release the owned bn_t of a parsed attestation (NULL-safe). */
void parsed_attestation_free(parsed_attestation_t *p);

/* ---- verifier ----------------------------------------------------------- */

/* RabinAttestationVerifier.verify: parse the signature, reconstruct the message
 * at the embedded seq, and rabin_verify against n = BigInt(attestorPubkey, base
 * 10). FAIL-CLOSED: any parse/verify error => *out_ok=false. Pure predicate
 * semantics. TS: rabinAttestor.ts::RabinAttestationVerifier.verify. Always BNS_OK. */
int rabin_attestation_verify(const char *attestor_pubkey,
                             const char *digest_hex, const char *signature,
                             bool *out_ok);

/* Populate an attestation_verifier_t vtable (release_anchor_verifier.h) backed
 * by the stateless Rabin verifier above (ctx unused). BNS_OK. */
int rabin_attestation_verifier_vtable(attestation_verifier_t *out_vtable);

#endif /* BONSAI_VERIFIER_RABIN_ATTESTOR_H */
