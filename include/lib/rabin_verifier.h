/*
 * rabin_verifier.h — a thin in-contract wrapper over crypto/rabin.h mirroring
 * scrypt-ts-lib RabinVerifier.verifySig and the attestation-message hashing the
 * contracts use, expressed in terms of the contracts' wire shapes (ByteString
 * message, RabinSig {s, padding}, RabinPubKey n).
 *
 * The heavy lifting (rabin_hash with SECURITY_LEVEL=6, sign/verify, byte-exact
 * bin2hash split-at-16) lives in crypto/rabin.h. This header adapts that to the
 * scrypt-ts-lib RabinVerifier.verifySig signature so contract methods
 * (rabinSpike / ricardianTea slashing / ARP quorum) and tests call it the same
 * way the TS does.
 *
 * TS origin: scrypt-ts-lib RabinVerifier.verifySig / RabinVerifier.hash;
 * src/verifier/rabinAttestor.ts attestation-message construction.
 */
#ifndef BONSAI_LIB_RABIN_VERIFIER_H
#define BONSAI_LIB_RABIN_VERIFIER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/bignum.h"
#include "crypto/rabin.h"

/* The contract-side Rabin signature wire shape: signature value `s` plus the
 * raw `padding` ByteString (the appended 0x00 bytes), exactly as scrypt-ts-lib
 * passes it. `s` is a borrowed bn_t; `padding` is borrowed bytes. This differs
 * from crypto/rabin.h's rabin_sig_t (which stores a padding BYTE COUNT) — the
 * adapter derives padding_byte_count = padding_len. TS: RabinSig {s, padding}. */
typedef struct {
    const bn_t    *s;           /* borrowed signature value                       */
    const uint8_t *padding;     /* borrowed padding bytes (the 0x00 run)          */
    size_t         padding_len; /* number of padding bytes                        */
} rabin_verifier_sig_t;

/* RabinVerifier.verifySig(msg, sig, pubKey): append `sig.padding` to `msg`,
 * rabin_hash the result, and return (hash mod n) == (s*s mod n). Pure predicate;
 * fail-closed on any internal error. `msg`/`msg_len` are the RAW message bytes
 * (the hex-decoded attestation message). TS: RabinVerifier.verifySig.
 * Equivalent to crypto/rabin.h rabin_verify with padding_byte_count = padding_len. */
bool rabin_verifier_verify_sig(const uint8_t *msg, size_t msg_len,
                               const rabin_verifier_sig_t *sig,
                               const bn_t *n);

/* Hash an attestation message body the way the contracts/attestor do before
 * Rabin verification: append it into the preimage and return rabin_hash of the
 * assembled bytes via *out (fresh bn_t, caller frees). Provided so the attestor
 * and tests build the exact pre-padding message bytes consistently.
 * TS: rabinAttestor attestation-message hashing / RabinVerifier.hash.
 * BNS_OK / BNS_ENOMEM. */
int rabin_verifier_hash(const uint8_t *msg, size_t msg_len, bn_t **out);

#endif /* BONSAI_LIB_RABIN_VERIFIER_H */
