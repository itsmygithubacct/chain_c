/*
 * contracts_next/attestor_tea.h — the ARP-1 bonded-attestor contract (v1): a
 * STATELESS contract whose UTXO value is an attestor's slashable Rabin bond.
 * Equivocation slashing (two Rabin sigs over the same seq, different activate
 * digests => anyone may slash, burn-split), anyone-may stake top-up, and an
 * operator withdraw gated by an absolute nLocktime unbonding floor.
 *
 * The C port reconstructs the lockingScript from the compiled AttestorTea
 * artifact (NOT yet in artifacts/) by substituting the 3 ctor @props. Being
 * stateless, every recreate reuses ctx.utxo.script verbatim — so a verifier needs
 * the actual prevout script bytes for stake().
 *
 * TS origin: src/contracts-next/attestorTea.ts (AttestorTea: operator,
 * attestorRabinPubKey, unbondNotBefore; slashEquivocation, stake, withdraw).
 *
 * DETERMINISM PINS (attestorTea.ts notes):
 *  (1) Rabin hash = SECURITY_LEVEL=6 (6 expandHash blocks); off-by-one = wrong h.
 *  (2) fromLEUnsigned is LITTLE-endian over the 384-byte hash buffer.
 *  (3) sig.padding bytes (all-zero, paddingByteCount) are concatenated to msg
 *      BEFORE hashing.
 *  (4) bounty = value/2 INTEGER floor-division; burn = value - bounty.
 *  (5) stake() has NO signature gate — do NOT add one.
 *  (6) Both equivocation messages are ArpAttest.attestationMsg(seq, digest{A,B})
 *      (contracts_next/arp_attest.h) — byte-identical to the 54-byte linchpin.
 *  (7) The burn output is OP_FALSE OP_RETURN 'SLASHED\0' (8 bytes ending NUL).
 */
#ifndef BONSAI_CONTRACTS_NEXT_ATTESTOR_TEA_H
#define BONSAI_CONTRACTS_NEXT_ATTESTOR_TEA_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/bignum.h"
#include "scrypt/scrypt_contract.h"
#include "contracts_next/arp_attest.h"
#include "lib/rabin_verifier.h"

/* The burn marker carried in the OP_FALSE OP_RETURN slash output: 'SLASHED\0'
 * (8 bytes ending in a literal NUL). TS: 'SLASHED\0' burn data. */
#define BONSAI_ARP_SLASHED_MARKER_HEX "534c41534845440000"  /* 'SLASHED' + 00, 8B */

/* The 3 AttestorTea constructor arguments, in @prop declaration order. operator
 * is a 33-byte compressed PubKey; attestorRabinPubKey is a Rabin modulus bn_t;
 * unbondNotBefore is a bigint nLocktime. Owns its members; *_free releases.
 * TS: attestorTea.ts constructor. */
typedef struct {
    byte_buf_t operator_pubkey;       /* operator PubKey (33B)                    */
    bn_t      *attestor_rabin_pubkey; /* attestorRabinPubKey (Rabin n)            */
    bn_t      *unbond_not_before;     /* unbondNotBefore (nLocktime floor)        */
} attestor_tea_params_t;

/* A live AttestorTea instance (stateless). The artifact is borrowed. TS: an
 * instantiated AttestorTea SmartContract. */
typedef struct {
    const scrypt_artifact_t *artifact; /* borrowed compiled attestorTea.json      */
    attestor_tea_params_t    params;   /* owned ctor args                         */
} attestor_tea_t;

void attestor_tea_params_free(attestor_tea_params_t *p);
void attestor_tea_free(attestor_tea_t *c);

/* Reconstruct the (stateless) locking script bytes into `out` (init'd):
 * substitutes the 3 ctor args via the ctor encoders (no state suffix).
 * Delegates to scrypt/script_codec.h. BNS_OK / BNS_EINVAL / BNS_EPARSE / BNS_ENOMEM. */
int attestor_tea_locking_script(const attestor_tea_t *c, byte_buf_t *out);

/* Model slashEquivocation()'s acceptance test off-chain: require digestA !=
 * digestB, and that sigA and sigB both Rabin-verify under attestorRabinPubKey
 * over ArpAttest.attestationMsg(seq, digestA) and (seq, digestB) respectively.
 * Fills *out_ok. `digest_a`/`digest_b` are 32 raw bytes. Pure check; fail-closed.
 * TS: attestorTea.ts::slashEquivocation gate. BNS_OK (result in *out_ok) /
 * BNS_EINVAL / BNS_ENOMEM. */
int attestor_tea_check_equivocation(const attestor_tea_t *c,
                                    const bn_t *seq,
                                    const uint8_t digest_a[32],
                                    const rabin_verifier_sig_t *sig_a,
                                    const uint8_t digest_b[32],
                                    const rabin_verifier_sig_t *sig_b,
                                    bool *out_ok);

#endif /* BONSAI_CONTRACTS_NEXT_ATTESTOR_TEA_H */
