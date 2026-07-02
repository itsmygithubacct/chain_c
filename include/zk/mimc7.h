/*
 * mimc7.h — the MiMC7 sponge hash over the BN254 SCALAR field r, ported from
 * scrypt-ts-lib/dist/hash/mimc7.js (circomlib keccak-seeded). The hiding
 * commitment primitive: limitCommitment = MiMC7(limit, salt) and the in-circuit
 * binding out = MiMC7(cost, MiMC7(limit, salt)).
 *
 * TS origin: scrypt-ts-lib Mimc7 (Mimc7.hash, Mimc7.SNARK_SCALAR_FIELD);
 * round constants in third_party/mimc7_consts/mimc7_consts.h.
 *
 * BYTE/FIELD-EXACTNESS PINS (module notes — must match circomlib MiMC7(91) and
 * the on-chain ZkHiddenLimit field-for-field):
 *  - Field is the SCALAR field r = 21888242871839275222246405745257275088
 *    548364400416034343698204186575808495617 (NOT the BN256 base field P).
 *  - ROUNDS=91, exponent t^7 each round, CONSTS[0]=0, round 0 uses x+k with no
 *    constant, final step adds k once more:
 *      ret=0; for i in 0..90: t=(i==0)?x+k:ret+k+CONSTS[i];
 *      ret=(t^7) mod r; after loop return (ret+k) mod r.
 *  - Intermediates (t*t, t2*t2, t4*t2*t) are FULL-WIDTH then reduced mod r ONCE
 *    per round; do multiply-then-mod (do not reduce intermediates early).
 */
#ifndef BONSAI_ZK_MIMC7_H
#define BONSAI_ZK_MIMC7_H

#include "common/error.h"
#include "crypto/bignum.h"     /* bn_t scalar */
#include "mimc7_consts.h"      /* MIMC7_ROUNDS, MIMC7_CONSTS, MIMC7_SNARK_SCALAR_FIELD */

/* Return the BN254 scalar field modulus r as a fresh bn_t via *out (caller
 * frees). Parsed from MIMC7_SNARK_SCALAR_FIELD. TS: Mimc7.SNARK_SCALAR_FIELD.
 * BNS_OK / BNS_ENOMEM. */
int mimc7_scalar_field(bn_t **out);

/* mimc7_hash(x, k): the 91-round MiMC7 permutation over the scalar field r (see
 * header note). Both inputs are reduced into [0,r) on entry; result via *out
 * (fresh bn_t, caller frees). TS: Mimc7.hash(x, k). BNS_OK / BNS_ENOMEM. */
int mimc7_hash(const bn_t *x, const bn_t *k, bn_t **out);

#endif /* BONSAI_ZK_MIMC7_H */
