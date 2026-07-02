/*
 * contracts/zk_hidden_limit.h — the Pillar-B hidden-policy-limit companion:
 * pins a Groth16 verifying key + a MiMC7 commitment to a secret spend limit, and
 * attest(amount, proof) recomputes the circuit's single public input in-script as
 * MiMC7(amount, limitCommitment) then runs an in-script BN254 Groth16 pairing
 * check. Proves a public cost is within a private committed limit without
 * revealing it.
 *
 * TS origin: src/contracts/zkHiddenLimit.ts (ZkHiddenLimit, vk, limitCommitment,
 * constructor, attest); the zk machinery lives in src/zk/{g16,mimc7,limit-
 * Commitment}.ts -> include/zk/{g16,mimc7,limit_commitment}.h (NOT yet present).
 *
 * This header deliberately does NOT include the include/zk/ headers (authored
 * separately and may be gated behind BONSAI_ENABLE_ZK). It refers to the Groth16
 * verifying key and proof as OPAQUE handles (g16_vk_t / g16_proof_t) whose full
 * definitions live in include/zk/g16.h; this keeps zk_hidden_limit.h parseable
 * standalone and lets the contract layer compile without the (large) BN254 tower.
 *
 * DETERMINISM/SECURITY (zkHiddenLimit.ts notes):
 *  - The single public input (N=1) binds the public amount AND the private
 *    (limit,salt) opening: input = Mimc7.hash(amount, limitCommitment).
 *  - MiMC7 CONSTS table exact; t^7 round reduced mod the BN254 SCALAR field r
 *    each round (NOT the base field P). Nesting per circomlib.
 *  - The BN254 Fp12 tower, G1 negation, and the precalc pairing arg order
 *    (a0,b,millerb1a1,vk_x,gamma,c,delta) must match the compiled artifact.
 *  - PROVING shells out to snarkjs/circom (src/zk/prover); the C side reproduces
 *    only the on-chain VERIFY.
 *  - The committed setup is a LOCAL single-contributor trusted setup —
 *    reference-only, NOT production.
 *  - The 2.8 MB artifact `hex` IS the locking script; reconstruct from artifact
 *    with vk + limitCommitment substituted — never regenerate by hand.
 */
#ifndef BONSAI_CONTRACTS_ZK_HIDDEN_LIMIT_H
#define BONSAI_CONTRACTS_ZK_HIDDEN_LIMIT_H

#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/bignum.h"
#include "scrypt/scrypt_contract.h"

/* Opaque Groth16 verifying key. Full definition in include/zk/g16.h
 * (VerifyingKey { millerb1a1, gamma, delta, gammaAbc[2] }). TS: zk/g16.ts. */
typedef struct g16_vk_s   g16_vk_t;

/* Opaque Groth16 proof (the snarkjs {pi_a, pi_b, pi_c} / on-chain Proof). Full
 * definition in include/zk/g16.h. TS: zk/g16.ts::Proof. */
typedef struct g16_proof_s g16_proof_t;

/* A live ZkHiddenLimit instance: the loaded artifact bound to the verifying key
 * (borrowed; large) and the MiMC7 limit commitment (owned bn_t). The locking
 * script is reconstructed from the artifact with vk + limitCommitment
 * substituted. TS: an instantiated ZkHiddenLimit SmartContract. */
typedef struct {
    const scrypt_artifact_t *artifact;       /* borrowed compiled zkHiddenLimit.json */
    const g16_vk_t          *vk;             /* borrowed verifying key               */
    bn_t                    *limit_commitment;/* owned MiMC7(limit,salt) scalar       */
} zk_hidden_limit_t;

/* Release the owned limit_commitment and zero the struct (NULL-safe; artifact
 * and vk are borrowed). */
void zk_hidden_limit_free(zk_hidden_limit_t *c);

/* Reconstruct the locking script bytes into `out` (init'd) from the artifact
 * with vk + limitCommitment substituted. Delegates to scrypt/script_codec.h.
 * BNS_OK / BNS_EINVAL / BNS_EPARSE / BNS_EUNSUPPORTED (zk compiled out) / BNS_ENOMEM. */
int zk_hidden_limit_locking_script(const zk_hidden_limit_t *c, byte_buf_t *out);

/* Model the attest() assertion off-chain: require amount>0, compute
 * input = Mimc7.hash(amount, limitCommitment), and verify the Groth16 proof over
 * the single public input [input] under vk (the C reproduction of
 * G16BN256.verify). Fills *out_ok with the verification result. The heavy lifting
 * (MiMC7 + BN254 pairing) lives in include/zk/{mimc7,g16}.h.
 * TS: zkHiddenLimit.ts::attest. BNS_OK (result in *out_ok) /
 * BNS_EINVAL (amount<=0) / BNS_EUNSUPPORTED (zk compiled out) / BNS_ENOMEM. */
int zk_hidden_limit_attest_verify(const zk_hidden_limit_t *c,
                                  const bn_t *amount,
                                  const g16_proof_t *proof,
                                  bool *out_ok);

#endif /* BONSAI_CONTRACTS_ZK_HIDDEN_LIMIT_H */
