/*
 * g16.h — the encoding bridge between snarkjs Groth16 proof/verification-key
 * JSON (decimal-string field elements) and scrypt-ts-lib's G16BN256 verifier
 * structs over alt_bn128 (BN254/bn128), plus an off-chain verifier replicating
 * the exact Groth16 pairing equation enforced in-script.
 *
 * TS origin: src/zk/g16.ts (SnarkjsVKey, SnarkjsProof, proofFromSnarkjs,
 * vkFromSnarkjs, verifyProofOffChain) over scrypt-ts-lib BN256/BN256Pairing/
 * G16BN256/Proof/VerifyingKey/FQ12.
 *
 * COMPILE GUARD: the off-chain pairing arithmetic (bn256.c/bn256_pairing.c) is
 * heavy; gate its DEFINITIONS behind BONSAI_ENABLE_ZK. These PROTOTYPES are
 * declared REGARDLESS so callers compile; when ZK is off the impl returns
 * BNS_EUNSUPPORTED.
 *
 * FIELD-EXACTNESS PINS (module notes — must match scrypt-ts-lib field-for-field):
 *  - G1 decode reads ONLY indices [0],[1] (the '1' z is ignored); G2 decode keeps
 *    snarkjs natural coeff order c0,c1 (FQ2={x:c0,y:c1}) — do NOT pre-swap
 *    (createTwistPoint does the go-ethereum swap later).
 *  - vkFromSnarkjs gate: protocol=="groth16" && curve in {bn128,bn254} &&
 *    nPublic==1 && IC.length==2; precompute millerb1a1 = miller(beta2, alpha1)
 *    WITHOUT final exp.
 *  - verify equation order: negate only A.y; acc=miller(b,negA);
 *    acc*=millerb1a1; acc*=miller(gamma, vk_x); acc*=miller(delta, C);
 *    return fq12Eq(finalExp(acc), FQ12One). FQ12One identity lives in y.z.y=1.
 *  - Base field P (Fp) != scalar field r (Mimc7). N==1.
 */
#ifndef BONSAI_ZK_G16_H
#define BONSAI_ZK_G16_H

#include <stddef.h>
#include <stdbool.h>
#include "common/error.h"
#include "crypto/bignum.h"     /* bn_t for Fp base-field elements */

/* Number of public inputs the G16BN256 verifier is hardcoded for. TS: G16BN256.N. */
#define BONSAI_G16_N 1

/* ---- tower-field element types (owned bn_t leaves over Fp) -------------- */
/* The Fp2/Fp6/Fp12 tower mirrors scrypt-ts-lib's representation. Each leaf is an
 * owned bn_t (release via the matching *_free). TS: FQ2/FQ6/FQ12 / G1Point /
 * G2Point structs in scrypt-ts-lib/dist/ec/bn256. */

/* FQ2 = { x:c0, y:c1 } over Fp (snarkjs natural coeff order). */
typedef struct { bn_t *x; bn_t *y; } fq2_t;

/* FQ6 = { x, y, z } over FQ2. */
typedef struct { fq2_t x; fq2_t y; fq2_t z; } fq6_t;

/* FQ12 = { x, y } over FQ6. */
typedef struct { fq6_t x; fq6_t y; } fq12_t;

/* G1 affine point over Fp. */
typedef struct { bn_t *x; bn_t *y; } g1_point_t;

/* G2 affine point over FQ2. */
typedef struct { fq2_t x; fq2_t y; } g2_point_t;

/* Groth16 proof: a:G1, b:G2, c:G1. TS: scrypt-ts-lib Proof. */
typedef struct {
    g1_point_t a;
    g2_point_t b;
    g1_point_t c;
} g16_proof_t;

/* Groth16 verifying key: precomputed millerb1a1 (FQ12) + gamma/delta (G2) +
 * gammaAbc[2] (G1). TS: scrypt-ts-lib VerifyingKey.
 *
 * The trailing `alpha`/`beta` leaves are OFF-CHAIN-ONLY auxiliaries: the original
 * snarkjs vk_alpha_1 / vk_beta_2 that the on-chain VerifyingKey collapses into
 * millerb1a1 = miller(beta2, alpha1). They are NOT part of the on-chain struct
 * flatten (which is exactly {millerb1a1, gamma, delta, gammaAbc} — see
 * src/contracts/zk_hidden_limit.c) and are APPENDED at the end so that prefix
 * layout is byte-for-byte unchanged. They exist solely so verify_proof_off_chain
 * can re-serialize a COMPLETE snarkjs verification_key.json for the toolchain
 * shell-out (snarkjs `groth16 verify` consumes vk_alpha_1/vk_beta_2 directly). */
typedef struct {
    fq12_t     miller_b1a1;
    g2_point_t gamma;
    g2_point_t delta;
    g1_point_t gamma_abc[2]; /* [g1(IC[0]), g1(IC[1])] */
    g1_point_t alpha;        /* off-chain only: g1(vk_alpha_1)  */
    g2_point_t beta;         /* off-chain only: g2(vk_beta_2)   */
} g16_verifying_key_t;

/* ---- snarkjs wire structs (decimal-string field elements) --------------- */
/* Borrowed views over the parsed snarkjs JSON; the converters read decimal
 * strings via BigInt(base 10). TS: g16.ts::SnarkjsVKey / SnarkjsProof. */

/* snarkjs proof.json subset: pi_a=[x,y,'1']; pi_b=[[c0,c1],[c0,c1],['1','0']];
 * pi_c=[x,y,'1']. TS: g16.ts::SnarkjsProof. */
typedef struct {
    const char *pi_a[2];        /* [x, y]                         */
    const char *pi_b[2][2];     /* [[c0,c1],[c0,c1]]              */
    const char *pi_c[2];        /* [x, y]                         */
} snarkjs_proof_t;

/* snarkjs verification_key.json subset. vk_alpha_1=[x,y]; vk_*_2=[[c0,c1],[c0,c1]];
 * IC=[[x,y],[x,y]]. TS: g16.ts::SnarkjsVKey. */
typedef struct {
    const char *protocol;       /* must be "groth16"              */
    const char *curve;          /* "bn128" or "bn254"             */
    int         n_public;       /* must be 1                      */
    const char *vk_alpha_1[2];
    const char *vk_beta_2[2][2];
    const char *vk_gamma_2[2][2];
    const char *vk_delta_2[2][2];
    const char *ic[2][2];       /* IC, length 2                   */
} snarkjs_vkey_t;

/* ---- converters --------------------------------------------------------- */

/* Convert a snarkjs proof to the G16BN256 Proof struct (owned bn_t leaves;
 * release via g16_proof_free). TS: g16.ts::proofFromSnarkjs.
 * BNS_OK / BNS_EPARSE (bad decimal) / BNS_ENOMEM / BNS_EUNSUPPORTED (ZK off). */
int proof_from_snarkjs(const snarkjs_proof_t *p, g16_proof_t *out);

/* Convert a snarkjs vkey to the G16BN256 VerifyingKey, precomputing
 * millerb1a1 = miller(beta2, alpha1). Rejects unless protocol=="groth16",
 * curve in {bn128,bn254}, nPublic==1, IC.length==2. Owned leaves; release via
 * g16_verifying_key_free. TS: g16.ts::vkFromSnarkjs.
 * BNS_OK / BNS_EINVAL (gate fail) / BNS_EPARSE / BNS_ENOMEM / BNS_EUNSUPPORTED. */
int vk_from_snarkjs(const snarkjs_vkey_t *vk, g16_verifying_key_t *out);

/* ---- off-chain verify --------------------------------------------------- */

/* verifyProofOffChain: the Groth16 pairing check
 *   e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta) == 1
 * over BN254. The heavy pairing is NOT hand-ported; with BONSAI_ENABLE_ZK this
 * serializes the in-memory `proof`, `vk` and the length-N (==1) `inputs` vector
 * back into snarkjs JSON in a private temp dir and SHELLS OUT to
 * `npx snarkjs groth16 verify` (mirroring src/zk/prover.c), setting *out_ok iff
 * snarkjs reports OK. `inputs` is the public-signal vector. Fail-closed: *out_ok
 * is never set true on any error or ambiguous toolchain output.
 * TS: g16.ts::verifyProofOffChain.
 * BNS_OK (verdict in *out_ok) / BNS_EUNSUPPORTED (ZK compiled out or toolchain
 * absent) / BNS_EINVAL (NULL arg) / BNS_EPARSE / BNS_EPERSIST (temp-file I/O) /
 * BNS_ENET / BNS_ECRYPTO (spawn or inconclusive verdict) / BNS_ENOMEM. */
int verify_proof_off_chain(const bn_t *const inputs[BONSAI_G16_N],
                           const g16_proof_t *proof,
                           const g16_verifying_key_t *vk, bool *out_ok);

/* File-path variant of the off-chain verify: shells out to
 * `npx snarkjs groth16 verify <vkey_path> <public_path> <proof_path>` against
 * EXISTING snarkjs JSON files (e.g. those zk_prove() / zk_build_artifacts()
 * already emit) and sets *out_ok iff snarkjs reports OK. This is the directly
 * reachable "supported files path"; verify_proof_off_chain() serializes its
 * in-memory structs to a temp dir and delegates to the same engine. Fail-closed.
 * BNS_OK (verdict in *out_ok) / BNS_EUNSUPPORTED (ZK off or toolchain absent) /
 * BNS_EINVAL (NULL arg) / BNS_ENET / BNS_ECRYPTO (spawn/inconclusive verdict). */
int verify_proof_off_chain_files(const char *vkey_path, const char *public_path,
                                 const char *proof_path, bool *out_ok);

/* ---- lifecycle ---------------------------------------------------------- */

/* Release the owned bn_t leaves of a proof / verifying key (NULL-safe). */
void g16_proof_free(g16_proof_t *p);
void g16_verifying_key_free(g16_verifying_key_t *vk);

#endif /* BONSAI_ZK_G16_H */
