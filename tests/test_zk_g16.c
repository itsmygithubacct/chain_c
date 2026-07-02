/*
 * test_zk_g16.c — Unity port of
 *   chain/tests/priscilla/zkG16.test.ts
 *
 * The Groth16 off-chain bridge (vkFromSnarkjs / proofFromSnarkjs /
 * verifyProofOffChain) is gated behind BONSAI_ENABLE_ZK, which is OFF by
 * default in this build (verified: build/libbonsai_chain.a carries NO bn256 /
 * miller symbols). Per cluster guidance, with ZK compiled out we assert the
 * BNS_EUNSUPPORTED contract for every entry point and TEST_IGNORE the
 * live-proof verify/reject assertions (they need real snarkjs proofs + the
 * BN254 pairing tower, neither present here).
 *
 * The TS pins these behaviors (mirrored below as the gate / ignore split):
 *  - a snarkjs proof verifies under the scrypt equation       -> live (IGNORE)
 *  - rejects the same proof against a mutated public input     -> live (IGNORE)
 *  - vkFromSnarkjs rejects an incompatible vkey LOUDLY         -> gate (see note)
 *  - circomlib/scrypt MiMC7 agree (withinLimit public output)  -> live (IGNORE)
 *  - proves/verifies cost <= secret limit                      -> live (IGNORE)
 *  - amount/commitment/vkey binding negatives                  -> live (IGNORE)
 *
 * Real API: include/zk/g16.h, include/crypto/bignum.h.
 *
 * Filename contains 'zk' -> CTest label `zk` (gated path). Runs OFFLINE.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdbool.h>
#include <string.h>

#include "unity.h"
#include "common/error.h"
#include "crypto/bignum.h"
#include "zk/g16.h"

void setUp(void) {}
void tearDown(void) {}

/* A structurally-valid snarkjs vkey: protocol/curve/nPublic in the accepted
 * envelope and well-formed decimal field elements. With ZK ON this would pass
 * the gate; with ZK OFF the converter short-circuits to BNS_EUNSUPPORTED before
 * ever inspecting the gate. Values are representative (the square circuit shape).
 */
static snarkjs_vkey_t valid_vkey(void)
{
    snarkjs_vkey_t vk;
    memset(&vk, 0, sizeof vk);
    vk.protocol = "groth16";
    vk.curve    = "bn128";
    vk.n_public = 1;
    vk.vk_alpha_1[0] = "1";  vk.vk_alpha_1[1] = "2";
    vk.vk_beta_2[0][0] = "1"; vk.vk_beta_2[0][1] = "2";
    vk.vk_beta_2[1][0] = "3"; vk.vk_beta_2[1][1] = "4";
    vk.vk_gamma_2[0][0] = "1"; vk.vk_gamma_2[0][1] = "2";
    vk.vk_gamma_2[1][0] = "3"; vk.vk_gamma_2[1][1] = "4";
    vk.vk_delta_2[0][0] = "1"; vk.vk_delta_2[0][1] = "2";
    vk.vk_delta_2[1][0] = "3"; vk.vk_delta_2[1][1] = "4";
    vk.ic[0][0] = "5"; vk.ic[0][1] = "6";
    vk.ic[1][0] = "7"; vk.ic[1][1] = "8";
    return vk;
}

static snarkjs_proof_t valid_proof(void)
{
    snarkjs_proof_t p;
    memset(&p, 0, sizeof p);
    p.pi_a[0] = "1"; p.pi_a[1] = "2";
    p.pi_b[0][0] = "1"; p.pi_b[0][1] = "2";
    p.pi_b[1][0] = "3"; p.pi_b[1][1] = "4";
    p.pi_c[0] = "5"; p.pi_c[1] = "6";
    return p;
}

/* vkFromSnarkjs on a well-formed vkey: with ZK off -> BNS_EUNSUPPORTED.
 * (TS: `expect(() => vkFromSnarkjs(vkey)).to.not.throw()` — the real one is fine.
 *  The C reproduction reports the feature is compiled out instead.) */
static void test_vk_from_snarkjs_unsupported_when_zk_off(void)
{
    snarkjs_vkey_t vk = valid_vkey();
    g16_verifying_key_t out;
    memset(&out, 0, sizeof out);

    int rc = vk_from_snarkjs(&vk, &out);
    TEST_ASSERT_EQUAL_INT(BNS_EUNSUPPORTED, rc);

    g16_verifying_key_free(&out); /* NULL-safe; out never populated */
}

/* proofFromSnarkjs on a well-formed proof: with ZK off -> BNS_EUNSUPPORTED. */
static void test_proof_from_snarkjs_unsupported_when_zk_off(void)
{
    snarkjs_proof_t p = valid_proof();
    g16_proof_t out;
    memset(&out, 0, sizeof out);

    int rc = proof_from_snarkjs(&p, &out);
    TEST_ASSERT_EQUAL_INT(BNS_EUNSUPPORTED, rc);

    g16_proof_free(&out); /* NULL-safe */
}

/* verifyProofOffChain: with ZK off -> BNS_EUNSUPPORTED and *out_ok forced false
 * (it must NEVER report a false positive when the pairing is compiled out). */
static void test_verify_off_chain_unsupported_and_not_ok_when_zk_off(void)
{
    bn_t *input = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("49", &input)); /* 7*7 */
    const bn_t *const inputs[BONSAI_G16_N] = { input };

    g16_proof_t proof;
    g16_verifying_key_t vk;
    memset(&proof, 0, sizeof proof);
    memset(&vk, 0, sizeof vk);

    bool ok = true; /* must be overwritten to false */
    int rc = verify_proof_off_chain(inputs, &proof, &vk, &ok);
    TEST_ASSERT_EQUAL_INT(BNS_EUNSUPPORTED, rc);
    TEST_ASSERT_FALSE(ok);

    bn_free(input);
}

/* TS: 'a snarkjs proof verifies under the scrypt verification equation' (B1) and
 * 'rejects the same proof against a mutated public input' — both need a live
 * snarkjs proof + the BN254 pairing tower. */
static void test_b1_live_proof_verify_and_mutate(void)
{
    TEST_IGNORE_MESSAGE(
        "live Groth16 proof verify/reject needs BONSAI_ENABLE_ZK + snarkjs/BN254 "
        "pairing (compiled out in this build)");
}

/* TS: 'vkFromSnarkjs rejects an incompatible vkey LOUDLY (protocol/curve/nPublic)'.
 * With ZK off the converter returns BNS_EUNSUPPORTED before reaching the gate, so
 * the EINVAL-vs-OK discrimination the TS pins cannot be exercised here. */
static void test_vk_gate_discrimination_zk_off(void)
{
    TEST_IGNORE_MESSAGE(
        "vkFromSnarkjs protocol/curve/nPublic gate (EINVAL vs OK) only reachable "
        "with BONSAI_ENABLE_ZK; ZK off short-circuits to BNS_EUNSUPPORTED");
}

/* TS withinLimit B2 cluster: MiMC7 agreement on the public output, prove/verify
 * cost<=limit, and the amount/commitment/vkey binding negatives — all live. */
static void test_within_limit_b2_live(void)
{
    TEST_IGNORE_MESSAGE(
        "withinLimit prove/verify + binding negatives need BONSAI_ENABLE_ZK + "
        "snarkjs/BN254 pairing (compiled out in this build)");
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_vk_from_snarkjs_unsupported_when_zk_off);
    RUN_TEST(test_proof_from_snarkjs_unsupported_when_zk_off);
    RUN_TEST(test_verify_off_chain_unsupported_and_not_ok_when_zk_off);
    RUN_TEST(test_b1_live_proof_verify_and_mutate);
    RUN_TEST(test_vk_gate_discrimination_zk_off);
    RUN_TEST(test_within_limit_b2_live);
    return UNITY_END();
}
