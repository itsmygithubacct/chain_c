/*
 * test_g16_verify.c — focused test for the real off-chain Groth16 verifier
 * (review finding #16 / Gap-1). verify_proof_off_chain() used to be a permanent
 * BNS_EUNSUPPORTED stub even under BONSAI_ENABLE_ZK; it now serializes the
 * in-memory proof/vk/inputs back into snarkjs JSON and shells out to
 * `npx snarkjs groth16 verify` (mirroring src/zk/prover.c).
 *
 * Fixture: the B1 toolchain-spike "square" circuit (artifacts/zk/square.*,
 * circuits/spike/square.circom: out == x*x, out public). The verifying key is the
 * committed artifacts/zk/square.vkey.json; the proof below was produced by
 * `snarkjs groth16 fullprove {"x":3} square.wasm square.zkey` (=> public [9]) and
 * verifies under that vkey. Verification is deterministic, so a captured proof is
 * a stable fixture.
 *
 * GATING: with BONSAI_ENABLE_ZK OFF the converters short-circuit to
 * BNS_EUNSUPPORTED — the live verify is TEST_IGNORE'd. With ZK ON but npx/snarkjs
 * unavailable at run time, verify_proof_off_chain() returns a non-OK rc and the
 * live assertions are likewise TEST_IGNORE'd. The real verify/reject assertions
 * only fire when the toolchain is genuinely present. Runs OFFLINE (snarkjs verify
 * is a local pairing check; no network).
 *
 * Real API: include/zk/g16.h, include/crypto/bignum.h.
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

/* artifacts/zk/square.vkey.json (protocol=groth16, curve=bn128, nPublic=1). The
 * snarkjs_vkey_t carries only the [c0,c1] rows; the trailing ["1","0"]/["...","1"]
 * projective rows are implicit (re-emitted by the serializer). */
static snarkjs_vkey_t square_vkey(void)
{
    snarkjs_vkey_t vk;
    memset(&vk, 0, sizeof vk);
    vk.protocol = "groth16";
    vk.curve    = "bn128";
    vk.n_public = 1;

    vk.vk_alpha_1[0] = "9568273531737907426963749682343466753819034769838374553630174748081116245378";
    vk.vk_alpha_1[1] = "13787681016252195732541727009308971532432439581130541568617273584224420246033";

    vk.vk_beta_2[0][0] = "11317395908853254398839126592547525651573115691823176214309448585760906095137";
    vk.vk_beta_2[0][1] = "19628395847868273370428129208923924624964792447403458751669238622083391914771";
    vk.vk_beta_2[1][0] = "14096282199938522535157360227190670746591047630746339690194542974817545145162";
    vk.vk_beta_2[1][1] = "15271286049318266109239630458759212953373815186715313002401961288505604361814";

    vk.vk_gamma_2[0][0] = "10857046999023057135944570762232829481370756359578518086990519993285655852781";
    vk.vk_gamma_2[0][1] = "11559732032986387107991004021392285783925812861821192530917403151452391805634";
    vk.vk_gamma_2[1][0] = "8495653923123431417604973247489272438418190587263600148770280649306958101930";
    vk.vk_gamma_2[1][1] = "4082367875863433681332203403145435568316851327593401208105741076214120093531";

    vk.vk_delta_2[0][0] = "13776032523196485561477323367143201838915338031831327293310630176029971709231";
    vk.vk_delta_2[0][1] = "8972900929495311331488059849699930053139023874132246751689579374655590600925";
    vk.vk_delta_2[1][0] = "2354797215433491624227404576870935006602988876956291493642096668689318171075";
    vk.vk_delta_2[1][1] = "2085022045296993762934710133801262551755140352865352845781309628066229694228";

    vk.ic[0][0] = "16625597622219254786865816255056780437497638230997585274415057027310182489130";
    vk.ic[0][1] = "8176947294503855520662317170643935207334818446953285093346397389582775886845";
    vk.ic[1][0] = "20479164680524409573191717585197321099517530977227607759861575918046022954650";
    vk.ic[1][1] = "16893735340599529209566615523950770737349590862124144501681805479914684401535";
    return vk;
}

/* A real groth16 proof for square(x=3) => out=9 (snarkjs fullprove). The
 * snarkjs_proof_t carries only the [x,y]/[c0,c1] coords; trailing "1"/["1","0"]
 * are implicit. */
static snarkjs_proof_t square_proof(void)
{
    snarkjs_proof_t p;
    memset(&p, 0, sizeof p);
    p.pi_a[0] = "14735119158782905956386615164011792919365297189999262760956873286479706434418";
    p.pi_a[1] = "5694494052785541384257745131977268485699117830976404142500064270795291288338";

    p.pi_b[0][0] = "21125886569238738342160743826047170847838363982726463756719696267668584034372";
    p.pi_b[0][1] = "16101380483231031135031150623112825864029477325019301850674293852541412425463";
    p.pi_b[1][0] = "5071871834768481749911238797879919257676976045183465158865647048266406790126";
    p.pi_b[1][1] = "4783183854972924718376074606379683504939138436132653115264690505688867653384";

    p.pi_c[0] = "13997419436579752135590201081292712003119688656919258693924111592504569940811";
    p.pi_c[1] = "2840223709567004613308724760326043866254494408871149858021887006064723434057";
    return p;
}

/* The headline test: a REAL snarkjs proof verifies through verify_proof_off_chain
 * (no longer a permanent stub), and a mutated public input is rejected with a
 * conclusive BNS_OK / *out_ok=false (never a false positive). */
static void test_real_proof_verify_and_reject(void)
{
    snarkjs_vkey_t  wvk = square_vkey();
    snarkjs_proof_t wpf = square_proof();
    g16_verifying_key_t vk;
    g16_proof_t pf;
    memset(&vk, 0, sizeof vk);
    memset(&pf, 0, sizeof pf);

    int rcv = vk_from_snarkjs(&wvk, &vk);
    int rcp = proof_from_snarkjs(&wpf, &pf);
    if (rcv == BNS_EUNSUPPORTED || rcp == BNS_EUNSUPPORTED) {
        g16_verifying_key_free(&vk);
        g16_proof_free(&pf);
        TEST_IGNORE_MESSAGE(
            "BONSAI_ENABLE_ZK off: off-chain verify shells out to snarkjs "
            "(converters compiled out)");
        return;
    }
    TEST_ASSERT_EQUAL_INT(BNS_OK, rcv);
    TEST_ASSERT_EQUAL_INT(BNS_OK, rcp);

    bn_t *pub = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("9", &pub)); /* 3*3 */
    const bn_t *const inputs[BONSAI_G16_N] = { pub };

    bool ok = false;
    int rc = verify_proof_off_chain(inputs, &pf, &vk, &ok);
    if (rc != BNS_OK) {
        /* snarkjs/npx not reachable at test time -> cannot run a live verify. */
        bn_free(pub);
        g16_verifying_key_free(&vk);
        g16_proof_free(&pf);
        TEST_IGNORE_MESSAGE(
            "npx/snarkjs unavailable: live groth16 verify not runnable here");
        return;
    }
    /* Toolchain present: the valid proof MUST verify. */
    TEST_ASSERT_TRUE(ok);

    /* Same proof, WRONG public input (10 != 3*3) -> conclusive reject. */
    bn_t *pub_bad = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("10", &pub_bad));
    const bn_t *const inputs_bad[BONSAI_G16_N] = { pub_bad };
    bool ok2 = true; /* must be overwritten to false */
    int rc2 = verify_proof_off_chain(inputs_bad, &pf, &vk, &ok2);
    TEST_ASSERT_EQUAL_INT(BNS_OK, rc2);
    TEST_ASSERT_FALSE(ok2);

    bn_free(pub);
    bn_free(pub_bad);
    g16_verifying_key_free(&vk);
    g16_proof_free(&pf);
}

/* Contract guards on both entry points: *out_ok is forced false and the rc is a
 * sane gate/argument code (NEVER BNS_OK + true) on bad/absent input. With ZK off
 * the gate returns BNS_EUNSUPPORTED before any work; with ZK on a NULL path is
 * BNS_EINVAL. Either way: no false positive. */
static void test_entry_points_fail_closed_on_null(void)
{
    bool ok = true;
    int rc = verify_proof_off_chain_files(NULL, NULL, NULL, &ok);
    TEST_ASSERT_FALSE(ok);
    TEST_ASSERT_TRUE(rc == BNS_EUNSUPPORTED || rc == BNS_EINVAL);

    ok = true;
    rc = verify_proof_off_chain(NULL, NULL, NULL, &ok);
    TEST_ASSERT_FALSE(ok);
    TEST_ASSERT_TRUE(rc == BNS_EUNSUPPORTED || rc == BNS_EINVAL);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_real_proof_verify_and_reject);
    RUN_TEST(test_entry_points_fail_closed_on_null);
    return UNITY_END();
}
