/*
 * test_zk_hidden_limit.c — Unity port of
 *   chain/tests/zkHiddenLimit.test.ts
 *
 * The in-script Groth16 verify (attest) is modelled off-chain by
 * zk_hidden_limit_attest_verify(), whose pairing path is gated behind
 * BONSAI_ENABLE_ZK (OFF in this build). Per cluster guidance:
 *  - the assertion-ORDER guarantee the TS pins ("rejects a non-positive amount
 *    BEFORE any pairing work") IS reproducible with ZK off and is asserted:
 *    amount<=0 returns BNS_EINVAL even though the pairing is compiled out;
 *  - a positive amount falls through to the compiled-out pairing and returns
 *    BNS_EUNSUPPORTED with *out_ok forced false (no false-positive unlock);
 *  - the live proof outcomes the TS pins (valid proof unlocks, cost==limit
 *    boundary, input/commitment/vkey binding rejections) are TEST_IGNORE'd —
 *    they need real snarkjs proofs + the BN254 pairing tower.
 *
 * Real API: include/contracts/zk_hidden_limit.h (g16_proof_t / g16_vk_t are
 * OPAQUE here), include/zk/limit_commitment.h, include/crypto/bignum.h.
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
#include "zk/limit_commitment.h"
#include "contracts/zk_hidden_limit.h"

/* TS fixture: LIMIT = 100_000, SALT = 12345678901234567890,
 *             commitment = Mimc7.hash(LIMIT, SALT). We instead build a real
 * commitment via commit_limit() (fresh salt) — its exact value is irrelevant to
 * the assertion-order / unsupported-path behavior we can pin with ZK off. */
static zk_hidden_limit_t g_zhl;

/* Borrowed, non-NULL placeholders for the artifact + vk handles. With ZK off the
 * impl never dereferences them past the NULL checks (the pairing is compiled out
 * before any use), so any non-NULL pointer satisfies the contract. */
static int g_dummy_artifact_storage;
static int g_dummy_vk_storage;

void setUp(void)
{
    bn_t *limit = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("100000", &limit));

    bn_t *commitment = NULL, *salt = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, commit_limit(limit, &commitment, &salt));
    bn_free(salt);
    bn_free(limit);

    memset(&g_zhl, 0, sizeof g_zhl);
    g_zhl.artifact         = (const scrypt_artifact_t *)&g_dummy_artifact_storage;
    g_zhl.vk               = (const g16_vk_t *)&g_dummy_vk_storage;
    g_zhl.limit_commitment = commitment; /* owned; freed in tearDown */
}

void tearDown(void)
{
    zk_hidden_limit_free(&g_zhl); /* frees limit_commitment, leaves borrowed ptrs */
}

/* A non-NULL opaque proof handle. With ZK off, attest_verify checks proof!=NULL
 * (else BNS_EINVAL) but never decodes it before the compiled-out pairing. */
static const g16_proof_t *dummy_proof(void)
{
    static int proof_storage;
    return (const g16_proof_t *)&proof_storage;
}

static bn_t *bn_dec(const char *s)
{
    bn_t *b = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec(s, &b));
    return b;
}

/* TS: 'rejects a non-positive amount before any pairing work' — amount == 0.
 * The assertion order (amount>0 checked FIRST) IS reproducible with ZK off:
 * EINVAL, NOT EUNSUPPORTED, proves the positivity check fires before the
 * compiled-out pairing. *out_ok must be false. */
static void test_rejects_zero_amount_before_pairing(void)
{
    bn_t *amount = bn_dec("0");
    bool ok = true;
    int rc = zk_hidden_limit_attest_verify(&g_zhl, amount, dummy_proof(), &ok);
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, rc);
    TEST_ASSERT_FALSE(ok);
    bn_free(amount);
}

/* Same ordering guarantee for a NEGATIVE amount (still EINVAL, not EUNSUPPORTED). */
static void test_rejects_negative_amount_before_pairing(void)
{
    bn_t *amount = bn_dec("-1");
    bool ok = true;
    int rc = zk_hidden_limit_attest_verify(&g_zhl, amount, dummy_proof(), &ok);
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, rc);
    TEST_ASSERT_FALSE(ok);
    bn_free(amount);
}

/* A positive amount passes the positivity gate and reaches the compiled-out
 * pairing: BNS_EUNSUPPORTED, *out_ok forced false (never a false unlock). This
 * is the ZK-off shadow of the TS 'a valid proof unlocks' / boundary cases. */
static void test_positive_amount_reaches_unsupported_pairing(void)
{
    bn_t *amount = bn_dec("40000");
    bool ok = true;
    int rc = zk_hidden_limit_attest_verify(&g_zhl, amount, dummy_proof(), &ok);
    TEST_ASSERT_EQUAL_INT(BNS_EUNSUPPORTED, rc);
    TEST_ASSERT_FALSE(ok);
    bn_free(amount);
}

/* NULL-argument contract: missing proof / amount / out_ok -> BNS_EINVAL. */
static void test_null_args_rejected(void)
{
    bn_t *amount = bn_dec("40000");
    bool ok = false;
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL,
        zk_hidden_limit_attest_verify(&g_zhl, amount, NULL, &ok));
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL,
        zk_hidden_limit_attest_verify(&g_zhl, NULL, dummy_proof(), &ok));
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL,
        zk_hidden_limit_attest_verify(&g_zhl, amount, dummy_proof(), NULL));
    bn_free(amount);
}

/* TS: 'a valid proof unlocks' + 'cost EXACTLY at the secret limit (inclusive)'.
 * Needs a live snarkjs proof verifying through the BN254 pairing. */
static void test_valid_proof_unlocks_live(void)
{
    TEST_IGNORE_MESSAGE(
        "valid-proof unlock + cost==limit boundary need BONSAI_ENABLE_ZK + "
        "snarkjs/BN254 pairing (compiled out in this build)");
}

/* TS: 'rejects the proof when presented with a DIFFERENT amount (input binding)'.
 * Distinguishing 'proof failed' from EUNSUPPORTED needs the live pairing. */
static void test_input_binding_reject_live(void)
{
    TEST_IGNORE_MESSAGE(
        "input-binding proof rejection (proof failed) needs BONSAI_ENABLE_ZK + "
        "snarkjs/BN254 pairing (compiled out in this build)");
}

/* TS: 'rejects a valid proof against the WRONG pinned commitment' and 'under the
 * WRONG verifying key (pinned circuit)'. Both need the live pairing. */
static void test_wrong_commitment_and_vkey_reject_live(void)
{
    TEST_IGNORE_MESSAGE(
        "wrong-commitment / wrong-vkey proof rejection needs BONSAI_ENABLE_ZK + "
        "snarkjs/BN254 pairing (compiled out in this build)");
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_rejects_zero_amount_before_pairing);
    RUN_TEST(test_rejects_negative_amount_before_pairing);
    RUN_TEST(test_positive_amount_reaches_unsupported_pairing);
    RUN_TEST(test_null_args_rejected);
    RUN_TEST(test_valid_proof_unlocks_live);
    RUN_TEST(test_input_binding_reject_live);
    RUN_TEST(test_wrong_commitment_and_vkey_reject_live);
    return UNITY_END();
}
