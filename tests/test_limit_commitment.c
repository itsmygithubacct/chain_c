/*
 * test_limit_commitment.c — Unity port of
 *   chain/tests/priscilla/limitCommitment.test.ts
 *
 * commitLimit (MiMC7) IS implemented in C, so this is asserted FULLY:
 *  - opens correctly: MiMC7(limit, salt) == commitment (recompute from the salt);
 *  - draws a valid, high-entropy field-element salt (salt < r and salt > 2^120);
 *  - hides: the same limit yields a different commitment each time (fresh salt);
 *  - rejects a negative limit (BNS_EINVAL).
 *
 * Plus a byte-exact golden pin from tests/golden/zk/mimc7.json:
 *   Mimc7.hash(1000, 42) == 100253785608061860744436590349275978948085785589
 *                           48732736767174265523349824461
 *   SNARK_SCALAR_FIELD     == the BN254 scalar field r.
 *
 * Real API: include/zk/limit_commitment.h, include/zk/mimc7.h,
 *           include/crypto/bignum.h.
 *
 * NB: this filename contains 'limit' but NOT 'zk' nor 'woc', so CTest labels it
 * `unit` (runs by default). The MiMC7 path needs no BONSAI_ENABLE_ZK.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "common/error.h"
#include "crypto/bignum.h"
#include "zk/limit_commitment.h"
#include "zk/mimc7.h"

/* Golden vectors captured from the TS chain (tests/golden/zk/mimc7.json). */
#define GOLDEN_MIMC7_LIMIT      "1000"
#define GOLDEN_MIMC7_SALT       "42"
#define GOLDEN_MIMC7_HASH_DEC \
    "10025378560806186074443659034927597894808578558948732736767174265523349824461"
#define SNARK_SCALAR_FIELD_DEC \
    "21888242871839275222246405745257275088548364400416034343698204186575808495617"

void setUp(void) {}
void tearDown(void) {}

/* helper: bn from decimal (asserts parse OK). */
static bn_t *bn_dec(const char *s)
{
    bn_t *b = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec(s, &b));
    TEST_ASSERT_NOT_NULL(b);
    return b;
}

/* it (golden): Mimc7.hash(1000, 42) matches the captured TS decimal exactly. */
static void test_mimc7_golden_vector(void)
{
    bn_t *x = bn_dec(GOLDEN_MIMC7_LIMIT);
    bn_t *k = bn_dec(GOLDEN_MIMC7_SALT);
    bn_t *out = NULL;

    TEST_ASSERT_EQUAL_INT(BNS_OK, mimc7_hash(x, k, &out));
    TEST_ASSERT_NOT_NULL(out);

    char *dec = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_to_dec(out, &dec));
    TEST_ASSERT_EQUAL_STRING(GOLDEN_MIMC7_HASH_DEC, dec);

    free(dec);
    bn_free(out);
    bn_free(k);
    bn_free(x);
}

/* it: Mimc7.SNARK_SCALAR_FIELD is the pinned BN254 scalar field r. */
static void test_mimc7_scalar_field_value(void)
{
    bn_t *r = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, mimc7_scalar_field(&r));
    TEST_ASSERT_NOT_NULL(r);

    char *dec = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_to_dec(r, &dec));
    TEST_ASSERT_EQUAL_STRING(SNARK_SCALAR_FIELD_DEC, dec);

    free(dec);
    bn_free(r);
}

/* it('opens correctly: MiMC7(limit, salt) === commitment') */
static void test_opens_correctly(void)
{
    bn_t *limit = bn_dec("100000");
    bn_t *commitment = NULL, *salt = NULL;

    TEST_ASSERT_EQUAL_INT(BNS_OK, commit_limit(limit, &commitment, &salt));
    TEST_ASSERT_NOT_NULL(commitment);
    TEST_ASSERT_NOT_NULL(salt);

    /* Recompute MiMC7(limit, salt) and require it equals the returned commitment. */
    bn_t *recomputed = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, mimc7_hash(limit, salt, &recomputed));
    TEST_ASSERT_EQUAL_INT(0, bn_cmp(recomputed, commitment));

    bn_free(recomputed);
    bn_free(salt);
    bn_free(commitment);
    bn_free(limit);
}

/* it('draws a valid, high-entropy field-element salt')
 *   salt < SNARK_SCALAR_FIELD   (valid field element)
 *   salt > 2^120                (~248-bit draw; below 2^120 has prob ~ 2^-128)
 */
static void test_salt_is_valid_high_entropy_field_element(void)
{
    bn_t *limit = bn_dec("100000");
    bn_t *commitment = NULL, *salt = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, commit_limit(limit, &commitment, &salt));

    bn_t *r = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, mimc7_scalar_field(&r));
    /* salt < r */
    TEST_ASSERT_TRUE(bn_cmp(salt, r) < 0);

    /* salt > 2^120 */
    bn_t *two_pow_120 = bn_dec("1329227995784915872903807060280344576"); /* 2^120 */
    TEST_ASSERT_TRUE(bn_cmp(salt, two_pow_120) > 0);

    bn_free(two_pow_120);
    bn_free(r);
    bn_free(salt);
    bn_free(commitment);
    bn_free(limit);
}

/* it('hides: same limit yields a different commitment each time (fresh salt)') */
static void test_hides_fresh_salt_each_time(void)
{
    bn_t *limit = bn_dec("100000");
    bn_t *c1 = NULL, *s1 = NULL, *c2 = NULL, *s2 = NULL;

    TEST_ASSERT_EQUAL_INT(BNS_OK, commit_limit(limit, &c1, &s1));
    TEST_ASSERT_EQUAL_INT(BNS_OK, commit_limit(limit, &c2, &s2));

    /* Fresh salt -> different salt and therefore a different commitment. */
    TEST_ASSERT_TRUE(bn_cmp(s1, s2) != 0);
    TEST_ASSERT_TRUE(bn_cmp(c1, c2) != 0);

    bn_free(s2); bn_free(c2);
    bn_free(s1); bn_free(c1);
    bn_free(limit);
}

/* it('rejects a negative limit') -> BNS_EINVAL ('limit must be non-negative'). */
static void test_rejects_negative_limit(void)
{
    bn_t *neg = bn_dec("-1");
    bn_t *commitment = NULL, *salt = NULL;

    int rc = commit_limit(neg, &commitment, &salt);
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, rc);
    TEST_ASSERT_NULL(commitment);
    TEST_ASSERT_NULL(salt);

    bn_free(neg);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_mimc7_golden_vector);
    RUN_TEST(test_mimc7_scalar_field_value);
    RUN_TEST(test_opens_correctly);
    RUN_TEST(test_salt_is_valid_high_entropy_field_element);
    RUN_TEST(test_hides_fresh_salt_each_time);
    RUN_TEST(test_rejects_negative_limit);
    return UNITY_END();
}
