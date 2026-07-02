/*
 * test_arp_attest.c — Unity port of chain/tests/priscilla/arpAttest.test.ts.
 *
 * Pins the ARP-1 sequenced-attestation message byte-identity between the
 * in-script builder (contracts_next/arp_attest.h::arp_attestation_msg, the C
 * analogue of ArpAttest.attestationMsg) and the off-chain signer's message
 * (verifier/rabin_attestor.h::attestation_msg_hex, the C analogue of
 * attestationMsgHex). Any drift silently breaks every quorum check and slash.
 *
 * Build+run (from chain_c/): see tests/CMakeLists.txt, or compile this file with
 * unity.c + tests/helpers against build/libbonsai_chain.a (secp256k1/crypto/curl).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "unity.h"

#include "common/error.h"
#include "common/bytes.h"
#include "common/hex.h"
#include "crypto/bignum.h"
#include "contracts_next/arp_attest.h"
#include "verifier/rabin_attestor.h"

void setUp(void) {}
void tearDown(void) {}

/* Build a bn_t from a uint64 via its decimal string. */
static bn_t *bn_from_u64(uint64_t v)
{
    char dec[32];
    snprintf(dec, sizeof(dec), "%" PRIu64, v);
    bn_t *n = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec(dec, &n));
    TEST_ASSERT_NOT_NULL(n);
    return n;
}

/* In-script attestationMsg(seq, digest) as a lowercase-hex string (owned). */
static char *in_script_msg_hex(uint64_t seq, const uint8_t digest[32])
{
    bn_t *bseq = bn_from_u64(seq);
    byte_buf_t buf;
    byte_buf_init(&buf);
    TEST_ASSERT_EQUAL_INT(BNS_OK, arp_attestation_msg(bseq, digest, &buf));
    TEST_ASSERT_EQUAL_size_t(BONSAI_ARP_ATTEST_MSG_LEN, buf.len); /* 54 bytes */
    char *hex = hex_encode(buf.data, buf.len);
    byte_buf_free(&buf);
    bn_free(bseq);
    TEST_ASSERT_NOT_NULL(hex);
    return hex;
}

/* TS: 'produces bytes identical to attestationMsgHex across the seq range'.
 * digestHex = 'ab'*32; seqs [0,1,7,255,256,2^32,2^40]. */
static void test_in_script_equals_off_chain_across_seq_range(void)
{
    const char *digest_hex =
        "abababababababababababababababababababababababababababababababab";
    uint8_t digest[32];
    TEST_ASSERT_EQUAL_INT(BNS_OK, hex_decode_fixed(digest_hex, digest, 32));

    const uint64_t seqs[] = {
        0, 1, 7, 255, 256,
        UINT64_C(1) << 32,   /* 2^32 */
        UINT64_C(1) << 40,   /* 2^40 */
    };

    for (size_t i = 0; i < sizeof(seqs) / sizeof(seqs[0]); i++) {
        char *in_script = in_script_msg_hex(seqs[i], digest);

        char *off_chain = NULL;
        TEST_ASSERT_EQUAL_INT(BNS_OK,
            attestation_msg_hex(seqs[i], digest_hex, &off_chain));
        TEST_ASSERT_NOT_NULL(off_chain);

        /* Both are already lowercase; assert byte-identity. */
        TEST_ASSERT_EQUAL_STRING(off_chain, in_script);

        free(off_chain);
        free(in_script);
    }
}

/* TS: 'has the documented shape: domain || seq(8 LE) || digest(32)'.
 * digestHex = 'cd'*32, seq=1. */
static void test_documented_shape(void)
{
    const char *digest_hex =
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    uint8_t digest[32];
    TEST_ASSERT_EQUAL_INT(BNS_OK, hex_decode_fixed(digest_hex, digest, 32));

    char *msg = in_script_msg_hex(1, digest); /* lowercase hex */

    /* starts with "ARP1_ATTEST_V1" domain tag */
    TEST_ASSERT_EQUAL_INT(0,
        strncmp(msg, BONSAI_ARP_ATTEST_TAG_HEX, strlen(BONSAI_ARP_ATTEST_TAG_HEX)));

    /* contains seq=1 as 8-byte little-endian */
    TEST_ASSERT_NOT_NULL(strstr(msg, "0100000000000000"));

    /* ends with the 32-byte digest */
    size_t mlen = strlen(msg);
    size_t dlen = strlen(digest_hex);
    TEST_ASSERT_TRUE(mlen >= dlen);
    TEST_ASSERT_EQUAL_INT(0, strcmp(msg + (mlen - dlen), digest_hex));

    /* and the exact length: 54 bytes => 108 hex chars */
    TEST_ASSERT_EQUAL_size_t(2 * BONSAI_ARP_ATTEST_MSG_LEN, mlen);

    free(msg);
}

/* TS: 'binds seq and digest distinctly'. A different seq OR digest yields a
 * different message. */
static void test_binds_seq_and_digest_distinctly(void)
{
    const char *d_hex =
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    const char *d2_hex =
        "cececececececececececececececececececececececececececececececece";
    uint8_t d[32], d2[32];
    TEST_ASSERT_EQUAL_INT(BNS_OK, hex_decode_fixed(d_hex, d, 32));
    TEST_ASSERT_EQUAL_INT(BNS_OK, hex_decode_fixed(d2_hex, d2, 32));

    char *m1_seq1 = in_script_msg_hex(1, d);
    char *m1_seq2 = in_script_msg_hex(2, d);
    char *m1_d2   = in_script_msg_hex(1, d2);

    /* different seq => different message */
    TEST_ASSERT_TRUE(strcmp(m1_seq1, m1_seq2) != 0);
    /* different digest => different message */
    TEST_ASSERT_TRUE(strcmp(m1_seq1, m1_d2) != 0);

    free(m1_seq1);
    free(m1_seq2);
    free(m1_d2);
}

/* Golden pin (tests/golden/golden.json::arpAttest): attestationMsg(seq=7,
 * digest=ef*32) == 415250315f4154544553545f5631 0700000000000000 ef*32.
 * Asserted for BOTH the in-script builder and the off-chain encoder. */
static void test_golden_vector_seq7_ef(void)
{
    const char *digest_hex =
        "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";
    const char *golden =
        "415250315f4154544553545f5631"  /* ARP1_ATTEST_V1 */
        "0700000000000000"              /* seq=7, 8-byte LE */
        "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";

    uint8_t digest[32];
    TEST_ASSERT_EQUAL_INT(BNS_OK, hex_decode_fixed(digest_hex, digest, 32));

    char *in_script = in_script_msg_hex(7, digest);
    TEST_ASSERT_EQUAL_STRING(golden, in_script);

    char *off_chain = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, attestation_msg_hex(7, digest_hex, &off_chain));
    TEST_ASSERT_EQUAL_STRING(golden, off_chain);

    free(in_script);
    free(off_chain);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_in_script_equals_off_chain_across_seq_range);
    RUN_TEST(test_documented_shape);
    RUN_TEST(test_binds_seq_and_digest_distinctly);
    RUN_TEST(test_golden_vector_seq7_ef);
    return UNITY_END();
}
