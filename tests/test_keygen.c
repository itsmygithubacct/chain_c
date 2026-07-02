/*
 * test_keygen.c — Unity tests for wallet_generate_key (wallet/keygen.h).
 *
 * OFFLINE / deterministic in structure (the key itself is random): asserts the
 * generated WIF round-trips to the same address, is a compressed mainnet key,
 * looks like a P2PKH '1...' address, and that two generations differ.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

#include "unity.h"
#include "wallet/keygen.h"
#include "scripts/keygen.h"
#include "bsv/address.h"
#include "crypto/ecdsa.h"

void setUp(void) {}
void tearDown(void) {}

/* The WIF must decode to a compressed mainnet secret, and re-deriving the
 * address from that secret must reproduce the returned address. */
static void test_keygen_wif_roundtrips_to_address(void)
{
    char *wif = NULL, *addr = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, wallet_generate_key(BSV_MAINNET, &wif, &addr));
    TEST_ASSERT_NOT_NULL(wif);
    TEST_ASSERT_NOT_NULL(addr);
    TEST_ASSERT_EQUAL_CHAR('1', addr[0]); /* mainnet P2PKH */

    uint8_t secret[BONSAI_ECDSA_SECKEY_LEN];
    bool compressed = false;
    bsv_network_t net = BSV_TESTNET;
    TEST_ASSERT_EQUAL_INT(BNS_OK, wif_decode(wif, secret, &compressed, &net));
    TEST_ASSERT_TRUE(compressed);
    TEST_ASSERT_EQUAL_INT(BSV_MAINNET, net);

    ecdsa_key_t *key = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, ecdsa_key_from_bytes(secret, &key));
    ecdsa_pubkey_t *pub = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, ecdsa_key_derive_pubkey(key, &pub));
    char *rederived = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, address_from_pubkey(pub, BSV_MAINNET, &rederived));
    TEST_ASSERT_EQUAL_STRING(addr, rederived);

    ecdsa_pubkey_free(pub);
    ecdsa_key_free(key);
    free(rederived);
    free(wif);
    free(addr);
}

/* Two generations must produce different keys (sanity check on randomness). */
static void test_keygen_is_random(void)
{
    char *w1 = NULL, *a1 = NULL, *w2 = NULL, *a2 = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, wallet_generate_key(BSV_MAINNET, &w1, &a1));
    TEST_ASSERT_EQUAL_INT(BNS_OK, wallet_generate_key(BSV_MAINNET, &w2, &a2));
    TEST_ASSERT_TRUE(strcmp(w1, w2) != 0);
    TEST_ASSERT_TRUE(strcmp(a1, a2) != 0);
    free(w1); free(a1); free(w2); free(a2);
}

/* NULL out-params are rejected. */
static void test_keygen_rejects_null(void)
{
    char *wif = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, wallet_generate_key(BSV_MAINNET, NULL, NULL));
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, wallet_generate_key(BSV_MAINNET, &wif, NULL));
}

/* keygen CLI writes a 0600 {"wif","address"} file and REFUSES to overwrite an
 * existing one (atomic no-clobber). Exercises write_key_file's link()-based path. */
static void test_keygen_cli_writes_0600_and_refuses_overwrite(void)
{
    /* Reserve a unique name, then remove it so keygen can create it fresh. */
    char path[] = "/tmp/chain_c_keygen_testXXXXXX";
    int tfd = mkstemp(path);
    TEST_ASSERT_TRUE(tfd >= 0);
    close(tfd);
    TEST_ASSERT_EQUAL_INT(0, unlink(path));

    char *argv[] = { "keygen", path, NULL };
    int ec = -1;
    TEST_ASSERT_EQUAL_INT(BNS_OK, keygen_run(2, argv, &ec));
    TEST_ASSERT_EQUAL_INT(0, ec);

    /* File exists, is a regular file, and is 0600 (no group/other bits). */
    struct stat st;
    TEST_ASSERT_EQUAL_INT(0, stat(path, &st));
    TEST_ASSERT_TRUE(S_ISREG(st.st_mode));
    TEST_ASSERT_EQUAL_INT(0, st.st_mode & (S_IRWXG | S_IRWXO));

    /* Content parses as our JSON and carries a mainnet WIF + '1...' address. */
    FILE *f = fopen(path, "r");
    TEST_ASSERT_NOT_NULL(f);
    char buf[512] = {0};
    size_t got = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    TEST_ASSERT_TRUE(got > 0);
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"wif\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"address\": \"1"));

    /* Second run against the same path must REFUSE (exit 1) and leave it intact. */
    off_t size_before = st.st_size;
    int ec2 = -1;
    TEST_ASSERT_EQUAL_INT(BNS_OK, keygen_run(2, argv, &ec2));
    TEST_ASSERT_EQUAL_INT(1, ec2);
    TEST_ASSERT_EQUAL_INT(0, stat(path, &st));
    TEST_ASSERT_EQUAL_INT((int)size_before, (int)st.st_size);  /* unchanged */

    unlink(path);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_keygen_wif_roundtrips_to_address);
    RUN_TEST(test_keygen_is_random);
    RUN_TEST(test_keygen_rejects_null);
    RUN_TEST(test_keygen_cli_writes_0600_and_refuses_overwrite);
    return UNITY_END();
}
