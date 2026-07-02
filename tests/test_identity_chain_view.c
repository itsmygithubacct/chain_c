/*
 * test_identity_chain_view.c — Unity port of
 * chain/tests/priscilla/identityChainView.test.ts.
 *
 * Pins the PRODUCTION on-chain read behind KeyBroker.issueFromChain /
 * verifyRicardian: ChainSourceIdentityView.getIdentityScriptHex parses the
 * genesis tx and returns the locking-script BODY hex of the requested output
 * index (no off-by-one), errors clearly when the requested output is absent, and
 * propagates a chain-read failure so verify-on-read can fail closed.
 *
 * The TS builds a 2-output genesis tx (output0 = OP_TRUE '51', output1 = a
 * distinct P2PKH). We build the same shape with the fixtures helper
 * (output0 = '51', output1 = OP_RETURN <receipt>), register it on the shared
 * mock chain source, and drive the real ChainSourceIdentityView.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "unity.h"
#include "common/error.h"
#include "reputation_indexer.h"
#include "broker/identity_chain_view.h"
#include "mock_chain_source.h"
#include "fixtures.h"

/* TS: const GENESIS = 'a'.repeat(64) */
#define GENESIS FIX_TXID_A
/* a 32-byte receipt hex (the OP_RETURN payload at output 1) */
#define RECEIPT32 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

/* The identity locking-script body at output 0 is OP_1 == 0x51. */
#define IDENTITY_SCRIPT_HEX "51"

/* The chain_source_t vtable is BORROWED by ChainSourceIdentityView (the impl
 * stores a pointer to it), so it must outlive the view. We keep the mock + its
 * vtable at file scope, built once in setUp(), to satisfy that lifetime. */
static mock_chain_source_t        *g_mock;
static chain_source_t              g_src;
static chain_source_identity_view_t *g_csv;
static identity_chain_view_t        g_view;

void setUp(void)
{
    g_mock = mock_chain_source_new(0);
    TEST_ASSERT_NOT_NULL(g_mock);
    /* output0 = '51' (identity), output1 = OP_RETURN <receipt> (a distinct script) */
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_add_state_tx(g_mock, GENESIS, RECEIPT32));

    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_chain_source_as_source(g_mock, &g_src));
    TEST_ASSERT_EQUAL_INT(BNS_OK, chain_source_identity_view_new(&g_src, &g_csv));
    TEST_ASSERT_EQUAL_INT(BNS_OK, chain_source_identity_view_as_view(g_csv, &g_view));
}

void tearDown(void)
{
    chain_source_identity_view_free(g_csv); g_csv = NULL;
    mock_chain_source_free(g_mock); g_mock = NULL;
}

/* TS: 'returns the locking-script hex of the requested output index (no off-by-one)' */
static void test_returns_script_of_requested_index(void)
{
    char *hex0 = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        g_view.get_identity_script_hex(g_view.ctx, GENESIS, 0, &hex0));
    TEST_ASSERT_EQUAL_STRING(IDENTITY_SCRIPT_HEX, hex0);

    char *hex1 = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        g_view.get_identity_script_hex(g_view.ctx, GENESIS, 1, &hex1));
    /* output 1 is a DIFFERENT script — the index is honoured (no off-by-one). */
    TEST_ASSERT_NOT_NULL(hex1);
    TEST_ASSERT_NOT_EQUAL(0, strcmp(hex0, hex1));
    /* it is the OP_RETURN body carrying the receipt (6a20 <32-byte receipt>). */
    TEST_ASSERT_NOT_NULL(strstr(hex1, RECEIPT32));

    free(hex0); free(hex1);
}

/* TS: 'throws a clear error when the requested output does not exist' (/no output 5/).
 * The C surface reports a missing output as BNS_ENOTFOUND. */
static void test_missing_output_errors(void)
{
    char *hex = (char *)0x1;
    int rc = g_view.get_identity_script_hex(g_view.ctx, GENESIS, 5, &hex);
    TEST_ASSERT_EQUAL_INT(BNS_ENOTFOUND, rc);
    TEST_ASSERT_NULL(hex); /* must not leave a dangling/garbage pointer */
}

/* TS: 'propagates a chain-read failure (so verify-on-read can fail closed)'
 * (/unknown tx/). The mock returns BNS_ENOTFOUND for an unregistered txid. */
static void test_propagates_unknown_tx(void)
{
    char *hex = (char *)0x1;
    int rc = g_view.get_identity_script_hex(g_view.ctx, FIX_TXID_B, 0, &hex);
    TEST_ASSERT_NOT_EQUAL(BNS_OK, rc);  /* error propagated, not swallowed */
    TEST_ASSERT_NULL(hex);
}

/* Bonus (verifyIdentityScriptOnChain is the fail-closed wrapper documented in
 * the same module): an expected-script byte-match is accepted (case-insensitive)
 * and a mismatch is rejected fail-closed with the verbatim mismatch reason. */
static void test_verify_on_read_match_and_mismatch(void)
{
    bool ok = false; char reason[256];
    /* matching (expected supplied UPPERCASE to exercise the case fold) */
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        verify_identity_script_on_chain(&g_view, GENESIS, 0, "51", &ok,
                                        reason, sizeof(reason)));
    TEST_ASSERT_TRUE(ok);

    /* mismatch fails closed with the verbatim reason */
    ok = true;
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        verify_identity_script_on_chain(&g_view, GENESIS, 0, "76a90088ac", &ok,
                                        reason, sizeof(reason)));
    TEST_ASSERT_FALSE(ok);
    TEST_ASSERT_EQUAL_STRING(BONSAI_IDVIEW_REASON_MISMATCH, reason);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_returns_script_of_requested_index);
    RUN_TEST(test_missing_output_errors);
    RUN_TEST(test_propagates_unknown_tx);
    RUN_TEST(test_verify_on_read_match_and_mismatch);
    return UNITY_END();
}
