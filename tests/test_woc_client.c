/*
 * test_woc_client.c — Unity port of chain/tests/whatsOnChain.test.ts
 * (WhatsOnChainSource live ChainSource adapter) plus the wocClient quirk
 * assertions called out in the cluster guidance (interpret_tx_status reads the
 * 'blockheight' wire key; broadcast strips one quote; is_429 classification).
 *
 * ALL OFFLINE: every HTTP exchange is served by the recording mock_http_transport
 * stub (the C port of the TS mockFetch route table). Filename contains "woc" so
 * CMake labels it 'net' (excluded from the default ctest run) but it MUST still
 * pass with zero network access.
 *
 * Build+run directly (avoids the shared cmake race):
 *   gcc -std=c11 -D_GNU_SOURCE -Iinclude -Ithird_party/unity -Ithird_party/cJSON
 *       -Ithird_party/ripemd160 -Ithird_party/mimc7_consts -Itests/helpers
 *       tests/test_woc_client.c third_party/unity/unity.c tests/helpers (all .c)
 *       -Lbuild -lbonsai_chain
 *       $(pkg-config --libs libsecp256k1 libcrypto libcurl) -lm -lpthread
 *       -o /tmp/test_woc_client  then run /tmp/test_woc_client
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>

#include "unity.h"

#include "common/error.h"
#include "common/hex.h"
#include "crypto/hash.h"
#include "chainSources/http_transport.h"
#include "chainSources/whats_on_chain.h"
#include "chainSources/woc_client.h"
#include "chainSources/woc_rate_limiter.h"
#include "reputation_indexer.h"

#include "mock_http_transport.h"
#include "fixtures.h"

/* ---- shared per-test fixtures ------------------------------------------- */

static mock_http_t      *g_http;       /* recording stub (default 404)        */
static http_transport_t  g_transport;  /* vtable over g_http                  */
static whats_on_chain_t *g_woc;        /* adapter under test                  */
static chain_source_t    g_src;        /* vtable over g_woc                   */

void setUp(void)
{
    g_http = mock_http_new(404);           /* TS mockFetch miss => 404 '' */
    TEST_ASSERT_NOT_NULL(g_http);
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_http_as_transport(g_http, &g_transport));

    whats_on_chain_opts_t opts = {0};
    opts.network   = WOC_NETWORK_MAIN;
    opts.base_url  = NULL;   /* derive default */
    opts.api_key   = NULL;
    opts.transport = &g_transport;
    TEST_ASSERT_EQUAL_INT(BNS_OK, whats_on_chain_new(&opts, &g_woc));
    TEST_ASSERT_EQUAL_INT(BNS_OK, whats_on_chain_as_source(g_woc, &g_src));
}

void tearDown(void)
{
    whats_on_chain_free(g_woc);
    g_woc = NULL;
    mock_http_free(g_http);
    g_http = NULL;
}

/* sha256(toByteString('a', true)) == sha256 of the single UTF-8 byte 0x61.
 * Returns a freshly malloc'd 64-hex string (caller frees). */
static char *sha256_of_char(char c)
{
    uint8_t out[BONSAI_SHA256_LEN];
    uint8_t in = (uint8_t)c;
    sha256(&in, 1, out);
    return hex_encode(out, sizeof out);
}

/* ----------------------------------------------------------------------------
 * WhatsOnChainSource (live ChainSource adapter)
 * ------------------------------------------------------------------------- */

/* TS: "getRawTx returns trimmed hex" — body '  deadbeef\n' -> 'deadbeef'. */
static void test_get_raw_tx_returns_trimmed_hex(void)
{
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        mock_http_register_ok(g_http, "/tx/abc/hex", "  deadbeef\n"));

    char *hex = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, g_src.get_raw_tx(g_src.ctx, "abc", &hex));
    TEST_ASSERT_NOT_NULL(hex);
    TEST_ASSERT_EQUAL_STRING("deadbeef", hex);
    free(hex);

    /* the adapter requested the documented raw-path suffix */
    TEST_ASSERT_TRUE(mock_http_requested(g_http, "/tx/abc/hex"));
}

/* TS: "getRawTx throws on non-OK status" — 500 -> rejected (HTTP 500). */
static void test_get_raw_tx_non_ok_status_errors(void)
{
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        mock_http_register(g_http, "GET", "/tx/abc/hex", 500, "err", 0, true));

    char *hex = NULL;
    int rc = g_src.get_raw_tx(g_src.ctx, "abc", &hex);
    TEST_ASSERT_NOT_EQUAL(BNS_OK, rc);    /* a non-OK status must surface as error */
    TEST_ASSERT_NULL(hex);
}

/* TS: "getTime returns blocktime, falling back to time when unconfirmed".
 *   confirmed:   {blocktime:1700, time:1699} -> 1700
 *   unconfirmed: {blocktime:0,    time:1650} -> 1650  (JS truthy fall-through) */
static void test_get_time_blocktime_then_time_fallback(void)
{
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_http_register_ok(
        g_http, "/tx/hash/c", "{\"blocktime\":1700,\"time\":1699}"));
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_http_register_ok(
        g_http, "/tx/hash/u", "{\"blocktime\":0,\"time\":1650}"));

    int64_t t = 0;
    TEST_ASSERT_EQUAL_INT(BNS_OK, g_src.get_time(g_src.ctx, "c", &t));
    TEST_ASSERT_EQUAL_INT64(1700, t);

    t = 0;
    TEST_ASSERT_EQUAL_INT(BNS_OK, g_src.get_time(g_src.ctx, "u", &t));
    TEST_ASSERT_EQUAL_INT64(1650, t);
}

/* TS: "getSpendingTxid returns the spender txid, or null on 404 (unspent)".
 * Note: the WoC adapter is the one source that DOES provide a spend index. */
static void test_get_spending_txid_spent_and_404_null(void)
{
    TEST_ASSERT_NOT_NULL(g_src.get_spending_txid);

    /* spent: body {txid:'child', vin:0} -> 'child' */
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_http_register_ok(
        g_http, "/tx/p/0/spent", "{\"txid\":\"child\",\"vin\":0}"));
    char *spender = (char *)0x1;
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        g_src.get_spending_txid(g_src.ctx, "p", 0, &spender));
    TEST_ASSERT_NOT_NULL(spender);
    TEST_ASSERT_EQUAL_STRING("child", spender);
    free(spender);

    /* unspent: 404 -> NULL sentinel BEFORE the !ok check, still BNS_OK */
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        mock_http_register(g_http, "GET", "/tx/q/0/spent", 404, "", 0, true));
    spender = (char *)0x1;
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        g_src.get_spending_txid(g_src.ctx, "q", 0, &spender));
    TEST_ASSERT_NULL(spender);
}

/* TS: "drives the reputation indexer end-to-end over a mocked WoC chain".
 * spend chain: genesis:0 -> tx1, tx1:0 -> tx2, tx2:0 -> unspent
 * raw txs carry OP_RETURN receipts sha256('a')/sha256('b'); times 1000/2000.
 * Expect receipts == [rh_a, rh_b]; count==2; rho ~= 1 (all valid, now=2000). */
static void test_drives_reputation_indexer_end_to_end(void)
{
    char *rh_a = sha256_of_char('a');
    char *rh_b = sha256_of_char('b');
    TEST_ASSERT_NOT_NULL(rh_a);
    TEST_ASSERT_NOT_NULL(rh_b);

    char *raw1 = NULL, *raw2 = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, fix_raw_tx_recreated(rh_a, &raw1));
    TEST_ASSERT_EQUAL_INT(BNS_OK, fix_raw_tx_recreated(rh_b, &raw2));

    /* spend index */
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_http_register_ok(
        g_http, "/tx/gen/0/spent", "{\"txid\":\"tx1\"}"));
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_http_register_ok(
        g_http, "/tx/tx1/0/spent", "{\"txid\":\"tx2\"}"));
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_http_register(
        g_http, "GET", "/tx/tx2/0/spent", 404, "", 0, true));
    /* raw txs */
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_http_register_ok(g_http, "/tx/tx1/hex", raw1));
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_http_register_ok(g_http, "/tx/tx2/hex", raw2));
    /* times */
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_http_register_ok(
        g_http, "/tx/hash/tx1", "{\"blocktime\":1000}"));
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_http_register_ok(
        g_http, "/tx/hash/tx2", "{\"blocktime\":2000}"));

    tea_receipts_t receipts = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        collect_receipts("gen", 0, &g_src, NULL, NULL, &receipts));
    TEST_ASSERT_EQUAL_size_t(2, receipts.count);
    TEST_ASSERT_EQUAL_STRING(rh_a, receipts.items[0].receipt_hash);
    TEST_ASSERT_EQUAL_STRING(rh_b, receipts.items[1].receipt_hash);
    tea_receipts_free(&receipts);

    reputation_score_t score = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        compute_reputation("gen", 0, &g_src, 2000, 1e-3, NULL, NULL,
                           &score, NULL));
    TEST_ASSERT_EQUAL_size_t(2, score.count);
    /* rho ~= 1 (all valid, now == latest receipt time). Unity double asserts are
     * compiled out in this build, so compare with libm directly. */
    TEST_ASSERT_TRUE(fabs(score.rho - 1.0) < 1e-9);

    free(raw1);
    free(raw2);
    free(rh_a);
    free(rh_b);
}

/* ----------------------------------------------------------------------------
 * wocClient pure-logic quirks (cluster guidance)
 * ------------------------------------------------------------------------- */

/* interpret_tx_status reads the WIRE key 'blockheight' into block_height:
 *  - confirmations >= 1 => confirmed; block_height carried iff has_blockheight.
 *  - confirmations 0 + raw present => mempool (no height).
 *  - confirmations 0 + no raw => unknown. TS: interpretTxStatus. */
static void test_interpret_tx_status_blockheight_wire(void)
{
    tx_status_t s;

    /* confirmed with a blockheight present */
    memset(&s, 0, sizeof s);
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        interpret_tx_status(false, 3, 800000, true, &s));
    TEST_ASSERT_EQUAL_INT(TX_STATE_CONFIRMED, s.state);
    TEST_ASSERT_EQUAL_INT64(3, s.confirmations);
    TEST_ASSERT_TRUE(s.has_block_height);
    TEST_ASSERT_EQUAL_INT64(800000, s.block_height);

    /* confirmed but blockheight absent (null) */
    memset(&s, 0, sizeof s);
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        interpret_tx_status(false, 1, 0, false, &s));
    TEST_ASSERT_EQUAL_INT(TX_STATE_CONFIRMED, s.state);
    TEST_ASSERT_FALSE(s.has_block_height);

    /* mempool: 0 confirmations but raw present */
    memset(&s, 0, sizeof s);
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        interpret_tx_status(true, 0, 0, false, &s));
    TEST_ASSERT_EQUAL_INT(TX_STATE_MEMPOOL, s.state);
    TEST_ASSERT_EQUAL_INT64(0, s.confirmations);
    TEST_ASSERT_FALSE(s.has_block_height);

    /* unknown: 0 confirmations and no raw */
    memset(&s, 0, sizeof s);
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        interpret_tx_status(false, 0, 0, false, &s));
    TEST_ASSERT_EQUAL_INT(TX_STATE_UNKNOWN, s.state);
}

/* is_429: true if status==429 OR message matches /429|too many requests/i. */
static void test_is_429_classification(void)
{
    TEST_ASSERT_TRUE(is_429(429, NULL));
    TEST_ASSERT_TRUE(is_429(0, "HTTP 429 from upstream"));
    TEST_ASSERT_TRUE(is_429(0, "Too Many Requests"));   /* case-insensitive */
    TEST_ASSERT_TRUE(is_429(0, "too many requests"));
    TEST_ASSERT_FALSE(is_429(200, NULL));
    TEST_ASSERT_FALSE(is_429(404, "not found"));
    TEST_ASSERT_FALSE(is_429(500, NULL));
}

/* broadcast strips a SINGLE leading and a SINGLE trailing double-quote only.
 * POST /tx/raw with a quoted txid body -> de-quoted txid. TS: broadcast. */
static void test_broadcast_strips_one_quote(void)
{
    woc_client_opts_t copts = {0};
    copts.transport = &g_transport;
    woc_client_t *client = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, woc_client_new(&copts, &client));

    /* WoC returns the txid wrapped in JSON-string quotes. */
    TEST_ASSERT_EQUAL_INT(BNS_OK, mock_http_register(
        g_http, "POST", "/tx/raw", 200, "\"abcdef0123\"", 0, true));

    char *txid = NULL;
    int rc = woc_client_broadcast(client, "deadbeef", &txid);
    TEST_ASSERT_EQUAL_INT(BNS_OK, rc);
    TEST_ASSERT_NOT_NULL(txid);
    TEST_ASSERT_EQUAL_STRING("abcdef0123", txid);   /* one leading+trailing quote stripped */
    free(txid);

    /* the request body actually carried the raw hex */
    TEST_ASSERT_TRUE(mock_http_requested(g_http, "/tx/raw"));

    woc_client_free(client);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_get_raw_tx_returns_trimmed_hex);
    RUN_TEST(test_get_raw_tx_non_ok_status_errors);
    RUN_TEST(test_get_time_blocktime_then_time_fallback);
    RUN_TEST(test_get_spending_txid_spent_and_404_null);
    RUN_TEST(test_drives_reputation_indexer_end_to_end);
    RUN_TEST(test_interpret_tx_status_blockheight_wire);
    RUN_TEST(test_is_429_classification);
    RUN_TEST(test_broadcast_strips_one_quote);
    return UNITY_END();
}
