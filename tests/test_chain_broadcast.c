/*
 * test_chain_broadcast.c — offline tests for shared broadcast funding helpers.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>

#include "unity.h"

#include "scripts/chain_broadcast.h"
#include "chainSources/http_transport.h"
#include "chainSources/woc_client.h"

void setUp(void) {}
void tearDown(void) {}

static void test_select_funding_rejects_prefix_total_over_money(void)
{
    const char *body =
        "["
        "{\"tx_hash\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
        "\"tx_pos\":0,\"value\":1050000000000000,\"height\":1},"
        "{\"tx_hash\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\","
        "\"tx_pos\":1,\"value\":1050000000000001,\"height\":1}"
        "]";
    http_stub_entry_t entries[] = {
        { "GET", "/address/funder/unspent", 200, body, 0 },
    };
    http_transport_t tp;
    TEST_ASSERT_EQUAL_INT(BNS_OK, http_transport_stub(entries, 1, &tp));

    woc_client_opts_t opts;
    memset(&opts, 0, sizeof opts);
    opts.transport = &tp;
    woc_client_t *woc = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, woc_client_new(&opts, &woc));

    funding_utxos_t out;
    bonsai_err_ctx err = {0};
    int rc = chain_broadcast_select_funding(woc, "funder", BONSAI_MAX_MONEY, &out, &err);
    TEST_ASSERT_EQUAL_INT(BNS_ERANGE, rc);
    TEST_ASSERT_NULL(out.items);
    TEST_ASSERT_EQUAL_size_t(0, out.count);

    woc_client_free(woc);
    tp.free(tp.ctx);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_select_funding_rejects_prefix_total_over_money);
    return UNITY_END();
}
