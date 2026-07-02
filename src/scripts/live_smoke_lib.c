/*
 * live_smoke_lib.c — read-only WhatsOnChain smoke test (faithful port of
 * scripts/liveSmoke.ts).
 *
 * TS reference (scripts/liveSmoke.ts):
 *   const woc = new WhatsOnChainSource({ network: 'main' })
 *   const TX  = 'f418...9e16'                  // block-170 Satoshi -> Hal Finney
 *   const hex     = await woc.getRawTx(TX)
 *   const time    = await woc.getTime(TX)
 *   const spender = await woc.getSpendingTxid(TX, 0)
 *   const prev    = parsePrevout(hex, 0)
 *   const prevHex = await woc.getRawTx(prev.txid)
 *   const results = { getRawTx_ok, getTime_unix, getTime_iso,
 *                     getSpendingTxid_output0, parsePrevout, backwardHop_ok }
 *   console.log(JSON.stringify(results, null, 2))
 *   const allOk = ...
 *   console.log(allOk ? 'LIVE SMOKE: PASS' : 'LIVE SMOKE: FAIL')
 *   process.exit(allOk ? 0 : 1)
 *
 * The C port takes the chain_source_t (the WhatsOnChain adapter's vtable) by
 * injection so the smoke path is testable against a stub transport; live_smoke_run
 * wires up the libcurl transport for real mainnet.
 */
#include "scripts/live_smoke.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "chainSources/http_transport.h"
#include "chainSources/whats_on_chain.h"

/* "LIVE SMOKE: ERROR <msg>" on stderr, exit code 1 — the TS top-level catch. */
static int smoke_error(const char *msg, int *out_exit_code)
{
    fprintf(stderr, "LIVE SMOKE: ERROR %s\n", msg ? msg : "");
    if (out_exit_code) *out_exit_code = 1;
    return BNS_OK;
}

/* new Date(time*1000).toISOString() == "YYYY-MM-DDTHH:MM:SS.000Z" (UTC, .000ms
 * because unix-seconds carry no sub-second part). Writes into buf[>=25]. */
static void iso8601_utc(int64_t unix_secs, char *buf, size_t buflen)
{
    time_t t = (time_t)unix_secs;
    struct tm tmv;
    gmtime_r(&t, &tmv);
    char base[20]; /* "YYYY-MM-DDTHH:MM:SS" */
    strftime(base, sizeof base, "%Y-%m-%dT%H:%M:%S", &tmv);
    snprintf(buf, buflen, "%s.000Z", base);
}

int live_smoke_run_with_source(const chain_source_t *source, int *out_exit_code)
{
    if (out_exit_code) *out_exit_code = 1;
    if (!source || !source->get_raw_tx || !source->get_time)
        return smoke_error("invalid chain source", out_exit_code);

    const char *TX = BONSAI_LIVE_SMOKE_TX;

    char   *hex      = NULL;  /* getRawTx(TX)            */
    int64_t time_unix = 0;    /* getTime(TX)            */
    char   *spender  = NULL;  /* getSpendingTxid(TX, 0) */
    char   *prev_hex = NULL;  /* getRawTx(prev.txid)    */
    indexer_prevout_t prev;
    memset(&prev, 0, sizeof prev);
    int rc;
    int ret = BNS_OK;

    /* const hex = await woc.getRawTx(TX) */
    rc = source->get_raw_tx(source->ctx, TX, &hex);
    if (rc != BNS_OK || !hex) { ret = smoke_error("getRawTx failed", out_exit_code); goto done; }

    /* const time = await woc.getTime(TX) */
    rc = source->get_time(source->ctx, TX, &time_unix);
    if (rc != BNS_OK) { ret = smoke_error("getTime failed", out_exit_code); goto done; }

    /* const spender = await woc.getSpendingTxid(TX, 0) — OPTIONAL vtable slot.
     * The TS adapter always implements it; a NULL slot means no spend index. */
    if (source->get_spending_txid) {
        rc = source->get_spending_txid(source->ctx, TX, 0, &spender);
        if (rc != BNS_OK) { ret = smoke_error("getSpendingTxid failed", out_exit_code); goto done; }
    }

    /* const prev = parsePrevout(hex, 0) */
    rc = indexer_parse_prevout(hex, 0, &prev);
    if (rc != BNS_OK) { ret = smoke_error("parsePrevout failed", out_exit_code); goto done; }

    /* const prevHex = await woc.getRawTx(prev.txid) — one real backward hop */
    rc = source->get_raw_tx(source->ctx, prev.txid, &prev_hex);
    if (rc != BNS_OK || !prev_hex) { ret = smoke_error("backward hop getRawTx failed", out_exit_code); goto done; }

    /* ---- build the results object (JSON.stringify(results, null, 2)) ------- */
    bool    getRawTx_ok    = strncmp(hex, "0100", 4) == 0;   /* hex.startsWith('0100') */
    int64_t getTime_unix   = time_unix;
    char    getTime_iso[32];
    iso8601_utc(getTime_unix, getTime_iso, sizeof getTime_iso);
    bool    backwardHop_ok = strlen(prev_hex) > 0;

    cJSON *results = cJSON_CreateObject();
    if (!results) { ret = smoke_error("out of memory", out_exit_code); goto done; }

    cJSON_AddBoolToObject(results, "getRawTx_ok", getRawTx_ok);
    cJSON_AddNumberToObject(results, "getTime_unix", (double)getTime_unix);
    cJSON_AddStringToObject(results, "getTime_iso", getTime_iso);
    /* getSpendingTxid_output0: txid string, or JSON null (TS `null` sentinel). */
    if (spender)
        cJSON_AddStringToObject(results, "getSpendingTxid_output0", spender);
    else
        cJSON_AddNullToObject(results, "getSpendingTxid_output0");
    /* parsePrevout: { txid, vout } */
    cJSON *prevout = cJSON_CreateObject();
    cJSON_AddStringToObject(prevout, "txid", prev.txid);
    cJSON_AddNumberToObject(prevout, "vout", (double)prev.vout);
    cJSON_AddItemToObject(results, "parsePrevout", prevout);
    cJSON_AddBoolToObject(results, "backwardHop_ok", backwardHop_ok);

    char *json = cJSON_Print(results);
    if (json) {
        printf("%s\n", json);
        free(json);
    }
    cJSON_Delete(results);

    /* const allOk = getRawTx_ok && getTime_unix > 0 && !!spender &&
     *               parsePrevout.txid.length === 64 && backwardHop_ok */
    bool allOk = getRawTx_ok
              && getTime_unix > 0
              && spender != NULL
              && strlen(prev.txid) == 64
              && backwardHop_ok;

    printf("%s\n", allOk ? "LIVE SMOKE: PASS" : "LIVE SMOKE: FAIL");
    if (out_exit_code) *out_exit_code = allOk ? 0 : 1;

done:
    free(hex);
    free(spender);
    free(prev_hex);
    return ret;
}

int live_smoke_run(int argc, char **argv, int *out_exit_code)
{
    (void)argc; (void)argv;
    if (out_exit_code) *out_exit_code = 1;

    /* globalThis.fetch == the libcurl transport. */
    http_transport_t transport;
    memset(&transport, 0, sizeof transport);
    int rc = http_transport_curl(&transport);
    if (rc != BNS_OK)
        return smoke_error("failed to create HTTP transport", out_exit_code);

    /* new WhatsOnChainSource({ network: 'main' }) */
    whats_on_chain_opts_t opts;
    memset(&opts, 0, sizeof opts);
    opts.network   = WOC_NETWORK_MAIN;
    opts.transport = &transport;

    whats_on_chain_t *woc = NULL;
    rc = whats_on_chain_new(&opts, &woc);
    if (rc != BNS_OK) {
        if (transport.free) transport.free(transport.ctx);
        return smoke_error("failed to create WhatsOnChainSource", out_exit_code);
    }

    chain_source_t source;
    memset(&source, 0, sizeof source);
    rc = whats_on_chain_as_source(woc, &source);
    if (rc != BNS_OK) {
        whats_on_chain_free(woc);
        if (transport.free) transport.free(transport.ctx);
        return smoke_error("failed to bind chain source", out_exit_code);
    }

    int ret = live_smoke_run_with_source(&source, out_exit_code);

    whats_on_chain_free(woc);
    if (transport.free) transport.free(transport.ctx);
    return ret;
}
