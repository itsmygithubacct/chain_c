/*
 * pay_lib.c — logic for the `pay` CLI (see include/scripts/pay.h).
 *
 * Sends BSV from a funded key to a P2PKH address (or sweeps the whole balance).
 * Reuses wallet_fund_and_sign (UTXO fetch+rank) and wallet_build_signed_spend.
 * Dry-run unless CONFIRM_MAINNET_BROADCAST=yes.
 */
#include "scripts/pay.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include "scripts/script_support.h"
#include "crypto/ecdsa.h"
#include "chainSources/http_transport.h"
#include "chainSources/woc_client.h"
#include "wallet/spend.h"
#include "wallet/send.h"

static int fail(const char *msg, int *ec) {
    fprintf(stderr, "PAY FAILED: %s\n", msg);
    *ec = 1;
    return BNS_OK;
}

/* Parse a non-negative satoshi amount; returns false on junk/negative. */
static bool parse_sats(const char *s, int64_t *out) {
    if (!s || !*s) return false;
    char *end = NULL; errno = 0;
    long long v = strtoll(s, &end, 10);
    if (errno || end == s || *end != '\0' || v < 0) return false;
    *out = (int64_t)v;
    return true;
}

int pay_run(int argc, char **argv, int *out_exit_code)
{
    (void)argc; (void)argv;
    int dummy = 0; if (!out_exit_code) out_exit_code = &dummy; *out_exit_code = 0;

    /* KEY_FILE default. */
    const char *kfe = env_get("KEY_FILE");
    char kfbuf[2048]; const char *key_file;
    if (kfe && kfe[0]) key_file = kfe;
    else { snprintf(kfbuf, sizeof kfbuf, "%s/chain/test_bsv.json", bonsai_home()); key_file = kfbuf; }

    const char *to = env_get("TO");
    const char *sweep_env = env_get("SWEEP");
    bool sweep = sweep_env && strcmp(sweep_env, "yes") == 0;
    int64_t amount = 0;
    if (!sweep) {
        if (!parse_sats(env_get("AMOUNT"), &amount))
            return fail("set AMOUNT=<sats> (or SWEEP=yes)", out_exit_code);
    }
    if (!to || !to[0]) return fail("set TO=<address>", out_exit_code);
    int64_t fee_per_kb = 0; /* 0 => wallet default rate */
    const char *fee_env = env_get("FEE_PER_KB");
    if (fee_env && fee_env[0]) {
        /* Refuse a garbage or out-of-range rate rather than silently defaulting. */
        if (!parse_sats(fee_env, &fee_per_kb) || fee_per_kb > WALLET_MAX_FEE_PER_KB)
            return fail("FEE_PER_KB must be a non-negative integer (sats/KB) within range", out_exit_code);
    }

    /* Load + verify key (mainnet). */
    bonsai_err_ctx err = {0};
    key_file_t kf;
    int rc = key_file_load(key_file, &kf, &err);
    if (rc != BNS_OK) return fail(err.msg[0] ? err.msg : "key file load failed", out_exit_code);
    rc = key_file_verify(&kf, BSV_MAINNET, &err);
    if (rc != BNS_OK) { key_file_free(&kf); return fail(err.msg[0] ? err.msg : "WIF/address mismatch", out_exit_code); }

    ecdsa_key_t *key = NULL;
    rc = ecdsa_key_from_wif(kf.wif, &key, NULL);
    if (rc != BNS_OK) { key_file_free(&kf); return fail("invalid WIF", out_exit_code); }

    /* WocClient. */
    http_transport_t tp;
    rc = http_transport_curl(&tp);
    if (rc != BNS_OK) { ecdsa_key_free(key); key_file_free(&kf); return fail("HTTP init failed", out_exit_code); }
    woc_client_t *woc = NULL;
    woc_client_opts_t wo = { .transport = &tp, .sleep = NULL, .sleep_user = NULL };
    rc = woc_client_new(&wo, &woc);
    if (rc != BNS_OK) { tp.free(tp.ctx); ecdsa_key_free(key); key_file_free(&kf); return fail("WocClient init failed", out_exit_code); }

    /* Build the plan. */
    spend_recipient_t r; memset(&r, 0, sizeof r);
    strncpy(r.address, to, sizeof r.address - 1);
    r.satoshis = (uint64_t)amount;
    spend_plan_t plan; memset(&plan, 0, sizeof plan);
    plan.recipients = &r; plan.num_recipients = 1;
    plan.change_address = kf.address;
    plan.fee_per_kb = (uint64_t)(fee_per_kb > 0 ? fee_per_kb : 0);
    plan.send_all = sweep;

    spend_result_t res;
    rc = wallet_fund_and_sign(woc, BSV_MAINNET, key, kf.address, &plan, &res, &err);
    if (rc != BNS_OK) {
        woc_client_free(woc); tp.free(tp.ctx); ecdsa_key_free(key); key_file_free(&kf);
        return fail(err.msg[0] ? err.msg : bns_err_name((bonsai_err_t)rc), out_exit_code);
    }

    printf("pay txid     : %s\n", res.txid);
    printf("from         : %s\n", kf.address);
    printf("to           : %s%s\n", to, sweep ? "  (SWEEP)" : "");
    printf("inputs       : %zu  (%" PRIu64 " sats)\n", res.num_inputs, res.total_in);
    printf("sent         : %" PRIu64 " sats\n", sweep ? res.total_out : (uint64_t)amount);
    printf("change       : %" PRIu64 " sats -> %s\n", res.change, kf.address);
    printf("fee / size   : %" PRIu64 " sats / %zu bytes\n", res.fee, res.size_bytes);

    if (!confirm_mainnet_broadcast()) {
        printf("\nDRY RUN — set CONFIRM_MAINNET_BROADCAST=yes to send.\n");
        printf("raw tx: %s\n", res.raw_hex);
        spend_result_free(&res); woc_client_free(woc); tp.free(tp.ctx);
        ecdsa_key_free(key); key_file_free(&kf);
        return BNS_OK;
    }

    char *btxid = NULL;
    rc = woc_client_broadcast(woc, res.raw_hex, &btxid);
    if (rc != BNS_OK) {
        char m[256]; snprintf(m, sizeof m, "broadcast failed: %s", bns_err_name((bonsai_err_t)rc));
        free(btxid); spend_result_free(&res); woc_client_free(woc); tp.free(tp.ctx);
        ecdsa_key_free(key); key_file_free(&kf);
        return fail(m, out_exit_code);
    }
    printf("\nBROADCAST OK: %s\n", btxid);
    free(btxid);
    spend_result_free(&res); woc_client_free(woc); tp.free(tp.ctx);
    ecdsa_key_free(key); key_file_free(&kf);
    return BNS_OK;
}
