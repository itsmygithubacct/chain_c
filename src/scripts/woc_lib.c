/*
 * woc_lib.c — implementation of the `woc` CLI (see include/scripts/woc.h).
 *
 * Thin dispatcher over WocClient (chainSources/woc_client.h), rank_funding_utxos
 * (chainSources/utxo_select.h) and send_time_fee_window (chainSources/bsv_fees.h).
 * Mirrors scripts/woc.ts: parses argv[2..4] as cmd/a/b, switch-dispatches, and
 * prints JSON.stringify-equivalent output to stdout.
 *
 * Exit codes match the TS: unknown cmd -> usage to stderr + 2; any thrown error
 * -> 'woc error: <msg>' to stderr + 1; success -> 0.
 *
 * JSON output is hand-built to be byte-for-byte compatible with JSON.stringify:
 *   - compact (no spaces) for every command except `utxos`;
 *   - `utxos` uses JSON.stringify(x, null, 1): 1-space-per-level indent, ": "
 *     after keys, empty array prints as "[]".
 */
#include "scripts/woc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include "chainSources/woc_client.h"
#include "chainSources/utxo_select.h"
#include "chainSources/bsv_fees.h"

#define WOC_USAGE \
    "usage: woc <status|tx|rawtx|utxos|fund|spent|balance|broadcast|wait|" \
    "mempool|feewindow> ...\n"

/* JS Number(x): parse a decimal string to int64. Empty / undefined args in TS
 * become Number(undefined)=NaN, but the commands that use Number() always have a
 * required arg present in practice; we coerce a NULL/empty to 0 (matching the
 * `Number(b ? ... )` guards where b is checked first). */
static int64_t js_number(const char *s) {
    if (!s || !*s) return 0;
    return (int64_t)strtoll(s, NULL, 10);
}

/* Map an error code to a short message for the 'woc error: <msg>' line. The TS
 * surfaces the thrown Error.message (e.g. "WoC GET ...: HTTP 500"); the C
 * woc_client API returns only codes, so we report the code name. */
static const char *woc_err_msg(int rc) {
    switch (rc) {
        case BNS_ENET:      return "network error";
        case BNS_EPARSE:    return "parse error";
        case BNS_ENOTFOUND: return "not found";
        case BNS_EINVAL:    return "invalid argument";
        case BNS_ENOMEM:    return "out of memory";
        default:            return bns_err_name((bonsai_err_t)rc);
    }
}

static const char *state_str(tx_state_t s) {
    switch (s) {
        case TX_STATE_CONFIRMED: return "confirmed";
        case TX_STATE_MEMPOOL:   return "mempool";
        default:                 return "unknown";
    }
}

/* Print a compact JSON {txid, ...status} line (status command). */
static void print_status_json(const char *txid, const tx_status_t *st) {
    printf("{\"txid\":\"%s\",\"state\":\"%s\",\"confirmations\":%" PRId64
           ",\"blockHeight\":",
           txid ? txid : "", state_str(st->state), st->confirmations);
    if (st->has_block_height)
        printf("%" PRId64 "}\n", st->block_height);
    else
        printf("null}\n");
}

/* `utxos`: ranked funding candidates as JSON.stringify(arr, null, 1). */
static void print_utxos_indent1(const funding_utxos_t *f) {
    if (f->count == 0) {
        printf("[]\n");
        return;
    }
    printf("[\n");
    for (size_t i = 0; i < f->count; i++) {
        const funding_utxo_t *u = &f->items[i];
        printf(" {\n");
        printf("  \"txId\": \"%s\",\n", u->tx_id);
        printf("  \"outputIndex\": %" PRIu32 ",\n", u->output_index);
        printf("  \"satoshis\": %" PRId64 ",\n", u->satoshis);
        printf("  \"confirmed\": %s\n", u->confirmed ? "true" : "false");
        printf(" }%s\n", (i + 1 < f->count) ? "," : "");
    }
    printf("]\n");
}

/* Emit 'woc error: <msg>' and set exit code 1. Returns BNS_OK (run() always
 * reports the outcome via *out_exit_code, like the TS top-level catch). */
static int fail_run(int rc, int *out_exit_code) {
    fprintf(stderr, "woc error: %s\n", woc_err_msg(rc));
    *out_exit_code = 1;
    return BNS_OK;
}

int woc_run(int argc, char **argv, const http_transport_t *transport,
            int *out_exit_code) {
    int exit_code = 0;
    /* argv[0] is the program name; TS uses process.argv.slice(2) so cmd/a/b are
     * argv[1..3] here. Missing args are NULL (TS: undefined). */
    const char *cmd = (argc > 1) ? argv[1] : NULL;
    const char *a   = (argc > 2) ? argv[2] : NULL;
    const char *b   = (argc > 3) ? argv[3] : NULL;

    if (!cmd) {
        fputs(WOC_USAGE, stderr);
        *out_exit_code = 2;
        return BNS_OK;
    }

    /* feewindow is pure compute and needs no network/transport — handle it
     * before constructing the client so it works offline. */
    if (strcmp(cmd, "feewindow") == 0) {
        int64_t signed_bytes = js_number(a);
        int64_t fee_per_kb   = js_number(b);
        fee_window_t w;
        int rc = send_time_fee_window(signed_bytes, fee_per_kb, &w);
        if (rc != BNS_OK) { *out_exit_code = 0; return fail_run(rc, out_exit_code); }
        printf("{\"signedBytes\":%" PRId64 ",\"feePerKb\":%" PRId64
               ",\"min\":%" PRId64 ",\"max\":%" PRId64 ",\"recommended\":%"
               PRId64 "}\n",
               signed_bytes, fee_per_kb, w.min, w.max, w.recommended);
        *out_exit_code = 0;
        return BNS_OK;
    }

    /* Construct the WocClient (default libcurl transport unless one is injected).
     * Build a libcurl transport iff none was supplied. */
    http_transport_t curl_tp;
    bool own_transport = false;
    const http_transport_t *tp = transport;
    if (!tp) {
        int rc = http_transport_curl(&curl_tp);
        if (rc != BNS_OK) {
            *out_exit_code = 0;
            return fail_run(rc, out_exit_code);
        }
        tp = &curl_tp;
        own_transport = true;
    }

    woc_client_opts_t copts;
    memset(&copts, 0, sizeof copts);
    copts.transport = tp;
    woc_client_t *woc = NULL;
    int rc = woc_client_new(&copts, &woc);
    if (rc != BNS_OK) {
        if (own_transport && curl_tp.free) curl_tp.free(curl_tp.ctx);
        *out_exit_code = 0;
        return fail_run(rc, out_exit_code);
    }

    int op_rc = BNS_OK;
    bool unknown = false;

    if (strcmp(cmd, "status") == 0) {
        tx_status_t st;
        op_rc = woc_client_tx_status(woc, a, &st);
        if (op_rc == BNS_OK) print_status_json(a, &st);

    } else if (strcmp(cmd, "tx") == 0) {
        tx_status_t st;
        op_rc = woc_client_tx_status(woc, a, &st);
        if (op_rc == BNS_OK) {
            /* {txid, confirmations, blockheight: blockHeight ?? 'mempool'} */
            printf("{\"txid\":\"%s\",\"confirmations\":%" PRId64
                   ",\"blockheight\":", a ? a : "", st.confirmations);
            if (st.has_block_height)
                printf("%" PRId64 "}\n", st.block_height);
            else
                printf("\"mempool\"}\n");
        }

    } else if (strcmp(cmd, "rawtx") == 0) {
        char *hex = NULL;
        op_rc = woc_client_raw_tx(woc, a, &hex);
        if (op_rc == BNS_OK) {
            printf("%s\n", hex ? hex : "(not found)");
            free(hex);
        }

    } else if (strcmp(cmd, "utxos") == 0) {
        woc_utxos_t u;
        memset(&u, 0, sizeof u);
        op_rc = woc_client_list_utxos(woc, a, &u);
        if (op_rc == BNS_OK) {
            funding_utxos_t ranked;
            memset(&ranked, 0, sizeof ranked);
            op_rc = rank_funding_utxos(u.items, u.count, NULL, &ranked);
            if (op_rc == BNS_OK) {
                print_utxos_indent1(&ranked);
                funding_utxos_free(&ranked);
            }
            woc_utxos_free(&u);
        }

    } else if (strcmp(cmd, "fund") == 0) {
        rank_opts_t opts;
        memset(&opts, 0, sizeof opts);
        const rank_opts_t *optp = NULL;
        if (b) { /* TS: b ? { minSats: Number(b) } : {} */
            opts.min_sats = js_number(b);
            opts.has_min_sats = true;
            optp = &opts;
        }
        funding_utxo_t fu;
        memset(&fu, 0, sizeof fu);
        bool found = false;
        op_rc = woc_client_pick_funding(woc, a, optp, &fu, &found);
        if (op_rc == BNS_OK) {
            if (found) {
                printf("{\"txId\":\"%s\",\"outputIndex\":%" PRIu32
                       ",\"satoshis\":%" PRId64 ",\"confirmed\":%s}\n",
                       fu.tx_id, fu.output_index, fu.satoshis,
                       fu.confirmed ? "true" : "false");
            } else {
                printf("(no spendable UTXO)\n");
            }
        }

    } else if (strcmp(cmd, "spent") == 0) {
        bool spent = false;
        op_rc = woc_client_is_output_spent(woc, a, (uint32_t)js_number(b), &spent);
        /* TS maps null->'unknown'; the C API never yields null on this path, so
         * only 'spent'/'unspent' are produced (matches the implementation). */
        if (op_rc == BNS_OK) printf("%s\n", spent ? "spent" : "unspent");

    } else if (strcmp(cmd, "balance") == 0) {
        woc_balance_t bal;
        memset(&bal, 0, sizeof bal);
        op_rc = woc_client_balance(woc, a, &bal);
        if (op_rc == BNS_OK)
            printf("{\"confirmed\":%" PRId64 ",\"unconfirmed\":%" PRId64 "}\n",
                   bal.confirmed, bal.unconfirmed);

    } else if (strcmp(cmd, "broadcast") == 0) {
        char *txid = NULL;
        op_rc = woc_client_broadcast(woc, a, &txid);
        if (op_rc == BNS_OK) {
            printf("%s\n", txid ? txid : "");
            free(txid);
        }

    } else if (strcmp(cmd, "wait") == 0) {
        woc_wait_opts_t wopts;
        memset(&wopts, 0, sizeof wopts);
        /* TS: { confirmations: b ? Number(b) : 1 } */
        wopts.confirmations = b ? js_number(b) : 1;
        wopts.has_confirmations = true;
        tx_status_t st;
        op_rc = woc_client_wait_for_confirmation(woc, a, &wopts, &st);
        if (op_rc == BNS_OK) print_status_json(a, &st);

    } else if (strcmp(cmd, "mempool") == 0) {
        op_rc = woc_client_wait_for_mempool(woc, a, NULL);
        if (op_rc == BNS_OK)
            printf("{\"txid\":\"%s\",\"state\":\"mempool\"}\n", a ? a : "");

    } else {
        unknown = true;
    }

    woc_client_free(woc);
    if (own_transport && curl_tp.free) curl_tp.free(curl_tp.ctx);

    if (unknown) {
        fputs(WOC_USAGE, stderr);
        *out_exit_code = 2;
        return BNS_OK;
    }
    if (op_rc != BNS_OK) {
        *out_exit_code = 0;
        return fail_run(op_rc, out_exit_code);
    }
    *out_exit_code = exit_code;
    return BNS_OK;
}
