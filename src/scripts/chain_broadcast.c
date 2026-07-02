/*
 * chain_broadcast.c — implementation of include/scripts/chain_broadcast.h.
 *
 * The only real bookkeeping here is ownership of the libcurl transport: a
 * woc_client_t borrows its http_transport_t (woc_client_new documents that the
 * transport must outlive the client and that woc_client_free does NOT free it),
 * but chain_broadcast_woc_new() promises a single handle that owns both. We
 * heap-allocate the http_transport_t so it outlives the call, build the client
 * over it, and remember the (client -> transport) pair in a tiny process-local
 * registry so chain_broadcast_woc_free() can release both. The chain_c CLIs are
 * single-threaded, so a plain array with no locking is sufficient and matches
 * the "not thread-safe; fine for CLIs" convention used elsewhere (bonsai_home).
 */
#include "scripts/chain_broadcast.h"

#include <stdlib.h>
#include <string.h>

#include "chainSources/http_transport.h"

/* ---- client -> owned-transport registry (single-threaded CLI use) ------- */

typedef struct {
    woc_client_t      *client;
    http_transport_t  *transport;   /* heap-owned; freed via ->free(->ctx)     */
} cb_owned_t;

static cb_owned_t *g_owned;
static size_t      g_owned_count;
static size_t      g_owned_cap;

/* Remember that `client` owns `transport`. Returns BNS_OK / BNS_ENOMEM. */
static int cb_register(woc_client_t *client, http_transport_t *transport) {
    if (g_owned_count == g_owned_cap) {
        size_t ncap = g_owned_cap ? g_owned_cap * 2 : 4;
        cb_owned_t *n = realloc(g_owned, ncap * sizeof *n);
        if (!n) return BNS_ENOMEM;
        g_owned = n;
        g_owned_cap = ncap;
    }
    g_owned[g_owned_count].client = client;
    g_owned[g_owned_count].transport = transport;
    g_owned_count++;
    return BNS_OK;
}

/* Remove `client` from the registry, returning its owned transport (or NULL if
 * it was not built by chain_broadcast_woc_new). */
static http_transport_t *cb_take(woc_client_t *client) {
    for (size_t i = 0; i < g_owned_count; i++) {
        if (g_owned[i].client == client) {
            http_transport_t *tp = g_owned[i].transport;
            g_owned[i] = g_owned[g_owned_count - 1];
            g_owned_count--;
            if (g_owned_count == 0) {
                free(g_owned);
                g_owned = NULL;
                g_owned_cap = 0;
            }
            return tp;
        }
    }
    return NULL;
}

/* ---- lifecycle ---------------------------------------------------------- */

woc_client_t *chain_broadcast_woc_new(bsv_network_t net, bonsai_err_ctx *err) {
    if (net == BSV_TESTNET) {
        /* woc_client.h pins BONSAI_WOC_CLIENT_BASE to mainnet; refuse rather
         * than silently broadcast a testnet tx to mainnet. */
        bns_fail(err, BNS_EUNSUPPORTED,
                 "chain_broadcast: WoC client is mainnet-only (no testnet base)");
        return NULL;
    }
    if (net != BSV_MAINNET) {
        bns_fail(err, BNS_EINVAL, "chain_broadcast: unknown network %d", (int)net);
        return NULL;
    }

    http_transport_t *tp = calloc(1, sizeof *tp);
    if (!tp) {
        bns_fail(err, BNS_ENOMEM, "chain_broadcast: out of memory");
        return NULL;
    }
    int rc = http_transport_curl(tp);
    if (rc != BNS_OK) {
        free(tp);
        bns_fail(err, rc, "chain_broadcast: could not build libcurl transport");
        return NULL;
    }

    woc_client_opts_t copts;
    memset(&copts, 0, sizeof copts);
    copts.transport = tp;   /* borrowed by the client; we keep it alive */

    woc_client_t *woc = NULL;
    rc = woc_client_new(&copts, &woc);
    if (rc != BNS_OK) {
        if (tp->free) tp->free(tp->ctx);
        free(tp);
        bns_fail(err, rc, "chain_broadcast: could not create WoC client");
        return NULL;
    }

    if (cb_register(woc, tp) != BNS_OK) {
        woc_client_free(woc);
        if (tp->free) tp->free(tp->ctx);
        free(tp);
        bns_fail(err, BNS_ENOMEM, "chain_broadcast: out of memory");
        return NULL;
    }
    return woc;
}

void chain_broadcast_woc_free(woc_client_t *woc) {
    if (!woc) return;
    http_transport_t *tp = cb_take(woc);
    woc_client_free(woc);
    if (tp) {
        if (tp->free) tp->free(tp->ctx);
        free(tp);
    }
}

/* ---- funding selection -------------------------------------------------- */

int chain_broadcast_select_funding(woc_client_t *woc,
                                   const char *funder_address,
                                   int64_t need_sats,
                                   funding_utxos_t *out,
                                   bonsai_err_ctx *err) {
    if (out) memset(out, 0, sizeof *out);
    if (!woc || !funder_address || !*funder_address || !out)
        return bns_fail(err, BNS_EINVAL, "chain_broadcast_select_funding: null arg");
    if (need_sats <= 0)
        return bns_fail(err, BNS_EINVAL,
                        "chain_broadcast_select_funding: need_sats must be positive");

    /* 1. list the address's UTXOs. */
    woc_utxos_t listed;
    memset(&listed, 0, sizeof listed);
    int rc = woc_client_list_utxos(woc, funder_address, &listed);
    if (rc != BNS_OK)
        return bns_fail(err, rc,
                        "chain_broadcast: WoC UTXO listing failed for %s",
                        funder_address);

    /* 2. rank confirmed-first / descending value (defaults: keep all). */
    funding_utxos_t ranked;
    memset(&ranked, 0, sizeof ranked);
    rc = rank_funding_utxos(listed.items, listed.count, NULL, &ranked);
    woc_utxos_free(&listed);
    if (rc != BNS_OK)
        return bns_fail(err, rc, "chain_broadcast: ranking funding UTXOs failed");

    /* 3. greedily take the smallest prefix whose total >= need_sats. */
    uint64_t total = 0;
    size_t take = 0;
    for (size_t i = 0; i < ranked.count; i++) {
        int64_t v = ranked.items[i].satoshis;
        if (v < 0 || v > BONSAI_MAX_MONEY ||
            (uint64_t)v > (uint64_t)BONSAI_MAX_MONEY - total) {
            funding_utxos_free(&ranked);
            return bns_fail(err, BNS_ERANGE,
                            "chain_broadcast: funding total out of range");
        }
        total += (uint64_t)v;
        take = i + 1;
        if (total >= (uint64_t)need_sats) break;
    }

    if (total < (uint64_t)need_sats) {
        funding_utxos_free(&ranked);
        return bns_fail(err, BNS_ENOTFOUND,
                        "chain_broadcast: insufficient funds for %s: "
                        "have %lld sats, need %lld sats",
                        funder_address, (long long)total, (long long)need_sats);
    }

    /* 4. hand back exactly `take` UTXOs in ranked order. Shrink the owned array
     *    in place so the caller frees it with funding_utxos_free unchanged. */
    funding_utxo_t *items = malloc(take * sizeof *items);
    if (!items) {
        funding_utxos_free(&ranked);
        return bns_fail(err, BNS_ENOMEM, "chain_broadcast: out of memory");
    }
    memcpy(items, ranked.items, take * sizeof *items);
    funding_utxos_free(&ranked);

    out->items = items;
    out->count = take;
    return BNS_OK;
}

/* ---- broadcast ---------------------------------------------------------- */

int chain_broadcast_send(woc_client_t *woc,
                         const char *raw_hex,
                         char **out_txid,
                         bonsai_err_ctx *err) {
    if (out_txid) *out_txid = NULL;
    if (!woc || !raw_hex || !*raw_hex || !out_txid)
        return bns_fail(err, BNS_EINVAL, "chain_broadcast_send: null/empty arg");

    int rc = woc_client_broadcast(woc, raw_hex, out_txid);
    if (rc != BNS_OK) {
        *out_txid = NULL;
        return bns_fail(err, rc, "chain_broadcast: WoC broadcast failed (%s)",
                        bns_err_name((bonsai_err_t)rc));
    }
    return BNS_OK;
}

/* ---- fee sizing (optional) ---------------------------------------------- */

int chain_broadcast_fee_window(int64_t signed_size_bytes,
                               int64_t fee_per_kb,
                               fee_window_t *out,
                               bonsai_err_ctx *err) {
    if (!out)
        return bns_fail(err, BNS_EINVAL, "chain_broadcast_fee_window: null out");
    int rc = send_time_fee_window(signed_size_bytes, fee_per_kb, out);
    if (rc != BNS_OK)
        return bns_fail(err, rc,
                        "chain_broadcast_fee_window: invalid size/rate");
    return BNS_OK;
}
