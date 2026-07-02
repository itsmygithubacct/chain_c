/*
 * throttled_provider.c — ThrottledProvider: a WhatsOnChain provider wrapper that
 * funnels every WoC network call through the process-global rate limiter (via
 * the composed woc_client_t) and layers a fixed fee-per-KB override on top.
 *
 * Port of src/chainSources/throttledProvider.ts (ThrottledProvider,
 * throttledMainnetProvider). The TS class subclasses scrypt-ts's
 * WhatsonchainProvider (node_modules, not this repo); the C port cannot `super.`
 * anything, so it composes a woc_client_t and overrides getFeePerKb /
 * sendRawTransaction.
 *
 * CORRECTNESS PIN (plan.risks / module notes): getFeePerKb returns the override
 * WITHOUT any network call only when the override is PRESENT. Presence is a bool
 * (has_fee_per_kb_override), NEVER a numeric sentinel — 0 sats/KB is a legal
 * distinct value, and the TS `feePerKbOverride !== undefined` check is strict.
 */
#include "chainSources/throttled_provider.h"

#include <stdlib.h>

/* Internal seam exported by woc_client.c (not in the frozen woc_client.h): a
 * rate-limited WoC fee-rate query for the non-override path. */
int woc_client_internal_fee_per_kb(woc_client_t *c, int64_t *out_fee_per_kb);

/* ---- handle ------------------------------------------------------------- */

struct throttled_provider_s {
    woc_client_t *client;                /* borrowed                            */
    int64_t       fee_per_kb_override;
    bool          has_fee_per_kb_override;
};

/* ---- lifecycle ---------------------------------------------------------- */

int throttled_provider_new(const throttled_provider_opts_t *opts,
                           throttled_provider_t **out)
{
    if (opts == NULL || out == NULL || opts->client == NULL) {
        return BNS_EINVAL;
    }
    throttled_provider_t *p = (throttled_provider_t *)calloc(1, sizeof(*p));
    if (p == NULL) {
        return BNS_ENOMEM;
    }
    p->client                 = opts->client;
    p->fee_per_kb_override     = opts->fee_per_kb_override;
    p->has_fee_per_kb_override = opts->has_fee_per_kb_override;
    *out = p;
    return BNS_OK;
}

int throttled_mainnet_provider(woc_client_t *client, throttled_provider_t **out)
{
    /* TS: throttledMainnetProvider() => new ThrottledProvider(mainnet) with NO
     * fee override. */
    throttled_provider_opts_t opts;
    opts.client                  = client;
    opts.fee_per_kb_override      = 0;
    opts.has_fee_per_kb_override  = false;
    return throttled_provider_new(&opts, out);
}

void throttled_provider_free(throttled_provider_t *p)
{
    free(p);
}

/* ---- operations --------------------------------------------------------- */

int throttled_provider_fee_per_kb(throttled_provider_t *p, int64_t *out)
{
    if (p == NULL || out == NULL) {
        return BNS_EINVAL;
    }
    /* TS: if (feePerKbOverride !== undefined) return Promise.resolve(override).
     * Strict presence check — 0 is a legal override, returned with NO network. */
    if (p->has_fee_per_kb_override) {
        *out = p->fee_per_kb_override;
        return BNS_OK;
    }
    /* Else: rate-limited WoC fee query (TS: rateLimited(() => super.getFeePerKb())). */
    return woc_client_internal_fee_per_kb(p->client, out);
}

int throttled_provider_broadcast(throttled_provider_t *p, const char *raw_hex,
                                 char **out_txid)
{
    if (p == NULL || raw_hex == NULL || out_txid == NULL) {
        return BNS_EINVAL;
    }
    /* TS: sendRawTransaction => rateLimited(() => super.sendRawTransaction(...)).
     * The composed client already routes broadcast through the rate limiter. */
    return woc_client_broadcast(p->client, raw_hex, out_txid);
}
