/*
 * throttled_provider.h — ThrottledProvider: a WhatsOnChain provider wrapper that
 * funnels every WoC network call (connect, feeQuote, broadcast, tx-lookup,
 * listUnspent, getBalance) through the process-global rate limiter so the
 * contract framework cannot burst past WoC free-tier limits. Also supports a
 * fixed fee-per-KB override.
 *
 * The TS class subclasses scrypt-ts's WhatsonchainProvider (in node_modules, not
 * this repo); the C port cannot `super.` anything, so it composes a woc_client_t
 * (which already implements the underlying WoC REST behavior + rate limiting)
 * and layers the override on top.
 *
 * TS origin: src/chainSources/throttledProvider.ts (ThrottledProvider,
 * throttledMainnetProvider).
 *
 * CORRECTNESS PIN (plan.risks / module notes): getFeePerKb returns the override
 * WITHOUT any network call only when the override is PRESENT. Model presence
 * with has_fee_per_kb_override (a bool), NEVER a numeric sentinel — 0 sats/KB is
 * a legal distinct value. The undefined check in TS is strict.
 */
#ifndef BONSAI_CHAINSOURCES_THROTTLED_PROVIDER_H
#define BONSAI_CHAINSOURCES_THROTTLED_PROVIDER_H

#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "chainSources/woc_client.h"

/* Construction options. `client` is the underlying rate-limited WoC client
 * (borrowed; must outlive the provider). The fee override is honored only when
 * has_fee_per_kb_override is true (so 0 is distinct from "absent").
 * TS: ThrottledProvider(network, feePerKbOverride?). */
typedef struct {
    woc_client_t *client;
    int64_t       fee_per_kb_override;     /* used iff has_fee_per_kb_override     */
    bool          has_fee_per_kb_override; /* false => query the fee endpoint      */
} throttled_provider_opts_t;

/* Opaque ThrottledProvider handle. TS: ThrottledProvider instance. */
typedef struct throttled_provider_s throttled_provider_t;

/* Construct a ThrottledProvider. *out freed via throttled_provider_free.
 * TS: new ThrottledProvider(...). BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int throttled_provider_new(const throttled_provider_opts_t *opts,
                           throttled_provider_t **out);

/* Factory: a mainnet ThrottledProvider over `client` with NO fee override.
 * TS: throttledMainnetProvider(). BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int throttled_mainnet_provider(woc_client_t *client, throttled_provider_t **out);

/* Release a ThrottledProvider (NULL-safe; does not free the borrowed client). */
void throttled_provider_free(throttled_provider_t *p);

/* Effective fee-per-KB: returns the override immediately (no network) when one
 * was set; otherwise routes a rate-limited WoC fee query. TS: getFeePerKb.
 * BNS_OK / BNS_ENET / BNS_EPARSE. */
int throttled_provider_fee_per_kb(throttled_provider_t *p, int64_t *out);

/* Rate-limited broadcast (delegates to the underlying client). On success writes
 * the freshly malloc'd txid to *out_txid (caller frees). TS: sendRawTransaction.
 * BNS_OK / BNS_ENET / BNS_EPARSE / BNS_ENOMEM. */
int throttled_provider_broadcast(throttled_provider_t *p, const char *raw_hex,
                                 char **out_txid);

#endif /* BONSAI_CHAINSOURCES_THROTTLED_PROVIDER_H */
