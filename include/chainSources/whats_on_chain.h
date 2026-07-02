/*
 * whats_on_chain.h — WhatsOnChainSource: a live chain_source_t implementation
 * backed by the WhatsOnChain (WoC) REST API over an injectable http_transport_t.
 *
 * Implements the chain_source_t vtable (reputation_indexer.h) — getRawTx,
 * getTime, and the OPTIONAL getSpendingTxid — so the reputation indexer can
 * score reputation against real BSV main/test data. The transport is injected so
 * unit tests can stub responses without network.
 *
 * TS origin: src/chainSources/whatsOnChain.ts (WhatsOnChainSource,
 * WhatsOnChainOpts).
 *
 * WoC QUIRKS pinned here (plan.risks #13, module notes):
 *  - URL paths are interpolated RAW (no URL-encoding): "/tx/{txid}/hex",
 *    "/tx/hash/{txid}", "/tx/{txid}/{vout}/spent". Base default
 *    "https://api.whatsonchain.com/v1/bsv/{network}", network default "main".
 *  - getRawTx returns the body text TRIMMED (no trailing newline) so downstream
 *    byte-exact hashing of the raw hex matches.
 *  - getTime uses blocktime || time (JS truthy): a present-but-ZERO blocktime
 *    falls through to time; both zero/absent => loud error (never returns 0).
 *  - getSpendingTxid: HTTP 404 => NULL (unspent sentinel) BEFORE the !ok check;
 *    other non-2xx => error; else body.txid ?? NULL.
 *  - The woc-api-key header is sent ONLY when an API key is present.
 */
#ifndef BONSAI_CHAINSOURCES_WHATS_ON_CHAIN_H
#define BONSAI_CHAINSOURCES_WHATS_ON_CHAIN_H

#include <stddef.h>
#include "common/error.h"
#include "chainSources/http_transport.h"
#include "reputation_indexer.h"   /* chain_source_t */

/* Default WoC base URL template (network is substituted). TS: base default. */
#define BONSAI_WOC_BASE_TEMPLATE "https://api.whatsonchain.com/v1/bsv/%s"

/* WoC network selector. TS: 'main' | 'test'. */
typedef enum {
    WOC_NETWORK_MAIN = 0, /* default */
    WOC_NETWORK_TEST
} woc_network_t;

/* Construction options. TS: WhatsOnChainOpts {network?, baseUrl?, fetchFn?,
 * apiKey?}. A NULL base_url uses the network-derived default; a NULL api_key
 * sends no woc-api-key header; `transport` is REQUIRED (the injected fetch). */
typedef struct {
    woc_network_t           network;   /* default WOC_NETWORK_MAIN                 */
    const char             *base_url;  /* NULL => derive from network             */
    const char             *api_key;   /* NULL => no woc-api-key header           */
    const http_transport_t *transport; /* injected HTTP transport (required)      */
} whats_on_chain_opts_t;

/* Opaque WhatsOnChainSource handle. TS: WhatsOnChainSource instance. */
typedef struct whats_on_chain_s whats_on_chain_t;

/* Construct a WhatsOnChainSource from `opts` (copies what it needs; the borrowed
 * transport must outlive the source). *out is freed via whats_on_chain_free.
 * TS: new WhatsOnChainSource(opts). BNS_OK / BNS_EINVAL (no transport) /
 * BNS_ENOMEM. */
int whats_on_chain_new(const whats_on_chain_opts_t *opts, whats_on_chain_t **out);

/* Release a WhatsOnChainSource (NULL-safe; does not free the borrowed transport). */
void whats_on_chain_free(whats_on_chain_t *src);

/* Populate a chain_source_t vtable backed by `src` (so the indexer can consume
 * it). The returned vtable's get_spending_txid is non-NULL for this adapter
 * (forward walking is supported). `out_vtable->ctx` borrows `src`.
 * TS: WhatsOnChainSource implements ChainSource. BNS_OK / BNS_EINVAL. */
int whats_on_chain_as_source(whats_on_chain_t *src, chain_source_t *out_vtable);

#endif /* BONSAI_CHAINSOURCES_WHATS_ON_CHAIN_H */
