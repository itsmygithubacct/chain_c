/*
 * chain_broadcast.h — shared WoC-backed funding + broadcast helper for the
 * chain_c CLI scripts (bin/deploy, bin/agentd, bin/cpfp, the live-contract
 * spend paths, ...).
 *
 * The contract-spend signing layer (txbuilders/contract_sign.h,
 * scrypt/contract_call.h) produces a fully-signed raw tx hex; the WoC client
 * (chainSources/woc_client.h) talks to WhatsOnChain. This module is the thin
 * glue every LIVE script repeats:
 *
 *   1. construct a libcurl-backed woc_client for a network          (woc_new)
 *   2. list + rank an address's UTXOs and select enough to fund a tx (select_funding)
 *   3. broadcast a signed raw tx and surface a clear error          (send)
 *   4. (optional) size the fee window for a ~28-55 KB contract tx    (fee_window)
 *
 * The funding output is a funding_utxos_t (chainSources/utxo_select.h) — the
 * exact type contract_sign / the txbuilders consume — so the wiring agents can
 * hand it straight to build_contract_deploy / contract_*_sign without a copy.
 *
 * NETWORK NOTE: woc_client.h pins BONSAI_WOC_CLIENT_BASE to the mainnet WoC
 * endpoint, so chain_broadcast_woc_new() only talks to mainnet. The `net`
 * argument selects the bsv_network_t the callers use for address/WIF version
 * bytes and is validated here; BSV_TESTNET currently returns BNS_EUNSUPPORTED
 * (the WoC client has no testnet base) so a caller never silently broadcasts a
 * testnet tx to mainnet.
 */
#ifndef BONSAI_SCRIPTS_CHAIN_BROADCAST_H
#define BONSAI_SCRIPTS_CHAIN_BROADCAST_H

#include <stdint.h>
#include "common/error.h"
#include "bsv/address.h"                 /* bsv_network_t                       */
#include "chainSources/woc_client.h"     /* woc_client_t                        */
#include "chainSources/utxo_select.h"    /* funding_utxos_t, funding_utxo_t     */
#include "chainSources/bsv_fees.h"       /* fee_window_t                        */

/* ---- lifecycle ---------------------------------------------------------- */

/* Construct a libcurl-backed woc_client_t for `net` (mainnet only; see the
 * NETWORK NOTE above). The returned client OWNS an internal http_transport_curl
 * — release BOTH together via chain_broadcast_woc_free(). On failure *out is
 * left NULL.
 *
 * Returns NULL and records `err` on failure; the bonsai_err_t code is in
 * err->code (BNS_EUNSUPPORTED for testnet, BNS_ENET if the curl transport could
 * not be built, BNS_ENOMEM, BNS_EINVAL). Pass NULL `err` if the message is not
 * needed. */
woc_client_t *chain_broadcast_woc_new(bsv_network_t net, bonsai_err_ctx *err);

/* Release a client built by chain_broadcast_woc_new(), including its internal
 * libcurl transport (NULL-safe). Do NOT pass a client built any other way. */
void chain_broadcast_woc_free(woc_client_t *woc);

/* ---- funding selection -------------------------------------------------- */

/* List `funder_address`'s UTXOs via WoC, rank them confirmed-first / descending
 * value (rank_funding_utxos), then greedily select the smallest prefix whose
 * total satoshis >= `need_sats` into *out (caller frees via funding_utxos_free).
 *
 * `need_sats` is the total input value the tx requires (contract identity value
 * + every output + the fee); pass the fee_window recommended/max via
 * chain_broadcast_fee_window() to size it for a contract tx.
 *
 * The selected funding_utxos_t feeds the txbuilders / contract_sign funding
 * inputs directly (tx_id / output_index / satoshis / confirmed).
 *
 * Returns:
 *   BNS_OK         *out holds 1+ UTXOs whose total >= need_sats.
 *   BNS_ENOTFOUND  insufficient confirmed/unconfirmed value (the address total
 *                  is < need_sats); *out is left empty.
 *   BNS_EINVAL     NULL arg or need_sats < 0.
 *   BNS_ENET / BNS_EPARSE / BNS_ENOMEM  from the underlying WoC list call.
 * On any non-OK return *out is zeroed/empty and `err` carries a message. */
int chain_broadcast_select_funding(woc_client_t *woc,
                                   const char *funder_address,
                                   int64_t need_sats,
                                   funding_utxos_t *out,
                                   bonsai_err_ctx *err);

/* ---- broadcast ---------------------------------------------------------- */

/* Broadcast `raw_hex` (a fully-signed contract tx hex from contract_sign) via
 * POST /tx/raw. On success writes the freshly malloc'd, locally computed txid to
 * *out_txid (caller frees). The provider body is checked but never trusted as
 * the state identifier. Thin wrapper over woc_client_broadcast that attaches a clear,
 * verbatim error to `err` on failure.
 *
 * SAFETY: this function performs a REAL mainnet broadcast unconditionally — it
 * does NOT itself check the CONFIRM_MAINNET_BROADCAST gate. The CALLER must call
 * confirm_mainnet_broadcast() (script_support.h) and only invoke this when it
 * returns true; every in-tree caller does. Dry-run paths must not reach here.
 *
 * Returns:
 *   BNS_OK         broadcast accepted; *out_txid is the 64-hex txid.
 *   BNS_EINVAL     NULL arg or empty raw_hex.
 *   BNS_ENET       network error (includes a WoC-tagged 429 rate limit / a
 *                  rejected tx — the WoC error body is the message).
 *   BNS_EPARSE / BNS_ENOMEM  from the underlying broadcast call.
 * *out_txid is set to NULL on any non-OK return. */
int chain_broadcast_send(woc_client_t *woc,
                         const char *raw_hex,
                         char **out_txid,
                         bonsai_err_ctx *err);

/* ---- fee sizing (optional) ---------------------------------------------- */

/* Compute the send-time fee window [min, 3*min] (+ recommended) for a contract
 * tx of `signed_size_bytes` at `fee_per_kb` (typically the WoC fee rate). The
 * stateful contract txs run ~28-55 KB, so the fee dominates funding selection;
 * use out->recommended (or out->max for headroom) as the fee term of
 * chain_broadcast_select_funding's need_sats.
 *
 * Pure arithmetic wrapper over send_time_fee_window (no I/O).
 * Returns BNS_OK / BNS_EINVAL (negative size or rate, or NULL out). */
int chain_broadcast_fee_window(int64_t signed_size_bytes,
                               int64_t fee_per_kb,
                               fee_window_t *out,
                               bonsai_err_ctx *err);

#endif /* BONSAI_SCRIPTS_CHAIN_BROADCAST_H */
