/*
 * woc_client.h — WocClient: the single rate-limited, reliability-hardened
 * WhatsOnChain client for every WoC operation the project performs (raw tx,
 * true tx-state fusion, spent check, UTXO listing, balance, funding selection,
 * broadcast, mempool/confirmation waiting). Encodes documented workarounds for
 * WoC's inconsistent endpoint behavior and funnels every call through the shared
 * process-global rate limiter (woc_rate_limiter.h).
 *
 * TS origin: src/chainSources/wocClient.ts (TxState, TxStatus, interpretTxStatus,
 * WaitOpts, WocClient).
 *
 * WoC QUIRKS pinned here (plan.risks #13, module notes):
 *  - BASE is hard-coded mainnet: "https://api.whatsonchain.com/v1/bsv/main".
 *  - get() order: 404-allow -> 429 (carry status so is_429 fires) -> non-ok.
 *  - interpretTxStatus reads WIRE key 'blockheight' (lowercase) into the
 *    camelCase struct field block_height; Number(confirmations ?? 0).
 *  - txStatus short-circuits to 'confirmed' WITHOUT a raw fetch when
 *    confirmations >= 1 (preserve to match HTTP call counts).
 *  - isOutputSpent: 404 => false (unspent; index may lag); else !!body.txid.
 *  - broadcast strips a SINGLE leading and a SINGLE trailing double-quote only.
 *  - waitForMempool checks rawTx FIRST then deadline (tries at least once);
 *    waitForConfirmation order: confirmation -> unknown/dropped -> deadline.
 */
#ifndef BONSAI_CHAINSOURCES_WOC_CLIENT_H
#define BONSAI_CHAINSOURCES_WOC_CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "chainSources/http_transport.h"
#include "chainSources/utxo_select.h"   /* woc_utxo_t, funding_utxo_t, rank_opts_t */

/* Hard-coded mainnet base. TS: BASE constant. */
#define BONSAI_WOC_CLIENT_BASE "https://api.whatsonchain.com/v1/bsv/main"

/* Default wait-loop timings (ms). TS: WaitOpts defaults. */
#define BONSAI_WOC_MEMPOOL_TIMEOUT_MS   240000
#define BONSAI_WOC_MEMPOOL_INTERVAL_MS  8000
#define BONSAI_WOC_CONFIRM_TIMEOUT_MS   3600000
#define BONSAI_WOC_CONFIRM_INTERVAL_MS  30000

/* A transaction's true network state. TS: TxState. */
typedef enum {
    TX_STATE_CONFIRMED = 0,
    TX_STATE_MEMPOOL,
    TX_STATE_UNKNOWN
} tx_state_t;

/* Fused transaction status. TS: TxStatus {state, confirmations, blockHeight}.
 * block_height is valid only when has_block_height (TS null => has=false). */
typedef struct {
    tx_state_t state;
    int64_t    confirmations;
    int64_t    block_height;     /* valid iff has_block_height                    */
    bool       has_block_height; /* false mirrors TS blockHeight === null         */
} tx_status_t;

/* Polling options. TS: WaitOpts {timeoutMs?, intervalMs?}. Presence flags model
 * the JS optional defaults (an explicit 0 is honored when the has_* flag set). */
typedef struct {
    int64_t timeout_ms;     bool has_timeout_ms;
    int64_t interval_ms;    bool has_interval_ms;
    int64_t confirmations;  bool has_confirmations; /* waitForConfirmation target  */
} woc_wait_opts_t;

/* Injectable sleep (ms) so wait loops are deterministic in tests. NULL => the
 * client's default real sleep. TS: opts.sleep. */
typedef void (*woc_sleep_fn)(void *user, int64_t ms);

/* WocClient construction options. `transport` is REQUIRED (the rate-limited HTTP
 * seam); `sleep`/`sleep_user` override the default sleep. TS: WocClient ctor. */
typedef struct {
    const http_transport_t *transport;
    woc_sleep_fn            sleep;
    void                   *sleep_user;
} woc_client_opts_t;

/* Opaque WocClient handle. TS: WocClient instance. */
typedef struct woc_client_s woc_client_t;

/* ---- pure status fusion ------------------------------------------------- */

/* Pure decision (no I/O): confirmations >= 1 => confirmed (block_height from the
 * 'blockheight' wire value, has=false when absent); else if `raw_present` =>
 * mempool (conf 0, no height); else unknown. `confirmations`/`blockheight` come
 * from the parsed /tx/hash body; `has_blockheight` mirrors presence of the wire
 * key. TS: interpretTxStatus(rawPresent, hashBody). Always BNS_OK. */
int interpret_tx_status(bool raw_present,
                        int64_t confirmations,
                        int64_t blockheight, bool has_blockheight,
                        tx_status_t *out);

/* ---- lifecycle ---------------------------------------------------------- */

/* Construct a WocClient (borrowed transport must outlive it). *out freed via
 * woc_client_free. TS: new WocClient(opts). BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int woc_client_new(const woc_client_opts_t *opts, woc_client_t **out);

/* Release a WocClient (NULL-safe; does not free the borrowed transport). */
void woc_client_free(woc_client_t *c);

/* ---- operations (all rate-limited) -------------------------------------- */

/* GET /tx/{txid}/hex (allow404). On success writes freshly malloc'd trimmed hex
 * to *out_hex (caller frees); 404 sets *out_hex = NULL (the reliable existence
 * check) and returns BNS_OK. TS: rawTx. BNS_OK / BNS_ENET / BNS_ENOMEM. */
int woc_client_raw_tx(woc_client_t *c, const char *txid, char **out_hex);

/* Fetch /tx/hash/{txid} (allow404); short-circuit to confirmed without a raw
 * fetch when confirmations >= 1; else fetch rawTx and fuse via
 * interpret_tx_status. TS: txStatus. BNS_OK / BNS_ENET / BNS_EPARSE. */
int woc_client_tx_status(woc_client_t *c, const char *txid, tx_status_t *out);

/* GET /tx/{txid}/{vout}/spent (allow404): 404 => *out_spent = false (unspent,
 * index may lag); else *out_spent = (body.txid present & non-empty). The TS
 * signature allows null but this path never returns null. TS: isOutputSpent.
 * BNS_OK / BNS_ENET / BNS_EPARSE. */
int woc_client_is_output_spent(woc_client_t *c, const char *txid, uint32_t vout,
                               bool *out_spent);

/* GET /address/{address}/unspent: parse the JSON array into *out (caller frees
 * via... see below). TS: listUtxos. BNS_OK / BNS_ENET / BNS_EPARSE / BNS_ENOMEM. */
typedef struct {
    woc_utxo_t *items;  /* owned array                                          */
    size_t      count;
} woc_utxos_t;

/* Free a listed-UTXO array (NULL-safe). */
void woc_utxos_free(woc_utxos_t *u);

int woc_client_list_utxos(woc_client_t *c, const char *address, woc_utxos_t *out);

/* GET /address/{address}/balance: confirmed/unconfirmed satoshi balances.
 * TS: balance. BNS_OK / BNS_ENET / BNS_EPARSE. */
typedef struct {
    int64_t confirmed;
    int64_t unconfirmed;
} woc_balance_t;

int woc_client_balance(woc_client_t *c, const char *address, woc_balance_t *out);

/* Rank listUtxos via rank_funding_utxos(opts), then return the first candidate
 * whose isOutputSpent == false into *out, setting *out_found. *out_found=false
 * (BNS_OK) when none survive (TS null). `opts` may be NULL. TS: pickFunding.
 * BNS_OK / BNS_ENET / BNS_EPARSE / BNS_ENOMEM. */
int woc_client_pick_funding(woc_client_t *c, const char *address,
                            const rank_opts_t *opts,
                            funding_utxo_t *out, bool *out_found);

/* POST /tx/raw with JSON {"txhex": rawHex}; on success writes the txid with a
 * single leading and single trailing double-quote stripped to *out_txid (freshly
 * malloc'd, caller frees). TS: broadcast. BNS_OK / BNS_ENET (incl. tagged 429) /
 * BNS_EPARSE / BNS_ENOMEM. */
int woc_client_broadcast(woc_client_t *c, const char *raw_hex, char **out_txid);

/* Poll rawTx every interval_ms (default 8000) until non-null, else fail after
 * timeout_ms (default 240000). Checks rawTx FIRST each iteration (tries at least
 * once even if timeout is 0). `opts` may be NULL. TS: waitForMempool.
 * BNS_OK / BNS_ENOTFOUND (timed out) / BNS_ENET. */
int woc_client_wait_for_mempool(woc_client_t *c, const char *txid,
                                const woc_wait_opts_t *opts);

/* Poll txStatus every interval_ms (default 30000) until confirmations >= target
 * (default 1) -> *out; fail if state goes unknown (dropped) or timeout_ms
 * (default 3600000) elapses. Order: confirm -> unknown -> deadline. `opts` may
 * be NULL. TS: waitForConfirmation. BNS_OK / BNS_ENOTFOUND / BNS_ESHREDDED-N/A /
 * BNS_ENET. */
int woc_client_wait_for_confirmation(woc_client_t *c, const char *txid,
                                     const woc_wait_opts_t *opts,
                                     tx_status_t *out);

#endif /* BONSAI_CHAINSOURCES_WOC_CLIENT_H */
