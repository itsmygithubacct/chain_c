/*
 * utxo_select.h — pure, deterministic UTXO ranking: order WhatsOnChain funding
 * candidates best-first (confirmed before unconfirmed, then descending value).
 * Spent/double-spend verification is done elsewhere (woc_client pickFunding);
 * this module only normalizes and orders.
 *
 * TS origin: src/chainSources/utxoSelect.ts (WocUtxo, FundingUtxo, RankOpts,
 * rankFundingUtxos).
 *
 * DETERMINISM PINS (plan.risks / module notes):
 *  - STABLE sort: V8 Array.sort is stable; the C port MUST use a stable sort so
 *    ties (equal confirmed-status AND equal value) keep input order. Do NOT use
 *    qsort (not guaranteed stable).
 *  - minSats uses ?? (nullish): an explicit 0 is honored; only absent => 0. Use
 *    presence flags, NOT numeric sentinels.
 *  - confirmed := (height > 0) (strict; height 0 is unconfirmed). The same > 0
 *    test gates the confirmedOnly filter and the confirmed flag.
 *  - WocUtxo field names (tx_hash, tx_pos, value, height) are the exact WoC
 *    /address/{a}/unspent JSON wire names.
 */
#ifndef BONSAI_CHAINSOURCES_UTXO_SELECT_H
#define BONSAI_CHAINSOURCES_UTXO_SELECT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"

/* BSV money supply cap: 21,000,000 BSV * 1e8 sats/BSV = 2.1e15 sats. No single
 * UTXO value nor any summed funding total may legitimately exceed this. It sits
 * well under 2^53 (so every legal value is exact as a JS/double-sourced number)
 * AND far under INT64/UINT64_MAX, which is what makes the overflow-safe running
 * sum check (`if (v > MAX_MONEY - total) fail`) catch a malicious/buggy
 * WhatsOnChain response stuffed with many near-2^53 `value` entries BEFORE any
 * int64/uint64 accumulator can wrap. Defined here (and mirrored, ifndef-guarded,
 * in bsv/tx_change.h) because common/error.h is the only shared header and is
 * frozen. */
#ifndef BONSAI_MAX_MONEY
#define BONSAI_MAX_MONEY (21000000LL * 100000000LL)  /* 2,100,000,000,000,000 sats */
#endif

/* A UTXO exactly as WoC's /address/{a}/unspent returns it; height 0 ==
 * unconfirmed. TS: WocUtxo {tx_hash, tx_pos, value, height}. */
typedef struct {
    char    tx_hash[65]; /* 64-hex tx id + NUL (WoC "tx_hash")                    */
    uint32_t tx_pos;     /* output index (WoC "tx_pos")                           */
    int64_t value;       /* satoshis (WoC "value")                               */
    int64_t height;      /* block height; 0 => unconfirmed (WoC "height")        */
} woc_utxo_t;

/* Normalized funding UTXO used internally to fund a transaction.
 * TS: FundingUtxo {txId, outputIndex, satoshis, confirmed}. */
typedef struct {
    char     tx_id[65];   /* 64-hex tx id + NUL (== tx_hash)                      */
    uint32_t output_index;/* == tx_pos                                           */
    int64_t  satoshis;    /* == value                                            */
    bool     confirmed;   /* (height > 0)                                         */
} funding_utxo_t;

/* Ranking options. TS: RankOpts {confirmedOnly?, minSats?}. Presence flags model
 * the JS optional/nullish semantics (an explicit min_sats of 0 is honored only
 * when has_min_sats is true; otherwise the default is 0). */
typedef struct {
    bool    confirmed_only;     /* keep only height > 0 when has_confirmed_only   */
    bool    has_confirmed_only; /* false => default (keep all)                    */
    int64_t min_sats;           /* inclusive value floor when has_min_sats        */
    bool    has_min_sats;       /* false => default 0                             */
} rank_opts_t;

/* An owned, ranked funding-candidate list. */
typedef struct {
    funding_utxo_t *items;
    size_t          count;
} funding_utxos_t;

/* Free a ranked list (NULL-safe). */
void funding_utxos_free(funding_utxos_t *f);

/* Overflow-safe funding total. Sums items[0..count).satoshis into *out_total,
 * failing CLOSED with BNS_ERANGE if any single value is out of range
 * (< 0 or > BONSAI_MAX_MONEY) or if the running sum would exceed BONSAI_MAX_MONEY.
 * The check is performed BEFORE each add so the accumulator can never wrap. This
 * is the reusable guard the wallet/broadcast funding-selection callers should use
 * instead of an ad-hoc `total += items[i].satoshis` loop (which silently wraps on
 * a malicious/buggy WhatsOnChain response with many inflated `value` entries).
 * BNS_OK / BNS_EINVAL (NULL out, or NULL items with count>0) / BNS_ERANGE. */
int funding_utxos_total(const funding_utxo_t *items, size_t count,
                        uint64_t *out_total);

/* Rank `utxos`/`n` into *out (caller frees via funding_utxos_free): (1) filter
 * value >= minSats; (2) if confirmedOnly keep height > 0; (3) map to
 * funding_utxo_t (confirmed = height > 0); (4) STABLE sort confirmed-first then
 * descending satoshis. `opts` may be NULL (all defaults). TS: rankFundingUtxos.
 * BNS_OK / BNS_ENOMEM. */
int rank_funding_utxos(const woc_utxo_t *utxos, size_t n,
                       const rank_opts_t *opts, funding_utxos_t *out);

#endif /* BONSAI_CHAINSOURCES_UTXO_SELECT_H */
