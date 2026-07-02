/*
 * mock_chain_source.h — an in-memory chain_source_t (reputation_indexer.h) for
 * unit tests, the C port of the TS FakeChain / MockChain classes used by
 * identityChainView / chainRevocationOracle / reputationIndexer / forwardWalk
 * / whatsOnChain tests.
 *
 * Backed by three tables:
 *   - {txid -> rawHex}        (get_raw_tx)
 *   - {txid -> time}          (get_time; falls back to a default)
 *   - {(txid,vout) -> spender|null} (get_spending_txid; NULL/unset => unspent)
 *
 * Build entries with the register API, then take a chain_source_t vtable via
 * mock_chain_source_as_source(). The vtable's get_spending_txid can be NULLed
 * (mock_chain_source_disable_spend_index) to model spend-index-less providers
 * (e.g. WhatsOnChain) so the "requires spend index" guards can be exercised.
 *
 * Call-count fields mirror MockChain.calls so tests can assert lookup behaviour.
 */
#ifndef BONSAI_TEST_MOCK_CHAIN_SOURCE_H
#define BONSAI_TEST_MOCK_CHAIN_SOURCE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "reputation_indexer.h"   /* chain_source_t */

/* Opaque in-memory chain. Owns its tables + every string registered. */
typedef struct mock_chain_source_s mock_chain_source_t;

/* ---- lifecycle ---------------------------------------------------------- */

/* Allocate an empty mock chain with default get_time = `default_time`
 * (TS FakeChain returns a constant 1_700_000_000; pass that for parity).
 * Returns NULL on OOM. */
mock_chain_source_t *mock_chain_source_new(int64_t default_time);

/* Release the mock and all owned strings (NULL-safe). */
void mock_chain_source_free(mock_chain_source_t *m);

/* ---- builder API -------------------------------------------------------- */

/* Register {txid -> raw_hex} (both copied). Overwrites an existing entry.
 * TS: FakeChain.raw.set / MockChain.raw.set. BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int mock_chain_source_add_raw(mock_chain_source_t *m, const char *txid,
                              const char *raw_hex);

/* Register a per-txid time override (else get_time returns default_time).
 * TS: a per-tx getTime. BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int mock_chain_source_set_time(mock_chain_source_t *m, const char *txid,
                               int64_t time);

/* Record that `spender` spends (txid,vout). `spender` NULL => explicitly
 * unspent (still a recorded sentinel). TS: spend.set(`${txid}:${vout}`, next)
 * / MockChain.link. BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int mock_chain_source_link(mock_chain_source_t *m, const char *txid,
                           uint32_t vout, const char *spender);

/* Convenience: build a "recreated identity" state tx (output[0]=OP_1, optional
 * OP_RETURN receipt) for `txid` and register its raw hex.
 * TS: MockChain.addStateTx / FakeChain.raw.set(rawTx(RECREATED, r)).
 * `receipt_hash_hex` NULL => no receipt. BNS_OK / BNS_EPARSE / BNS_ENOMEM. */
int mock_chain_source_add_state_tx(mock_chain_source_t *m, const char *txid,
                                   const char *receipt_hash_hex);

/* Convenience: build a terminal P2PKH-payout tx for `txid` and register it.
 * TS: MockChain.addTerminalTx. BNS_OK / BNS_ENOMEM. */
int mock_chain_source_add_terminal_tx(mock_chain_source_t *m, const char *txid);

/* Convenience: register a no-outputs (degenerate terminal) tx for `txid`.
 * TS: MockChain.addNoOutputTx. BNS_OK / BNS_ENOMEM. */
int mock_chain_source_add_no_output_tx(mock_chain_source_t *m, const char *txid);

/* ---- fault injection / introspection ------------------------------------ */

/* When set, the NEXT get_raw_tx OR get_spending_txid call returns BNS_ENET and
 * clears the flag. TS: MockChain.failNext. */
void mock_chain_source_fail_next(mock_chain_source_t *m, bool fail);

/* Per-method call counters (TS: MockChain.calls). Pass NULL to skip an out. */
void mock_chain_source_calls(const mock_chain_source_t *m,
                             size_t *out_get_raw_tx,
                             size_t *out_get_spending_txid,
                             size_t *out_get_time);

/* ---- vtable export ------------------------------------------------------ */

/* Fill *out with a chain_source_t whose ctx borrows `m` (m must outlive it).
 * get_spending_txid is wired by default. BNS_OK / BNS_EINVAL. */
int mock_chain_source_as_source(mock_chain_source_t *m, chain_source_t *out);

/* NULL out->get_spending_txid (model a provider with no spend index, e.g. the
 * WhatsOnChain adapter) so the indexer/oracle's "needs spend index" guards
 * (BNS_EINVAL) can be tested. Call after mock_chain_source_as_source. */
void mock_chain_source_disable_spend_index(chain_source_t *out);

#endif /* BONSAI_TEST_MOCK_CHAIN_SOURCE_H */
