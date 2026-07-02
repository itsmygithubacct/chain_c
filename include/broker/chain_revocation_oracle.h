/*
 * chain_revocation_oracle.h — a RevocationOracle backed by the public BSV
 * identity-UTXO chain: forward-walks the spend chain of an identity's output-0
 * from genesis and reports REVOKED iff a terminal spend (revoke/slash, paying a
 * standard P2PKH at output 0 or having no outputs, instead of recreating the
 * contract) is observed; otherwise LIVE. Caches REVOKED permanently and resumes
 * LIVE walks from the last seen tip.
 *
 * TS origin: src/broker/chainRevocationOracle.ts (ChainRevocationOracle).
 *
 * PINS (module notes — must be byte-exact / fail-closed):
 *  - isTerminalSpend(rawTx): outputs[0] absent (zero outputs) => TERMINAL; else
 *    outputs[0].scriptPubKey is the canonical 25-byte P2PKH template
 *    [0x76 0xa9 0x14 <20 bytes> 0x88 0xac] => TERMINAL; else LIVE. (Mirrors
 *    reputation_indexer.h::is_terminal_identity_spend.)
 *  - walk: revoked-cache hit => true; resume txid = liveTip[genesis] ?? genesis;
 *    loop maxHops: spender = get_spending_txid; null => cache liveTip, return
 *    false (LIVE); raw = get_raw_tx(spender); terminal => cache revoked, return
 *    true; else txid = spender. Loop exhaust => error 'exceeded N hops'.
 *  - Constructor REQUIRES source->get_spending_txid != NULL (a spend index).
 *  - FAIL-CLOSED: any HTTP/hop-limit error MUST propagate (non-BNS_OK) so the
 *    KeyBroker treats unknown as deny; never swallow errors.
 */
#ifndef BONSAI_BROKER_CHAIN_REVOCATION_ORACLE_H
#define BONSAI_BROKER_CHAIN_REVOCATION_ORACLE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "reputation_indexer.h"        /* chain_source_t */
#include "broker/key_broker.h"         /* revocation_oracle_t */

/* Default identity output index and forward-walk hop cap. TS: opts defaults. */
#define BONSAI_REVOCATION_DEFAULT_VOUT      0
#define BONSAI_REVOCATION_DEFAULT_MAX_HOPS  100000

/* Construction options. TS: { identityVout?; maxHops? }. The has_* flags model
 * the JS optional defaults (identityVout default 0, maxHops default 100000). */
typedef struct {
    uint32_t identity_vout; bool has_identity_vout;
    size_t   max_hops;      bool has_max_hops;
} chain_revocation_oracle_opts_t;

/* Opaque ChainRevocationOracle handle (owns the revoked-set + liveTip caches).
 * TS: chainRevocationOracle.ts::ChainRevocationOracle. */
typedef struct chain_revocation_oracle_s chain_revocation_oracle_t;

/* Construct over a borrowed chain_source_t (must outlive it). `opts` may be
 * NULL (use defaults). REQUIRES source->get_spending_txid != NULL else
 * BNS_EINVAL (TS: 'ChainRevocationOracle needs ChainSource.getSpendingTxid ...').
 * *out freed via chain_revocation_oracle_free.
 * TS: new ChainRevocationOracle(source, opts). BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int chain_revocation_oracle_new(const chain_source_t *source,
                                const chain_revocation_oracle_opts_t *opts,
                                chain_revocation_oracle_t **out);

/* Release the oracle and its caches (NULL-safe; does not free the source). */
void chain_revocation_oracle_free(chain_revocation_oracle_t *o);

/* isRevoked(genesisTxid): sets *out_revoked. Fail-closed — propagates chain/hop
 * errors as non-BNS_OK. TS: ChainRevocationOracle.isRevoked.
 * BNS_OK / BNS_ENET / BNS_EHOPLIMIT / BNS_EPARSE / BNS_ENOMEM. */
int chain_revocation_oracle_is_revoked(chain_revocation_oracle_t *o,
                                       const char *genesis_txid,
                                       bool *out_revoked);

/* Populate a revocation_oracle_t vtable (key_broker.h) backed by `o`, so the
 * KeyBroker can consume it. `out_vtable->ctx` borrows `o`. BNS_OK / BNS_EINVAL. */
int chain_revocation_oracle_as_oracle(chain_revocation_oracle_t *o,
                                      revocation_oracle_t *out_vtable);

#endif /* BONSAI_BROKER_CHAIN_REVOCATION_ORACLE_H */
