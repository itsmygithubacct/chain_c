/*
 * txbuilders/ricardian_tea_tx_builder.h — unsigned-tx builders bound to the
 * RicardianTea spending methods (executeTea, revoke, slash, updateSlashCheckpoint).
 * Each builds the EXACT input/output layout the contract's
 * assert(this.ctx.hashOutputs == hash256(outputs)) pins, recomputing the TEA
 * receipt hash off-chain identically to the contract so the spend validates.
 *
 * TS origin: src/ricardianTeaTxBuilder.ts (ReceiptBuilderOpts, bindReceiptBuilder,
 * bindRevokeBuilder, bindSlashBuilder, bindCheckpointBuilder).
 *
 * BYTE-EXACTNESS (ricardianTeaTxBuilder.ts notes):
 *  - The off-chain receipt preimage MUST match the contract (contracts/
 *    ricardian_tea.h ricardian_tea_receipt_preimage).
 *  - next.lockingScript is the recreated contract's compiled+stateful script —
 *    reconstruct from artifacts/ricardianTea.json (ricardian_tea_locking_script);
 *    never recompile sCrypt.
 *  - `now` (nLockTime) is a SIGNED 4-byte CScriptNum (2038 bound), kept 4 bytes
 *    in lockstep with on-chain + the Python verifier; input[0].sequence is set
 *    < 0xffffffff to enable nLocktime.
 *  - amount is the satoshi value of output[1] AND an 8-byte int2ByteString inside
 *    the receipt — keep both forms.
 *  - The contract input unlocking script is huge (~15KB); fee estimation must
 *    serialize a dummy unlocking script of that size to match change, or fee/
 *    change diverges. revoke/slash/checkpoint have NO funding-from here, so they
 *    can yield zero-fee txs unless the caller supplies fee context.
 */
#ifndef BONSAI_TXBUILDERS_RICARDIAN_TEA_TX_BUILDER_H
#define BONSAI_TXBUILDERS_RICARDIAN_TEA_TX_BUILDER_H

#include <stddef.h>
#include <stdint.h>
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/bignum.h"
#include "bsv/tx_builder.h"
#include "chainSources/utxo_select.h"   /* funding_utxos_t */
#include "contracts/ricardian_tea.h"

/* The identity UTXO being spent at input[0]: its prevout + current value, so the
 * builder can recreate the constant-balance state output. TS: the bound
 * instance's current UTXO. */
typedef struct {
    char     txid_display[65]; /* 64-hex DISPLAY prev txid + NUL                  */
    uint32_t vout;             /* identity output index                          */
    uint64_t value;           /* identity UTXO satoshi balance                  */
} ricardian_tea_utxo_t;

/* Optional funding/change context for the executeTea builder (Model D: the
 * payment is funded from the agent's external wallet). `funding` may be NULL/empty;
 * `change_hash160` (20 bytes) is the P2PKH change address (has_change selects it).
 * `fee_per_kb` 0 => BONSAI_FEE_PER_KB default. TS: ReceiptBuilderOpts. */
typedef struct {
    const funding_utxos_t *funding;        /* borrowed funding UTXOs (or NULL)    */
    const uint8_t         *change_hash160; /* 20-byte change addr (or NULL)       */
    bool                   has_change;
    uint64_t               fee_per_kb;     /* 0 => default                        */
} ricardian_tea_builder_opts_t;

/* Build the executeTea unsigned tx into `b` (init'd by the caller):
 *   input[0]  = identity UTXO (sequence < 0xffffffff to enable nLocktime),
 *   input[1..]= agent funding (from opts->funding),
 *   output[0] = recreated identity (constant balance, next state via
 *               ricardian_tea_locking_script over the post-spend state),
 *   output[1] = P2PKH payment of `amount` sats to hash160(counterparty),
 *   output[2] = OP_RETURN <receiptHash> (0 sat),
 *   output[3] = change (if opts->has_change and non-dust).
 * Sets nLockTime = now. `c` carries the PRE-spend state used for the receipt
 * (txCount pre-increment); the builder applies the post-spend state to output[0].
 * `counterparty` is 33 raw bytes. TS: bindReceiptBuilder.
 * BNS_OK / BNS_EINVAL / BNS_ERANGE (insufficient funds) / BNS_ENOMEM. */
int build_ricardian_tea_execute(const ricardian_tea_t *c,
                                const ricardian_tea_utxo_t *identity,
                                const uint8_t counterparty[33],
                                const bn_t *amount,
                                const uint8_t invoice_hash[32],
                                const uint8_t provenance_hash[32],
                                int64_t now,
                                const ricardian_tea_builder_opts_t *opts,
                                tx_builder_t *b);

/* Build the revoke unsigned tx into `b`: single P2PKH output of the full identity
 * balance to hash160(owner); no state output; change(ownerAddress) appended for
 * fee context (zero-fee unless opts supplies funding). TS: bindRevokeBuilder.
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int build_ricardian_tea_revoke(const ricardian_tea_t *c,
                               const ricardian_tea_utxo_t *identity,
                               const ricardian_tea_builder_opts_t *opts,
                               tx_builder_t *b);

/* Build the slash unsigned tx into `b`: single P2PKH output of the full balance
 * to hash160(reporter) as bounty; no state output; change(reporterAddress).
 * `reporter` is 33 raw bytes. (slash() is SUPERSEDED — test parity only.)
 * TS: bindSlashBuilder. BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int build_ricardian_tea_slash(const ricardian_tea_t *c,
                              const ricardian_tea_utxo_t *identity,
                              const uint8_t reporter[33],
                              const ricardian_tea_builder_opts_t *opts,
                              tx_builder_t *b);

/* Build the updateSlashCheckpoint unsigned tx into `b`: output[0] = recreated
 * identity at constant balance carrying the advanced slashCheckpointHash;
 * change(signer default address). TS: bindCheckpointBuilder.
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int build_ricardian_tea_checkpoint(const ricardian_tea_t *c,
                                   const ricardian_tea_utxo_t *identity,
                                   const uint8_t new_checkpoint_hash[32],
                                   const ricardian_tea_builder_opts_t *opts,
                                   tx_builder_t *b);

#endif /* BONSAI_TXBUILDERS_RICARDIAN_TEA_TX_BUILDER_H */
