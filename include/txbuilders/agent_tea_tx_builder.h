/*
 * txbuilders/agent_tea_tx_builder.h — unsigned-tx builders for the AgentTea
 * contract (executeAction, stake, slashValidator, recover, revoke). Mirrors the
 * RicardianTea builders but adapted to AgentTea shapes: actions carry NO
 * settlement output (cost is metered, not paid), stake raises identity value,
 * slashValidator burn-splits collateral 50/50, recover rotates the agent key.
 * Each reproduces the on-chain hashOutputs-pinned layout.
 *
 * TS origin: src/agentTeaTxBuilder.ts (AgentActionBuilderOpts, bindActionBuilder,
 * bindStakeBuilder, bindSlashValidatorBuilder, bindRecoverBuilder,
 * bindAgentRevokeBuilder).
 *
 * BYTE-EXACTNESS (agentTeaTxBuilder.ts notes):
 *  - next.lockingScript for executeAction/stake/recover is the recreated AgentTea
 *    compiled+stateful script (agent_tea_locking_script); recover ROTATES the
 *    agent PubKey state field so the state encoder must overwrite it.
 *  - feeSats override exists because the contract input dummy-signed unlocking
 *    script is ~15KB; either serialize it identically OR honor an explicit
 *    feeSats to bypass estimation.
 *  - slashValidator/revoke pay the WHOLE identity value out, so without funding
 *    inputs==outputs and fee=0 (won't relay) — source fee from funding and let
 *    change absorb it WITHOUT disturbing the pinned bounty/burn/payout amounts.
 *  - bounty = total/2 (INTEGER floor); burn = total - bounty; burn data is
 *    'SLASHED\0' (8 bytes ending NUL). Use int64 arithmetic, never floating point.
 *  - `now` (nLockTime) is a SIGNED 4-byte CScriptNum (2038 bound), kept 4 bytes.
 */
#ifndef BONSAI_TXBUILDERS_AGENT_TEA_TX_BUILDER_H
#define BONSAI_TXBUILDERS_AGENT_TEA_TX_BUILDER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/bignum.h"
#include "bsv/tx_builder.h"
#include "chainSources/utxo_select.h"
#include "contracts_next/agent_tea.h"

/* The identity UTXO being spent at input[0]. TS: bound instance current UTXO. */
typedef struct {
    char     txid_display[65]; /* 64-hex DISPLAY prev txid + NUL  */
    uint32_t vout;             /* identity output index           */
    uint64_t value;           /* identity UTXO satoshi balance   */
} agent_tea_utxo_t;

/* Funding/change/fee context. `funding` borrowed (or NULL); `change_hash160`
 * (20 bytes) selected by has_change; `fee_sats` override selected by has_fee_sats
 * (mainnet: set large enough to cover the ~15KB executeAction unlocking script so
 * scrypt-ts's pre-sign fee check doesn't race-add fee inputs). TS:
 * AgentActionBuilderOpts {fundingUtxos?, changeAddress?, feeSats?}. */
typedef struct {
    const funding_utxos_t *funding;        /* borrowed funding UTXOs (or NULL)    */
    const uint8_t         *change_hash160; /* 20-byte change addr (or NULL)       */
    bool                   has_change;
    uint64_t               fee_sats;       /* explicit fee override               */
    bool                   has_fee_sats;   /* false => estimate                   */
} agent_tea_builder_opts_t;

/* Build executeAction into `b` (init'd):
 *   input[0] = identity (sequence < 0xffffffff), input[1..] = funding;
 *   output[0]= recreated identity (constant balance, post-spend state),
 *   output[1]= OP_RETURN <receiptHash> (0 sat),
 *   output[2]= change.
 * No counterparty payment output (metered). Sets nLockTime = now. `c` carries the
 * PRE-spend state (txCount pre-increment) for the receipt. `counterparty` is 33
 * raw bytes. TS: bindActionBuilder. BNS_OK / BNS_EINVAL / BNS_ERANGE / BNS_ENOMEM. */
int build_agent_tea_action(const agent_tea_t *c,
                           const agent_tea_utxo_t *identity,
                           const uint8_t counterparty[33],
                           const bn_t *amount,
                           const uint8_t action_hash[32],
                           const uint8_t provenance_hash[32],
                           int64_t now,
                           const agent_tea_builder_opts_t *opts,
                           tx_builder_t *b);

/* Build stake into `b`: output[0] = recreated identity at newBalance =
 * identity->value + add_amount (collateral from funding inputs); change appended.
 * TS: bindStakeBuilder. BNS_OK / BNS_EINVAL / BNS_ERANGE / BNS_ENOMEM. */
int build_agent_tea_stake(const agent_tea_t *c,
                          const agent_tea_utxo_t *identity,
                          const bn_t *add_amount,
                          const agent_tea_builder_opts_t *opts,
                          tx_builder_t *b);

/* Build slashValidator into `b`: output[0] = P2PKH bounty = total/2 (floor) to
 * hash160(reporter); output[1] = OP_RETURN 'SLASHED\0' carrying burn = total -
 * bounty; no state output; change(reporterAddress). `reporter` is 33 raw bytes;
 * `total` is the slashed identity value. TS: bindSlashValidatorBuilder.
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int build_agent_tea_slash_validator(const agent_tea_t *c,
                                    const agent_tea_utxo_t *identity,
                                    const uint8_t reporter[33],
                                    const agent_tea_builder_opts_t *opts,
                                    tx_builder_t *b);

/* Build recover into `b`: output[0] = recreated identity carrying the rotated
 * `new_agent` key (constant balance); output[1] = OP_RETURN <recovery receiptHash>;
 * change appended; lineage continues. `new_agent` is 33 raw bytes; `c` must hold
 * the PRE-rotation state (recoveryCount pre-increment used in the signed message).
 * TS: bindRecoverBuilder. BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int build_agent_tea_recover(const agent_tea_t *c,
                            const agent_tea_utxo_t *identity,
                            const uint8_t new_agent[33],
                            const agent_tea_builder_opts_t *opts,
                            tx_builder_t *b);

/* Build revoke into `b`: single P2PKH output of full balance to hash160(owner)
 * (Elder); no state output; funding sourced for fee; change(ownerAddress).
 * TS: bindAgentRevokeBuilder. BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int build_agent_tea_revoke(const agent_tea_t *c,
                           const agent_tea_utxo_t *identity,
                           const agent_tea_builder_opts_t *opts,
                           tx_builder_t *b);

#endif /* BONSAI_TXBUILDERS_AGENT_TEA_TX_BUILDER_H */
