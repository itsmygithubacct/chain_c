/*
 * contracts_next/agent_tea.h — AgentTea, the Pillar-B sovereign-agent identity
 * STATEFUL contract (a fixed/repurposed RicardianTea): metered autonomous-agent
 * identity with per-tx/window caps, four-entry receipts, input-0 pinning, stake
 * top-up, cross-agent validator slashing, and M-of-3 social-recovery key rotation.
 *
 * The C port reconstructs the lockingScript from the compiled AgentTea artifact
 * (under artifacts/src/contracts-next/agentTea.json) by substituting the 12 ctor
 * @props + the 6 mutable state props as trailing state (scrypt/script_codec.h).
 * It also owns the byte-exact attestation / recovery / receipt preimages and the
 * from_tx state DECODER that resumable agentd needs.
 *
 * TS origin: src/contracts-next/agentTea.ts (AgentTea: 11 immutable + 1 mutable
 * (agent) ctor-set @props, 6 @prop(true) state fields, checkInputZero,
 * attestationMsg, recoveryMsg, executeAction, stake, slashValidator, recover,
 * revoke).
 *
 * DETERMINISM PINS (agentTea.ts notes — hardest of the four):
 *  (1) int2ByteString(validatorPubKey) with NO size arg = BN.toSM minimal
 *      sign-magnitude LE (num2bin.h int2bytestring_minimal) — must match the
 *      off-chain builder exactly in attestationMsg AND slashValidator.
 *  (2) executeAction commits txCount at PRE-increment in the receipt.
 *  (3) recover: recoveryMsg signs the PRE-increment recoveryCount; recoveryCount
 *      is incremented AFTER the sig check; the receipt embeds the CURRENT (not
 *      incremented) txCount; the recreated state serializes the ROTATED agent key.
 *  (4) checkInputZero: this.prevouts (36 bytes/input: 32B txid in stored/internal
 *      order + 4B LE vout) hash256 == hashPrevouts; slice[0:36] == own outpoint.
 *  (5) int2ByteString(now,4) signed 4-byte nLocktime (2038 bound) in lockstep
 *      with the builder + Python verifier.
 *  (6) 'SLASHED\0' burn data is 8 bytes ending in a literal NUL (0x00).
 *  (7) state output recreation reproduces scrypt-ts stateful serialization from
 *      the compiled artifact (script_codec.h build_state).
 *  (8) bounty/burn use INTEGER floor division.
 *  (9) agent pubkey is mutable, committed at its CURRENT value.
 */
#ifndef BONSAI_CONTRACTS_NEXT_AGENT_TEA_H
#define BONSAI_CONTRACTS_NEXT_AGENT_TEA_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/bignum.h"
#include "scrypt/scrypt_contract.h"

/* Fixed-size charter recovery-guardian set (M-of-3). TS: FixedArray<RabinPubKey,3>. */
#define BONSAI_AGENT_TEA_RECOVERY_KEYS 3

/* The 12 AgentTea constructor arguments, in @prop DECLARATION ORDER (== locking-
 * script substitution order). owner/agent PubKeys are 33-byte compressed SEC
 * bytes; ricardianHash is 32 raw bytes; policy/threshold params and the two
 * Rabin pubkeys + the 3 recovery Rabin pubkeys are bn_t. Owns its members;
 * agent_tea_params_free releases them. TS: agentTea.ts constructor. */
typedef struct {
    byte_buf_t owner;                      /* 1. owner PubKey (33B), Elder         */
    byte_buf_t agent;                      /* 2. agent PubKey (33B), rotated by recover */
    byte_buf_t ricardian_hash;             /* 3. ricardianHash Sha256 (32B)        */
    bn_t      *per_tx_limit;               /* 4. perTxLimit                        */
    bn_t      *daily_limit;                /* 5. dailyLimit                        */
    bn_t      *window_duration;            /* 6. windowDuration                    */
    bn_t      *graduation_threshold;       /* 7. graduationThreshold               */
    bn_t      *validator_threshold;        /* 8. validatorThreshold                */
    bn_t      *designated_validator_pubkey;/* 9. designatedValidatorPubKey (Rabin n)*/
    bn_t      *validator_rabin_pubkey;     /* 10. validatorRabinPubKey (Rabin n)   */
    bn_t      *recovery_keys[BONSAI_AGENT_TEA_RECOVERY_KEYS]; /* 11. recoveryKeys[3] (Rabin n) */
    bn_t      *recovery_threshold;         /* 12. recoveryThreshold (M of 3)       */
} agent_tea_params_t;

/* The 6 mutable @prop(true) state fields, in declaration order. Genesis:
 * txCount=0, spentInWindow=0, windowStart=0, tier=1, recoveryCount=0; `agent`
 * is the (mutable) ctor agent and lives in params. Owns its members.
 * TS: agentTea.ts @prop(true) txCount/spentInWindow/windowStart/tier/recoveryCount
 * (+ the mutable `agent` carried in params). */
typedef struct {
    bn_t *tx_count;          /* txCount                                          */
    bn_t *spent_in_window;   /* spentInWindow                                    */
    bn_t *window_start;      /* windowStart                                      */
    bn_t *tier;              /* 1=agent, 2=bonded validator                      */
    bn_t *recovery_count;    /* recoveryCount (anti-replay)                       */
} agent_tea_state_t;

/* A live AgentTea instance. `agent` (the mutable operating key) lives in params
 * and is overwritten by recover(); state holds the 5 numeric mutable fields.
 * The artifact is borrowed. TS: an instantiated AgentTea SmartContract. */
typedef struct {
    const scrypt_artifact_t *artifact;  /* borrowed compiled agentTea.json        */
    agent_tea_params_t       params;    /* owned ctor args (incl. mutable agent)  */
    agent_tea_state_t        state;     /* owned current numeric state            */
} agent_tea_t;

/* ---- lifecycle ---------------------------------------------------------- */

void agent_tea_params_free(agent_tea_params_t *p);
void agent_tea_state_free(agent_tea_state_t *s);
void agent_tea_free(agent_tea_t *c);

/* Initialise genesis state (txCount/spentInWindow/windowStart/recoveryCount=0,
 * tier=1). TS: agentTea.ts constructor state init. BNS_OK / BNS_ENOMEM. */
int agent_tea_genesis_state(agent_tea_state_t *out);

/* Compute the POST-action state (init's `next`, caller frees via agent_tea_state_free) from
 * `c->state` exactly as the on-chain executeAction does: window roll, spentInWindow += amount,
 * txCount += 1, tier graduation. The recreated output[0] state MUST use this or the contract's
 * hashOutputs assertion fails. `now` is the tx nLockTime. BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int agent_tea_apply_action(const agent_tea_t *c, const bn_t *amount, int64_t now,
                           agent_tea_state_t *next);

/* ---- locking-script reconstruction -------------------------------------- */

/* Reconstruct the locking script bytes into `out` (init'd): substitutes the 12
 * ctor args (ctor encoders) and appends the state suffix (state encoders).
 * Delegates to scrypt/script_codec.h. BNS_OK / BNS_EINVAL / BNS_EPARSE / BNS_ENOMEM. */
int agent_tea_locking_script(const agent_tea_t *c, bool is_genesis,
                             byte_buf_t *out);

/* As above, but `state_agent` (when non-NULL, 33 raw bytes) overrides ONLY the
 * @state agent push (state[0]); ctor[1] (the genesis agent embedded in the
 * immutable code part) keeps `c->params.agent`. recover() rotates only the @state
 * copy — the contract's getStateScript freezes the code part — so a full rebuild
 * with the new key in BOTH places would corrupt ctor[1] and fail hashOutputs.
 * Pass NULL for the normal (executeAction/stake/genesis) case. */
int agent_tea_locking_script_ex(const agent_tea_t *c, bool is_genesis,
                                const byte_buf_t *state_agent, byte_buf_t *out);

/* ---- resumable state DECODER (for agentd) ------------------------------- */

/* DECODE the mutable state (txCount, spentInWindow, windowStart, tier,
 * recoveryCount, and the rotated agent PubKey) out of an EXISTING locking
 * script's stateful state suffix, so a restarted agentd can resume the lineage
 * WITHOUT re-running the constructor. Parses the state blob appended after the
 * compiled code part (NOT the inline '6a' of the code template). Fills *out_state
 * (caller frees via agent_tea_state_free) and, if `out_agent` != NULL, appends
 * the decoded 33-byte agent PubKey to it (init'd). `locking_script`/`len` are the
 * raw on-chain locking script bytes. TS: AgentTea.fromTx state decode.
 * BNS_OK / BNS_EPARSE (malformed state suffix) / BNS_ENOMEM. */
int agent_tea_from_tx(const uint8_t *locking_script, size_t len,
                      const scrypt_artifact_t *artifact,
                      agent_tea_state_t *out_state, byte_buf_t *out_agent);

/* ---- byte-exact preimage builders --------------------------------------- */

/* Build the guardian attestation preimage appended to `out` (init'd):
 *   tag || ricardianHash(32) || agent(33) || int2ByteString(validatorPubKey)
 *   || int2ByteString(amount,8) || int2ByteString(attestedLimit,8) || receiptHash(32)
 * validatorPubKey uses the ONE-ARG minimal encoder; amount/attestedLimit use the
 * TWO-ARG fixed 8-byte LE encoder. TS: AgentTea.attestationMsg.
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int agent_tea_attestation_msg(const uint8_t ricardian_hash[32],
                              const uint8_t agent[33],
                              const bn_t *validator_pubkey,
                              const bn_t *amount,
                              const bn_t *attested_limit,
                              const uint8_t receipt_hash[32],
                              byte_buf_t *out);

/* Build the recovery authorization preimage appended to `out` (init'd):
 * domain-separated tag || ricardianHash(32) || newAgent(33) ||
 * int2ByteString(recoveryCount,...) using the PRE-increment recoveryCount the
 * guardians sign against. `new_agent` is 33 raw bytes. TS: AgentTea.recoveryMsg.
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int agent_tea_recovery_msg(const uint8_t ricardian_hash[32],
                           const uint8_t new_agent[33],
                           const bn_t *recovery_count,
                           byte_buf_t *out);

/* Build the executeAction receipt preimage appended to `out` (init'd) exactly as
 * the contract assembles it before sha256, using state.tx_count at PRE-increment
 * and `now` as int2ByteString(now,4) signed. `counterparty` is 33 raw bytes;
 * action/provenance hashes are 32 raw bytes. TS: AgentTea.executeAction receipt.
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int agent_tea_receipt_preimage(const agent_tea_t *c,
                               const uint8_t counterparty[33],
                               const bn_t *amount,
                               const uint8_t action_hash[32],
                               const uint8_t provenance_hash[32],
                               int64_t now,
                               byte_buf_t *out);

/* sha256(executeAction receipt preimage) as freshly malloc'd 64-hex (*out_hex;
 * caller frees). TS: AgentTea receiptHash. BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int agent_tea_receipt_hash(const agent_tea_t *c,
                           const uint8_t counterparty[33],
                           const bn_t *amount,
                           const uint8_t action_hash[32],
                           const uint8_t provenance_hash[32],
                           int64_t now,
                           char **out_hex);

#endif /* BONSAI_CONTRACTS_NEXT_AGENT_TEA_H */
