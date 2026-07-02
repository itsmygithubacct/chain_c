/*
 * agent_state.h — the resumable AgentState model + its JSON serialization, the
 * STATE_FILE persisted between separate `agentd` process invocations. The
 * state-carry trick is AgentTea.fromTx(rawTx, vout): each step reconstructs the
 * on-chain @prop(true) state from the previous step's raw tx, so nothing but the
 * raw tx (plus this metadata) survives between runs.
 *
 * TS origin: scripts/agentd.ts (STATE_SCHEMA, AgentParams, DEFAULT_PARAMS,
 * AgentState and its nested rabinPub/tip/state/history shapes).
 *
 * BYTE-EXACTNESS PINS (module notes — STATE_FILE must round-trip the TS shape):
 *  - STATE_FILE = JSON.stringify(state, null, 2) with field order EXACTLY as the
 *    AgentState interface declares (schema, network, genesisTxid, ricardianHash,
 *    owner, agentPubKey, counterpartyPubKey, charter, params, rabinPub,
 *    identitySats, tip, state, status, history).
 *  - params = Record<string,string>: bigints stringified (decimal).
 *  - rabinPub.recovery = array of n.toString() (decimal Rabin pubkeys).
 *  - state.{txCount,spentInWindow,windowStart,tier,recoveryCount} are DECIMAL
 *    strings (bigints stringified).
 *  - schema literal = "bonsai.agentd-state/v1".
 */
#ifndef BONSAI_SCRIPTS_AGENT_STATE_H
#define BONSAI_SCRIPTS_AGENT_STATE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"

/* The STATE_FILE schema literal. TS: agentd.ts::STATE_SCHEMA. */
#define BONSAI_AGENT_STATE_SCHEMA "bonsai.agentd-state/v1"

/* The immutable agent policy parameters (bigints). TS: agentd.ts::AgentParams.
 * DEFAULT_PARAMS = {100000, 1000000, 86400, 10000, 50000, 2}. */
typedef struct {
    int64_t per_tx_limit;          /* perTxLimit          default 100000  */
    int64_t daily_limit;           /* dailyLimit          default 1000000 */
    int64_t window_duration;       /* windowDuration      default 86400   */
    int64_t graduation_threshold;  /* graduationThreshold default 10000   */
    int64_t validator_threshold;   /* validatorThreshold  default 50000   */
    int64_t recovery_threshold;    /* recoveryThreshold   default 2       */
} agent_params_t;

/* Populate `out` with DEFAULT_PARAMS. TS: agentd.ts::DEFAULT_PARAMS. */
void agent_params_defaults(agent_params_t *out);

/* The three Rabin pubkeys (decimal strings). `recovery` is an OWNED array of
 * OWNED decimal-string pubkeys. TS: AgentState.rabinPub. */
typedef struct {
    char  *guardian;       /* owned decimal */
    char  *own_validator;  /* owned decimal */
    char **recovery;       /* owned array of owned decimal strings */
    size_t num_recovery;
} agent_rabin_pub_t;

/* The UTXO tip carried between steps. `raw_tx_hex` is the previous step's raw tx.
 * TS: AgentState.tip {txid, vout, rawTxHex}. */
typedef struct {
    char    *txid;        /* owned 64-hex display txid */
    uint32_t vout;
    char    *raw_tx_hex;  /* owned raw tx hex */
} agent_tip_t;

/* The mutable on-chain @prop state (as decimal-string-backed integers). TS:
 * AgentState.state {txCount, spentInWindow, windowStart, tier, recoveryCount}. */
typedef struct {
    int64_t tx_count;
    int64_t spent_in_window;
    int64_t window_start;
    int64_t tier;
    int64_t recovery_count;
} agent_runtime_state_t;

/* Lifecycle status. TS: AgentState.status 'deployed'|'actioned'|'revoked'. */
typedef enum {
    AGENT_STATUS_DEPLOYED = 0,
    AGENT_STATUS_ACTIONED,
    AGENT_STATUS_REVOKED
} agent_status_t;

/* One history entry. TS: AgentState.history[] {op, txid}. */
typedef struct {
    char *op;    /* owned */
    char *txid;  /* owned */
} agent_history_entry_t;

/* The full persisted AgentState. Owns all nested arrays/strings. Network is
 * 'mainnet'|'testnet'. TS: agentd.ts::AgentState. */
typedef struct {
    char                  *schema;              /* owned; == BONSAI_AGENT_STATE_SCHEMA */
    char                  *network;             /* owned "mainnet"|"testnet"           */
    char                  *genesis_txid;        /* owned */
    char                  *ricardian_hash;      /* owned 64-hex */
    char                  *owner;               /* owned pubkey hex */
    char                  *agent_pub_key;       /* owned 66-hex */
    char                  *counterparty_pub_key;/* owned 66-hex */
    char                  *charter;             /* owned */
    agent_params_t         params;              /* serialized as Record<string,string> */
    agent_rabin_pub_t      rabin_pub;
    int64_t                identity_sats;
    agent_tip_t            tip;
    agent_runtime_state_t  state;
    agent_status_t         status;
    agent_history_entry_t *history;             /* owned array */
    size_t                 num_history;
} agent_state_t;

/* Release all owned members of an agent_state_t and zero it (NULL-safe). */
void agent_state_free(agent_state_t *st);

/* Serialize to the STATE_FILE JSON (JSON.stringify(state, null, 2) with the
 * exact declared field order). Writes a freshly malloc'd NUL-terminated string
 * to *out (caller frees). TS: JSON.stringify(state, null, 2).
 * BNS_OK / BNS_ENOMEM. */
int agent_state_to_json(const agent_state_t *st, char **out);

/* Parse a STATE_FILE JSON string into *out (owned; release via agent_state_free).
 * TS: JSON.parse(readFileSync(STATE_FILE)). BNS_OK / BNS_EPARSE / BNS_ENOMEM. */
int agent_state_from_json(const char *json, agent_state_t *out);

#endif /* BONSAI_SCRIPTS_AGENT_STATE_H */
