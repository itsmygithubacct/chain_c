/*
 * agentd.h — the agentd script LIBRARY entry point: a resumable Pillar-B agent
 * lifecycle CLI (deploy a stateful AgentTea identity UTXO once, then run many
 * metered actions, revoke, or report status across separate process
 * invocations). The logic lives in src/scripts/agentd_lib.c; the main lives in
 * bin/.
 *
 * TS origin: scripts/agentd.ts (agentDeploy, agentAction, agentRevoke + the CLI
 * dispatch). Reads its configuration from environment + a STATE_FILE; see the
 * env list below.
 *
 * Env (TS): BONSAI_NOTARY_HOME, HOME, STATE_FILE, NETWORK,
 * CONFIRM_MAINNET_BROADCAST, ELDER_KEY_FILE, AGENT_KEY_FILE,
 * COUNTERPARTY_KEY_FILE, CHANGE_ADDRESS, RICARDIAN_HASH, ACTION_HASH,
 * PROVENANCE_HASH, AMOUNT, FUND_DEPLOY_KEY_FILE, FUND_ACTION_KEY_FILE,
 * FUND_REVOKE_KEY_FILE.
 *
 * BYTE-EXACTNESS PINS (module notes — the off-chain state advance MUST byte-match
 * AgentTea.executeAction; the receipt preimage field order/encodings are
 * load-bearing): see src/contracts_next agent_tea + agent_tea_tx_builder.
 */
#ifndef BONSAI_SCRIPTS_AGENTD_H
#define BONSAI_SCRIPTS_AGENTD_H

#include "common/error.h"

/* Run the agentd CLI library: dispatches the subcommand (deploy/action/revoke/
 * status) from argv against the environment + STATE_FILE, performing the
 * resumable lifecycle step and persisting the updated STATE_FILE. Dry-run unless
 * CONFIRM_MAINNET_BROADCAST=yes. Returns a process exit code via *out_exit_code.
 * TS: scripts/agentd.ts main dispatch.
 * BNS_OK (ran; see *out_exit_code) / BNS_EINVAL (bad args/env) / propagated errors. */
int agentd_run(int argc, char **argv, int *out_exit_code);

#endif /* BONSAI_SCRIPTS_AGENTD_H */
