/*
 * live_agent_smoke.h — the liveAgentSmoke script LIBRARY entry point: a live
 * MAINNET end-to-end lifecycle smoke for the Pillar B AgentTea sovereign-agent
 * identity contract (deploy a 1-sat identity UTXO, run one metered executeAction
 * below the validator threshold committing a TEA receipt hash in OP_RETURN, then
 * revoke via the Elder kill switch). Dry-run by default; CONFIRM_MAINNET_BROADCAST
 * =yes to broadcast. The most algorithm-dense script — drives scrypt-ts contract
 * deploy/method-call with custom tx builders. Logic in
 * src/scripts/live_agent_smoke_lib.c.
 *
 * TS origin: scripts/liveAgentSmoke.ts (main + waitSeen/waitConfirmed/
 * loadOrCreateEphemeral helpers).
 *
 * Env (TS): BONSAI_NOTARY_HOME, HOME, KEY_FILE, EPHEMERAL_FILE,
 * CONFIRM_MAINNET_BROADCAST, SKIP_ACTION.
 *
 * PINS (module notes): charter constants PER_TX=100000, DAILY=1000000,
 * WINDOW=86400, GRAD=10000, VAL_THRESHOLD=50000, ACTION_COST=1000,
 * IDENTITY_SATS=1, recoveryThreshold=2; FEE_PER_KB=100; ricardianHash =
 * sha256(toByteString(charter,true)) (NON-canonical, per-run); next-state
 * txCount=1, spent=ACTION_COST, windowStart=now=floor(Date.now()/1000)-600;
 * lockTime=now, input[0] sequence=0. ACTION_FEE=sendTimeFeeWindow(31000,100),
 * REVOKE_FEE=sendTimeFeeWindow(15300,100).
 */
#ifndef BONSAI_SCRIPTS_LIVE_AGENT_SMOKE_H
#define BONSAI_SCRIPTS_LIVE_AGENT_SMOKE_H

#include "common/error.h"

/* Run the liveAgentSmoke library from the environment. Dry-run unless
 * CONFIRM_MAINNET_BROADCAST=yes. Returns a process exit code via *out_exit_code.
 * TS: scripts/liveAgentSmoke.ts main. BNS_OK (ran; see *out_exit_code) /
 * propagated errors. */
int live_agent_smoke_run(int argc, char **argv, int *out_exit_code);

#endif /* BONSAI_SCRIPTS_LIVE_AGENT_SMOKE_H */
