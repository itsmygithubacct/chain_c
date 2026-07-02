/*
 * bonsai_third_entry.h — the bonsaiThirdEntry script LIBRARY entry point: a LIVE
 * Pillar-B lifecycle smoke test (deploy -> executeAction -> revoke chain of three
 * mainnet transactions), committing the Bonsai TEA receipt hash in a real
 * OP_RETURN Third Entry. Dry-run by default; broadcasts only when
 * CONFIRM_MAINNET_BROADCAST=yes. Logic in src/scripts/bonsai_third_entry_lib.c.
 *
 * TS origin: scripts/bonsaiThirdEntry.ts (main).
 *
 * Env (TS): BONSAI_NOTARY_HOME, HOME, KEY_FILE, EPHEMERAL_FILE, ELDER_KEY_FILE,
 * AGENT_KEY_FILE, COUNTERPARTY_KEY_FILE, FUND_DEPLOY_KEY_FILE,
 * FUND_ACTION_KEY_FILE, FUND_REVOKE_KEY_FILE, CHANGE_ADDRESS, RICARDIAN_HASH,
 * ACTION_HASH, PROVENANCE_HASH, CONFIRM_MAINNET_BROADCAST, SKIP_ACTION.
 *
 * PINS (module notes): hard-coded policy PER_TX=100000, DAILY=1000000,
 * WINDOW=86400, GRAD=10000, VAL_THRESHOLD=50000, ACTION_COST=1000,
 * recoveryThreshold=2, IDENTITY_SATS=1, FEE_PER_KB=100. Manual first-action
 * advance: txCount=1, spent=1000, windowStart=now=floor(Date.now()/1000)-600.
 * The receipt preimage is identical to agentTeaTxBuilder (byte layout
 * load-bearing).
 */
#ifndef BONSAI_SCRIPTS_BONSAI_THIRD_ENTRY_H
#define BONSAI_SCRIPTS_BONSAI_THIRD_ENTRY_H

#include "common/error.h"

/* Run the bonsaiThirdEntry live smoke library from the environment. Dry-run
 * unless CONFIRM_MAINNET_BROADCAST=yes. Returns a process exit code via
 * *out_exit_code. TS: scripts/bonsaiThirdEntry.ts main.
 * BNS_OK (ran; see *out_exit_code) / propagated errors. */
int bonsai_third_entry_run(int argc, char **argv, int *out_exit_code);

#endif /* BONSAI_SCRIPTS_BONSAI_THIRD_ENTRY_H */
