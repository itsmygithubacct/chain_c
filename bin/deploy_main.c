/*
 * deploy_main.c — thin entry point for the deploy CLI. Parses argv (optional
 * ROOT) + environment and delegates to deploy_run(); returns its computed
 * process exit code. TS: scripts/deploy.ts (main().catch(console.error)).
 *
 * Usage:  deploy [ROOT]
 *   ROOT defaults to $BONSAI_CHAIN_ROOT or "." (must contain legal/ + artifacts/).
 *   Env: PRIVATE_KEY (WIF, mainnet), AGENT_PUBKEY, MAX_SLASHING_TARGET,
 *   MIN_SLASH_CONFIRMATIONS, DESIGNATED_VALIDATOR_RABIN_PUBKEY,
 *   VALIDATOR_RABIN_PUBKEY, INITIAL_SLASH_CHECKPOINT_HASH, CONFIRM_MAINNET_BROADCAST.
 *   DRY-RUN unless CONFIRM_MAINNET_BROADCAST=yes.
 */
#include "scripts/deploy.h"

int main(int argc, char **argv)
{
    int exit_code = 1;
    int rc = deploy_run(argc, argv, &exit_code);
    /* deploy_run reports failures via *exit_code (mirroring the TS top-level
     * .catch -> process.exit(1)); a non-OK return is an internal fault. */
    if (rc != BNS_OK) return 1;
    return exit_code;
}
