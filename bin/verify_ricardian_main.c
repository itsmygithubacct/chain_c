/*
 * verify_ricardian_main.c — thin entry for the verifyRicardian CLI.
 * Parses argv (optional ROOT) and delegates to verify_ricardian_run; returns its
 * CI exit code. TS: scripts/verifyRicardian.ts (main + process.exit).
 *
 * Usage:  verify_ricardian [ROOT]
 *   ROOT defaults to $BONSAI_CHAIN_ROOT or "." (must contain legal/ + artifacts/).
 *   On-chain mode (opt-in) also reads: VERIFY_IDENTITY_TXID, IDENTITY_KIND,
 *   ELDER_PUBKEY, AGENT_PUBKEY, DESIGNATED_VALIDATOR_RABIN_PUBKEY,
 *   VALIDATOR_RABIN_PUBKEY, and (default RicardianTea) MAX_SLASHING_TARGET,
 *   MIN_SLASH_CONFIRMATIONS, INITIAL_SLASH_CHECKPOINT_HASH, or (agenttea)
 *   RICARDIAN_HASH, RECOVERY_RABIN_PUBKEYS, RECOVERY_THRESHOLD; plus WOC_NETWORK.
 */
#include <stdio.h>
#include "scripts/verify_ricardian.h"

int main(int argc, char **argv)
{
    int exit_code = 1;
    int rc = verify_ricardian_run(argc, argv, &exit_code);
    if (rc != BNS_OK) {
        /* an internal fault before the run produced a CI code */
        return 1;
    }
    return exit_code;
}
