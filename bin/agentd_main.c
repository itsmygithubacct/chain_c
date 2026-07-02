/*
 * agentd_main.c — thin entry point for the agentd CLI. Parses argv (the
 * subcommand) + environment and delegates to agentd_run(); returns its computed
 * process exit code. TS: scripts/agentd.ts `if (require.main === module)`.
 */
#include "scripts/agentd.h"

int main(int argc, char **argv)
{
    int exit_code = 1;
    int rc = agentd_run(argc, argv, &exit_code);
    /* agentd_run reports failures via *exit_code (mirroring the TS top-level
     * catch -> process.exit(1)); a non-OK return is an internal fault. */
    if (rc != BNS_OK) return 1;
    return exit_code;
}
