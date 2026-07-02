/*
 * live_agent_smoke_main.c — thin entry point for the liveAgentSmoke CLI.
 *
 * Parses no flags (env-driven, like the TS); delegates to
 * live_agent_smoke_run() and returns its process exit code. Dry-run unless
 * CONFIRM_MAINNET_BROADCAST=yes. TS origin: scripts/liveAgentSmoke.ts.
 */
#include "scripts/live_agent_smoke.h"

int main(int argc, char **argv)
{
    int exit_code = 1;
    int rc = live_agent_smoke_run(argc, argv, &exit_code);
    if (rc != BNS_OK) return 1;
    return exit_code;
}
