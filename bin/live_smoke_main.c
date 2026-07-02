/*
 * live_smoke_main.c — thin CLI wrapper for the liveSmoke read-only WoC smoke
 * test. Parses nothing (no args/env), runs the library against real mainnet, and
 * returns its process exit code.
 *
 * TS origin: scripts/liveSmoke.ts (main + the top-level .catch).
 */
#include "scripts/live_smoke.h"

int main(int argc, char **argv)
{
    int exit_code = 1;
    int rc = live_smoke_run(argc, argv, &exit_code);
    if (rc != BNS_OK)
        return 1; /* unexpected internal failure -> nonzero, like the TS catch */
    return exit_code;
}
