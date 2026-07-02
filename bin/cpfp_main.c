/*
 * cpfp_main.c — thin CLI entry for the cpfp script. Parses nothing of its own
 * (the script is env-driven, like the TS) and delegates to cpfp_run; returns its
 * process exit code. TS origin: scripts/cpfp.ts top-level main().catch(exit 1).
 */
#include "scripts/cpfp.h"

int main(int argc, char **argv)
{
    int exit_code = 0;
    int rc = cpfp_run(argc, argv, &exit_code);
    if (rc != BNS_OK) return 1; /* unexpected internal failure */
    return exit_code;
}
