/*
 * bonsai_third_entry_main.c — thin CLI wrapper around bonsai_third_entry_run().
 *
 * TS origin: scripts/bonsaiThirdEntry.ts (main + main().catch -> process.exit(1)).
 * DRY-RUN by default; broadcasts only when CONFIRM_MAINNET_BROADCAST=yes.
 */
#include <stdio.h>
#include "scripts/bonsai_third_entry.h"
#include "common/error.h"

int main(int argc, char **argv)
{
    int exit_code = 1;
    int rc = bonsai_third_entry_run(argc, argv, &exit_code);
    if (rc != BNS_OK) {
        /* Unexpected internal failure not captured as an exit code. */
        return 1;
    }
    return exit_code;
}
