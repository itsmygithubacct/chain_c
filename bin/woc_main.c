/*
 * woc_main.c — thin entry point for the `woc` CLI. Parses nothing beyond argc/
 * argv and delegates to woc_run(); the dispatch logic lives in
 * src/scripts/woc_lib.c so it is unit-testable with an injected HTTP transport.
 *
 * TS origin: scripts/woc.ts (the main() + top-level .catch()).
 */
#include <stdio.h>
#include "scripts/woc.h"

int main(int argc, char **argv) {
    int exit_code = 1;
    /* transport = NULL -> woc_run builds the default libcurl transport. */
    int rc = woc_run(argc, argv, NULL, &exit_code);
    if (rc != BNS_OK) {
        /* Should not happen: woc_run reports outcomes via exit_code. */
        fprintf(stderr, "woc error: %s\n", bns_err_name((bonsai_err_t)rc));
        return 1;
    }
    return exit_code;
}
