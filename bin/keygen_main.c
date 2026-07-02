/*
 * keygen_main.c — thin CLI entry for the `keygen` script. Delegates to
 * keygen_run; the logic lives in src/scripts/keygen_lib.c so it is unit-testable.
 */
#include "scripts/keygen.h"

int main(int argc, char **argv)
{
    int exit_code = 0;
    int rc = keygen_run(argc, argv, &exit_code);
    if (rc != BNS_OK) return 1; /* unexpected internal failure */
    return exit_code;
}
