/*
 * opreturn_main.c — thin CLI entry for `opreturn`. Logic in opreturn_lib.c.
 */
#include "scripts/opreturn.h"

int main(int argc, char **argv)
{
    int exit_code = 0;
    int rc = opreturn_run(argc, argv, &exit_code);
    if (rc != BNS_OK) return 1;
    return exit_code;
}
