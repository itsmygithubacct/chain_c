/*
 * pay_main.c — thin CLI entry for the `pay` script. Logic in src/scripts/pay_lib.c.
 */
#include "scripts/pay.h"

int main(int argc, char **argv)
{
    int exit_code = 0;
    int rc = pay_run(argc, argv, &exit_code);
    if (rc != BNS_OK) return 1;
    return exit_code;
}
