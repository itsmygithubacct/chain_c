/*
 * zk_build_main.c — thin CLI wrapper for the zk-build pipeline. Parses argv
 * (optional ROOT positional) and shells out to circom2 + snarkjs via the
 * library; returns the library's process exit code (0 success, 1 failure),
 * matching scripts/zkBuild.js process.exit semantics.
 *
 * TS origin: scripts/zkBuild.js (main + the top-level .catch).
 */
#include "scripts/zk_build.h"

int main(int argc, char **argv)
{
    int exit_code = 1;
    int rc = zk_build_run(argc, argv, &exit_code);
    if (rc != BNS_OK)
        return 1; /* unexpected internal failure -> nonzero, like the TS catch */
    return exit_code;
}
