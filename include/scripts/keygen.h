/*
 * scripts/keygen.h — the `keygen` CLI: generate a fresh mainnet P2PKH key.
 *
 * Usage:
 *   keygen [path]
 *     - with `path` (or $KEY_FILE): write {"wif","address"} JSON to that path
 *       with 0600 perms (refusing to overwrite an existing file) and print the
 *       address to stdout.
 *     - with no path: print {"wif","address"} JSON to stdout.
 *
 * Mirrors the chain_c key-file convention used by deploy/cpfp/agentd
 * (script_support.h key_file_t).
 */
#ifndef BONSAI_SCRIPTS_KEYGEN_H
#define BONSAI_SCRIPTS_KEYGEN_H

#include "common/error.h"

/* Run the keygen CLI. Reports outcome via *out_exit_code (0 ok, 1 failure).
 * Returns BNS_OK unless an unexpected internal error occurs. */
int keygen_run(int argc, char **argv, int *out_exit_code);

#endif /* BONSAI_SCRIPTS_KEYGEN_H */
