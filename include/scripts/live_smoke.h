/*
 * live_smoke.h — the liveSmoke script LIBRARY entry point: a read-only MAINNET
 * smoke test of the WhatsOnChain ChainSource adapter (no keys, no broadcast —
 * just GETs). Exercises getRawTx / getTime / getSpendingTxid plus one real
 * backward chain hop via parsePrevout, using the historical block-170
 * Satoshi -> Hal Finney tx as a stable fixture. Logic in
 * src/scripts/live_smoke_lib.c.
 *
 * TS origin: scripts/liveSmoke.ts (main).
 *
 * Behaviour: prints a JSON result object (JSON.stringify(results, null, 2)) then
 * "LIVE SMOKE: PASS" or "LIVE SMOKE: FAIL"; exits 0 on all-ok, 1 otherwise. On
 * an exception it prints "LIVE SMOKE: ERROR <msg>" to stderr and exits 1.
 *
 * No env vars; no broadcast gate. The TX fixture is hard-coded.
 */
#ifndef BONSAI_SCRIPTS_LIVE_SMOKE_H
#define BONSAI_SCRIPTS_LIVE_SMOKE_H

#include "common/error.h"
#include "reputation_indexer.h"   /* chain_source_t */

/* The block-170 fixture (Satoshi -> Hal Finney), display byte order. TS: TX. */
#define BONSAI_LIVE_SMOKE_TX \
    "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"

/* Run the smoke against an injected `source` (so the curl-free unit/smoke path
 * can drive a stub transport). Prints the JSON result + PASS/FAIL exactly as the
 * TS does, and writes the process exit code (0 all-ok / 1 otherwise) to
 * *out_exit_code. On a chain_source error it prints "LIVE SMOKE: ERROR ..." to
 * stderr and sets *out_exit_code = 1. Always returns BNS_OK (the result is the
 * exit code, mirroring the TS try/catch that swallows into process.exit).
 * TS: scripts/liveSmoke.ts main body. */
int live_smoke_run_with_source(const chain_source_t *source, int *out_exit_code);

/* Run the liveSmoke library against REAL mainnet via a libcurl transport.
 * Returns a process exit code via *out_exit_code (0 / 1). On transport
 * construction failure prints "LIVE SMOKE: ERROR ..." and sets exit code 1.
 * TS: scripts/liveSmoke.ts main + the top-level catch. */
int live_smoke_run(int argc, char **argv, int *out_exit_code);

#endif /* BONSAI_SCRIPTS_LIVE_SMOKE_H */
