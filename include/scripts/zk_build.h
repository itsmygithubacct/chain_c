/*
 * zk_build.h — the zk-build script LIBRARY entry point: the ZK build pipeline.
 *
 * Faithful (functional) port of chain/scripts/zkBuild.js. This is a BUILD-TIME
 * orchestrator, NOT a runtime/consensus crypto path: circom2 (the circom v2
 * compiler) and snarkjs (Groth16 trusted setup / key export) are NOT portable
 * to C, so the C port SHELLS OUT to the same `npx circom2` / `npx snarkjs`
 * toolchain via posix_spawn, exactly as the TS calls them programmatically.
 *
 * Pipeline (PTAU_POWER=12, 2^12 constraint ceiling; withinLimit needs ~600):
 *   1) local powers of tau, built ONCE:
 *        snarkjs powersoftau new bn128 12 pot_0
 *        snarkjs powersoftau contribute  pot_0 -> pot_1   (name "priscilla local",
 *                                                          entropy "priscilla-local-entropy-1")
 *        snarkjs powersoftau preparephase2 pot_1 -> pot_final
 *   2) per circuit {square, withinLimit}:
 *        circom2 <src> --r1cs --wasm -o TMP -l <ROOT>/node_modules
 *        snarkjs groth16 setup <name>.r1cs pot_final <name>_0.zkey
 *        snarkjs zkey contribute <name>_0.zkey OUT/<name>.zkey
 *                                  (name "priscilla local",
 *                                   entropy "priscilla-local-entropy-<name>")
 *        snarkjs zkey export verificationkey OUT/<name>.zkey OUT/<name>.vkey.json
 *        copy TMP/<name>_js/<name>.wasm -> OUT/<name>.wasm
 *   TMP = <ROOT>/.zkbuild (removed at start and end); OUT = <ROOT>/artifacts/zk.
 *
 * TRUSTED-SETUP PROVENANCE: the powers-of-tau AND the phase-2 contribution are
 * generated LOCALLY, single-contributor, with hardcoded entropy. Fine for a
 * reference implementation and tests; NOT a production ceremony — whoever ran
 * this could forge proofs for these keys. A production deployment must rebuild
 * from a public powersOfTau ceremony + a multi-party phase 2 and pin the vkey
 * hash. (Verbatim from the zkBuild.js header.)
 *
 * ROOT resolution (the TS uses __dirname/..): the first positional argv, else
 * $ZK_BUILD_ROOT, else the current working directory. circuits/ and
 * node_modules/ must live under ROOT.
 *
 * Logic in src/scripts/zk_build_lib.c.
 */
#ifndef BONSAI_SCRIPTS_ZK_BUILD_H
#define BONSAI_SCRIPTS_ZK_BUILD_H

#include "common/error.h"

/* Run the zk-build pipeline. Mirrors zkBuild.js main(). Shells out to circom2 +
 * snarkjs; if the toolchain is absent it prints a clear message and the process
 * exits non-zero. Returns BNS_OK with the process exit code in *out_exit_code
 * (0 success, 1 on any failure — matching the TS process.exit codes), or a
 * propagated error code on an internal failure before the pipeline begins.
 * TS: scripts/zkBuild.js. */
int zk_build_run(int argc, char **argv, int *out_exit_code);

#endif /* BONSAI_SCRIPTS_ZK_BUILD_H */
