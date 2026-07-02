/*
 * prover.h — proof production by shelling out to circom2 + snarkjs via
 * posix_spawn. Circom/snarkjs are not portable to C; a C deployment either
 * shells out to `snarkjs.groth16.fullProve` against the precompiled artifacts
 * (artifacts/zk/withinLimit.{wasm,zkey,vkey.json}) or ships stored proofs. This
 * is the wrapper around that shell-out; consumers parse the resulting
 * proof.json/vkey.json via zk/g16.h.
 *
 * TS origin: scripts/zkBuild.js (build pipeline) + snarkjs.groth16.fullProve
 * usage in the ZK scripts. NOT a runtime crypto module — pure process/file
 * orchestration.
 *
 * COMPILE GUARD: prove/build require an external toolchain; gate the IMPL behind
 * BONSAI_ENABLE_ZK. Prototypes declared regardless; impl returns
 * BNS_EUNSUPPORTED when compiled out or when the toolchain is absent.
 */
#ifndef BONSAI_ZK_PROVER_H
#define BONSAI_ZK_PROVER_H

#include <stddef.h>
#include "common/error.h"

/* Build the ZK artifacts (circom2 compile + local single-contributor Groth16
 * trusted setup) into `out_dir`, mirroring scripts/zkBuild.js (PTAU_POWER=12).
 * `circuit_path` is the .circom source. NON-secure local setup. Shells out via
 * posix_spawn; surfaces a non-zero child exit as BNS_ECRYPTO.
 * TS: zkBuild.js main. BNS_OK / BNS_EUNSUPPORTED / BNS_EPERSIST / BNS_ECRYPTO. */
int zk_build_artifacts(const char *circuit_path, const char *out_dir);

/* Generate a Groth16 proof for `input_json_path` against the precompiled
 * `wasm_path` + `zkey_path` (snarkjs.groth16.fullProve), writing proof JSON to
 * `out_proof_path` and public-signals JSON to `out_public_path`. Shells out via
 * posix_spawn. TS: snarkjs.groth16.fullProve.
 * BNS_OK / BNS_EUNSUPPORTED / BNS_EPERSIST / BNS_ECRYPTO. */
int zk_prove(const char *wasm_path, const char *zkey_path,
             const char *input_json_path,
             const char *out_proof_path, const char *out_public_path);

#endif /* BONSAI_ZK_PROVER_H */
