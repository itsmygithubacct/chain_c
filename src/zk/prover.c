/*
 * prover.c — ZK proof production / circuit build by SHELLING OUT to the circom2
 * + snarkjs toolchain via posix_spawn. Ported from chain/scripts/zkBuild.js
 * (build pipeline) and the snarkjs.groth16.fullProve usage in the ZK scripts.
 *
 * This is NOT a runtime crypto module: circom/snarkjs are not portable to C, so
 * a C deployment shells out to the same toolchain rather than re-implementing
 * the Groth16 setup/prover. Consumers parse the resulting proof.json/vkey.json
 * via zk/g16.h.
 *
 * COMPILE GUARD (see include/zk/prover.h): the external toolchain is heavy and
 * optional; the IMPL is gated behind BONSAI_ENABLE_ZK. Prototypes are declared
 * regardless; when compiled out (or when the toolchain spawn fails) the impl
 * returns BNS_EUNSUPPORTED / BNS_ECRYPTO as documented.
 */
#include "zk/prover.h"

#ifdef BONSAI_ENABLE_ZK

#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

/* PTAU_POWER from zkBuild.js (2^12 constraint ceiling; withinLimit needs ~600). */
#define ZK_PTAU_POWER "12"

/*
 * Spawn argv[0] with argv, inheriting stdio, and wait. Returns:
 *   BNS_OK     child exited 0
 *   BNS_ECRYPTO  child exited non-zero / signalled (a toolchain failure)
 *   BNS_EUNSUPPORTED  the binary could not be spawned (toolchain absent)
 */
static int run_tool(char *const argv[])
{
    pid_t pid;
    int spawn_rc;
    int status;

    spawn_rc = posix_spawnp(&pid, argv[0], NULL, NULL, argv, environ);
    if (spawn_rc != 0) {
        /* ENOENT etc. — the toolchain binary is not installed/visible. */
        return BNS_EUNSUPPORTED;
    }
    if (waitpid(pid, &status, 0) < 0)
        return BNS_ECRYPTO;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        return BNS_OK;
    return BNS_ECRYPTO;
}

/* mkdir -p `path` (mode 0755). BNS_OK / BNS_EPERSIST. */
static int mkdir_p(const char *path)
{
    char buf[4096];
    size_t len;
    size_t i;

    if (path == NULL)
        return BNS_EPERSIST;
    len = strlen(path);
    if (len == 0 || len >= sizeof buf)
        return BNS_EPERSIST;
    memcpy(buf, path, len + 1);

    for (i = 1; i < len; i++) {
        if (buf[i] == '/') {
            buf[i] = '\0';
            if (mkdir(buf, 0755) != 0 && errno != EEXIST)
                return BNS_EPERSIST;
            buf[i] = '/';
        }
    }
    if (mkdir(buf, 0755) != 0 && errno != EEXIST)
        return BNS_EPERSIST;
    return BNS_OK;
}

/* Join a dir and leaf into `out` (size cap). BNS_OK / BNS_EPERSIST. */
static int join_path(char *out, size_t cap, const char *dir, const char *leaf)
{
    int n = snprintf(out, cap, "%s/%s", dir, leaf);
    if (n < 0 || (size_t)n >= cap)
        return BNS_EPERSIST;
    return BNS_OK;
}

#endif /* BONSAI_ENABLE_ZK */

int zk_build_artifacts(const char *circuit_path, const char *out_dir)
{
#ifndef BONSAI_ENABLE_ZK
    (void)circuit_path;
    (void)out_dir;
    return BNS_EUNSUPPORTED;
#else
    /*
     * Mirror scripts/zkBuild.js for a single circuit:
     *   1) circom2 <src> --r1cs --wasm -o OUT
     *   2) snarkjs powersOfTau new bn128 12 + contribute + prepare phase2
     *   3) snarkjs groth16 setup <r1cs> <ptau_final> <zkey0>
     *   4) snarkjs zkey contribute <zkey0> <zkey>
     *   5) snarkjs zkey export verificationkey <zkey> <vkey.json>
     * The snarkjs CLI is the same library zkBuild.js calls programmatically.
     */
    int rc;
    char tmp[4096];
    char r1cs[4096];
    char base[256];
    char ptau0[4096], ptau1[4096], ptau_final[4096];
    char zkey0[4096], zkey[4096], vkey[4096];
    const char *slash, *dot;
    size_t blen;

    if (circuit_path == NULL || out_dir == NULL)
        return BNS_EPERSIST;

    rc = mkdir_p(out_dir);
    if (rc != BNS_OK)
        return rc;

    /* TMP scratch dir under out_dir/.zkbuild (zkBuild.js uses ROOT/.zkbuild). */
    if ((rc = join_path(tmp, sizeof tmp, out_dir, ".zkbuild")) != BNS_OK)
        return rc;
    if ((rc = mkdir_p(tmp)) != BNS_OK)
        return rc;

    /* circuit base name (strip dir + .circom). */
    slash = strrchr(circuit_path, '/');
    slash = slash ? slash + 1 : circuit_path;
    dot = strrchr(slash, '.');
    blen = dot ? (size_t)(dot - slash) : strlen(slash);
    if (blen == 0 || blen >= sizeof base)
        return BNS_EPERSIST;
    memcpy(base, slash, blen);
    base[blen] = '\0';

    /* 1) circom2 compile (npx circom2 <src> --r1cs --wasm -o TMP). */
    {
        char *argv[] = { "npx", "circom2", (char *)circuit_path,
                         "--r1cs", "--wasm", "-o", tmp, NULL };
        rc = run_tool(argv);
        if (rc != BNS_OK)
            return rc;
    }

    /* paths */
    if ((rc = join_path(ptau0, sizeof ptau0, tmp, "pot_0.ptau")) != BNS_OK ||
        (rc = join_path(ptau1, sizeof ptau1, tmp, "pot_1.ptau")) != BNS_OK ||
        (rc = join_path(ptau_final, sizeof ptau_final, tmp, "pot_final.ptau")) != BNS_OK)
        return rc;
    {
        char leaf[300];
        if (snprintf(leaf, sizeof leaf, "%s.r1cs", base) >= (int)sizeof leaf)
            return BNS_EPERSIST;
        if ((rc = join_path(r1cs, sizeof r1cs, tmp, leaf)) != BNS_OK)
            return rc;
        if (snprintf(leaf, sizeof leaf, "%s_0.zkey", base) >= (int)sizeof leaf)
            return BNS_EPERSIST;
        if ((rc = join_path(zkey0, sizeof zkey0, tmp, leaf)) != BNS_OK)
            return rc;
        if (snprintf(leaf, sizeof leaf, "%s.zkey", base) >= (int)sizeof leaf)
            return BNS_EPERSIST;
        if ((rc = join_path(zkey, sizeof zkey, out_dir, leaf)) != BNS_OK)
            return rc;
        if (snprintf(leaf, sizeof leaf, "%s.vkey.json", base) >= (int)sizeof leaf)
            return BNS_EPERSIST;
        if ((rc = join_path(vkey, sizeof vkey, out_dir, leaf)) != BNS_OK)
            return rc;
    }

    /* 2) local powers of tau (2^12), contribute, prepare phase2. */
    {
        char *argv[] = { "npx", "snarkjs", "powersoftau", "new",
                         "bn128", ZK_PTAU_POWER, ptau0, "-v", NULL };
        if ((rc = run_tool(argv)) != BNS_OK)
            return rc;
    }
    {
        char *argv[] = { "npx", "snarkjs", "powersoftau", "contribute",
                         ptau0, ptau1, "--name=priscilla local",
                         "-e=priscilla-local-entropy-1", NULL };
        if ((rc = run_tool(argv)) != BNS_OK)
            return rc;
    }
    {
        char *argv[] = { "npx", "snarkjs", "powersoftau", "preparephase2",
                         ptau1, ptau_final, "-v", NULL };
        if ((rc = run_tool(argv)) != BNS_OK)
            return rc;
    }

    /* 3) groth16 setup -> zkey0. */
    {
        char *argv[] = { "npx", "snarkjs", "groth16", "setup",
                         r1cs, ptau_final, zkey0, NULL };
        if ((rc = run_tool(argv)) != BNS_OK)
            return rc;
    }
    /* 4) zkey contribute -> final zkey. */
    {
        char ename[300];
        if (snprintf(ename, sizeof ename, "-e=priscilla-local-entropy-%s", base)
            >= (int)sizeof ename)
            return BNS_EPERSIST;
        char *argv[] = { "npx", "snarkjs", "zkey", "contribute",
                         zkey0, zkey, "--name=priscilla local", ename, NULL };
        if ((rc = run_tool(argv)) != BNS_OK)
            return rc;
    }
    /* 5) export verification key -> vkey.json. */
    {
        char *argv[] = { "npx", "snarkjs", "zkey", "export",
                         "verificationkey", zkey, vkey, NULL };
        if ((rc = run_tool(argv)) != BNS_OK)
            return rc;
    }

    return BNS_OK;
#endif
}

int zk_prove(const char *wasm_path, const char *zkey_path,
             const char *input_json_path,
             const char *out_proof_path, const char *out_public_path)
{
#ifndef BONSAI_ENABLE_ZK
    (void)wasm_path;
    (void)zkey_path;
    (void)input_json_path;
    (void)out_proof_path;
    (void)out_public_path;
    return BNS_EUNSUPPORTED;
#else
    /*
     * snarkjs.groth16.fullProve(input, wasm, zkey) via the CLI:
     *   snarkjs groth16 fullprove <input.json> <wasm> <zkey> <proof> <public>
     * (the CLI's fullprove takes the input/wasm/zkey and writes proof + public).
     */
    if (wasm_path == NULL || zkey_path == NULL || input_json_path == NULL ||
        out_proof_path == NULL || out_public_path == NULL)
        return BNS_EPERSIST;

    char *argv[] = { "npx", "snarkjs", "groth16", "fullprove",
                     (char *)input_json_path, (char *)wasm_path,
                     (char *)zkey_path, (char *)out_proof_path,
                     (char *)out_public_path, NULL };
    return run_tool(argv);
#endif
}
