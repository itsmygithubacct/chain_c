/*
 * zk_build_lib.c — ZK build pipeline (faithful functional port of
 * chain/scripts/zkBuild.js). BUILD-TIME orchestrator only: it SHELLS OUT to the
 * circom2 + snarkjs toolchain (the same commands zkBuild.js drives through
 * execFileSync('npx',['circom2',...]) and snarkjs's programmatic API). No
 * Groth16 / circom crypto is reimplemented in C.
 *
 * See include/scripts/zk_build.h for the full pipeline, env vars, ROOT
 * resolution, and the trusted-setup provenance note.
 */
#include "scripts/zk_build.h"
#include "scripts/script_support.h"

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

/* ---- small process / fs helpers (local to the orchestrator) -------------- */

/* Does `name` resolve on $PATH as an executable? (a `which`-style probe). */
static bool on_path(const char *name)
{
    const char *path = getenv("PATH");
    char buf[4096];
    const char *p;

    if (name == NULL || name[0] == '\0')
        return false;
    /* an explicit path: test directly */
    if (strchr(name, '/') != NULL)
        return access(name, X_OK) == 0;
    if (path == NULL || path[0] == '\0')
        return false;

    p = path;
    while (*p) {
        const char *colon = strchr(p, ':');
        size_t dlen = colon ? (size_t)(colon - p) : strlen(p);
        if (dlen == 0) {
            /* empty PATH element == current dir */
            if (snprintf(buf, sizeof buf, "./%s", name) < (int)sizeof buf &&
                access(buf, X_OK) == 0)
                return true;
        } else if (dlen + 1 + strlen(name) + 1 < sizeof buf) {
            memcpy(buf, p, dlen);
            buf[dlen] = '/';
            strcpy(buf + dlen + 1, name);
            if (access(buf, X_OK) == 0)
                return true;
        }
        if (!colon)
            break;
        p = colon + 1;
    }
    return false;
}

/*
 * Spawn argv[0] with argv (PATH-searched), inheriting stdio, and wait.
 *   BNS_OK           child exited 0
 *   BNS_EUNSUPPORTED the binary could not be spawned (toolchain absent)
 *   BNS_ECRYPTO      child exited non-zero / signalled (a toolchain failure)
 */
static int run_tool(char *const argv[])
{
    pid_t pid;
    int status;

    if (posix_spawnp(&pid, argv[0], NULL, NULL, argv, environ) != 0)
        return BNS_EUNSUPPORTED;
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
    size_t len, i;

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

/* rm -rf `path` via the system `rm` (mirrors fs.rmSync recursive+force). */
static void rm_rf(const char *path)
{
    char *argv[] = { "rm", "-rf", "--", (char *)path, NULL };
    (void)run_tool(argv); /* best-effort: force => no error if absent */
}

/* Byte copy src -> dst (mirrors fs.copyFileSync). BNS_OK / BNS_EPERSIST. */
static int copy_file(const char *src, const char *dst)
{
    FILE *in = fopen(src, "rb");
    FILE *out;
    char buf[65536];
    size_t n;
    int rc = BNS_OK;

    if (in == NULL)
        return BNS_EPERSIST;
    out = fopen(dst, "wb");
    if (out == NULL) {
        fclose(in);
        return BNS_EPERSIST;
    }
    while ((n = fread(buf, 1, sizeof buf, in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            rc = BNS_EPERSIST;
            break;
        }
    }
    if (ferror(in))
        rc = BNS_EPERSIST;
    fclose(in);
    if (fclose(out) != 0)
        rc = BNS_EPERSIST;
    return rc;
}

/* Join `dir`/`leaf` into `out`. BNS_OK / BNS_EPERSIST (overflow). */
static int join_path(char *out, size_t cap, const char *dir, const char *leaf)
{
    int n = snprintf(out, cap, "%s/%s", dir, leaf);
    if (n < 0 || (size_t)n >= cap)
        return BNS_EPERSIST;
    return BNS_OK;
}

/* ---- pipeline ------------------------------------------------------------ */

struct circuit {
    const char *name;       /* artifact base name */
    const char *rel_source; /* .circom path relative to ROOT */
};

int zk_build_run(int argc, char **argv, int *out_exit_code)
{
    /* ROOT = argv[1] (the TS __dirname/..) else $ZK_BUILD_ROOT else cwd. */
    const char *root;
    char cwd[4096];
    char out_dir[4096], tmp[4096], node_modules[4096];
    char ptau0[4096], ptau1[4096], ptau_final[4096];
    int rc;
    size_t i;

    const struct circuit circuits[] = {
        { "square",      "circuits/spike/square.circom" },
        { "withinLimit", "circuits/withinLimit.circom"  },
    };

    if (out_exit_code != NULL)
        *out_exit_code = 1; /* default to failure until we reach the clean exit */

    if (argc > 1 && argv[1] != NULL && argv[1][0] != '\0') {
        root = argv[1];
    } else if (env_get("ZK_BUILD_ROOT") != NULL && env_get("ZK_BUILD_ROOT")[0]) {
        root = env_get("ZK_BUILD_ROOT");
    } else {
        if (getcwd(cwd, sizeof cwd) == NULL)
            return BNS_EPERSIST;
        root = cwd;
    }

    /* Guard the heavy steps: require the toolchain BEFORE touching the fs. */
    if (!on_path("circom2") || !on_path("snarkjs")) {
        fprintf(stderr,
                "zk-build: circom2/snarkjs not found on PATH.\n"
                "  This build step shells out to the circom2 + snarkjs toolchain.\n"
                "  Install them (e.g. `npm i -g circom2 snarkjs`) and ensure they\n"
                "  resolve on $PATH, then re-run.\n");
        if (out_exit_code != NULL)
            *out_exit_code = 1;
        return BNS_OK; /* ran to a clean, well-defined non-zero exit */
    }

    if ((rc = join_path(out_dir, sizeof out_dir, root, "artifacts/zk")) != BNS_OK ||
        (rc = join_path(tmp, sizeof tmp, root, ".zkbuild")) != BNS_OK ||
        (rc = join_path(node_modules, sizeof node_modules, root, "node_modules")) != BNS_OK)
        return rc;

    /* mkdirSync(OUT); rmSync(TMP); mkdirSync(TMP). */
    if ((rc = mkdir_p(out_dir)) != BNS_OK)
        return rc;
    rm_rf(tmp);
    if ((rc = mkdir_p(tmp)) != BNS_OK)
        return rc;

    if ((rc = join_path(ptau0, sizeof ptau0, tmp, "pot_0.ptau")) != BNS_OK ||
        (rc = join_path(ptau1, sizeof ptau1, tmp, "pot_1.ptau")) != BNS_OK ||
        (rc = join_path(ptau_final, sizeof ptau_final, tmp, "pot_final.ptau")) != BNS_OK) {
        rm_rf(tmp);
        return rc;
    }

    /* --- local powers of tau (built once; see provenance note) --- */
    printf("powers of tau (local, 2^%s) ...\n", ZK_PTAU_POWER);
    fflush(stdout);
    {
        char *a_new[] = { "snarkjs", "powersoftau", "new", "bn128",
                          ZK_PTAU_POWER, ptau0, "-v", NULL };
        char *a_contrib[] = { "snarkjs", "powersoftau", "contribute",
                              ptau0, ptau1, "--name=priscilla local",
                              "-e=priscilla-local-entropy-1", NULL };
        char *a_prep[] = { "snarkjs", "powersoftau", "preparephase2",
                           ptau1, ptau_final, "-v", NULL };
        if ((rc = run_tool(a_new)) != BNS_OK ||
            (rc = run_tool(a_contrib)) != BNS_OK ||
            (rc = run_tool(a_prep)) != BNS_OK) {
            fprintf(stderr, "zk-build: powers-of-tau step failed (%s)\n",
                    bns_err_name(rc));
            rm_rf(tmp);
            if (out_exit_code != NULL)
                *out_exit_code = 1;
            return BNS_OK;
        }
    }

    /* --- per circuit --- */
    for (i = 0; i < sizeof circuits / sizeof circuits[0]; i++) {
        const char *name = circuits[i].name;
        char source[4096], r1cs[4096], zkey0[4096], zkey[4096];
        char vkey[4096], wasm_src[4096], wasm_dst[4096];
        char leaf[300], ename[300];

        printf("\n=== %s ===\n", name);
        fflush(stdout);

        if ((rc = join_path(source, sizeof source, root, circuits[i].rel_source)) != BNS_OK)
            goto fail;

        /* compile (circom2 <src> --r1cs --wasm -o TMP -l ROOT/node_modules) */
        {
            char *a[] = { "circom2", source, "--r1cs", "--wasm",
                          "-o", tmp, "-l", node_modules, NULL };
            if ((rc = run_tool(a)) != BNS_OK)
                goto fail;
        }

        if (snprintf(leaf, sizeof leaf, "%s.r1cs", name) >= (int)sizeof leaf) { rc = BNS_EPERSIST; goto fail; }
        if ((rc = join_path(r1cs, sizeof r1cs, tmp, leaf)) != BNS_OK) goto fail;
        if (snprintf(leaf, sizeof leaf, "%s_0.zkey", name) >= (int)sizeof leaf) { rc = BNS_EPERSIST; goto fail; }
        if ((rc = join_path(zkey0, sizeof zkey0, tmp, leaf)) != BNS_OK) goto fail;
        if (snprintf(leaf, sizeof leaf, "%s.zkey", name) >= (int)sizeof leaf) { rc = BNS_EPERSIST; goto fail; }
        if ((rc = join_path(zkey, sizeof zkey, out_dir, leaf)) != BNS_OK) goto fail;
        if (snprintf(leaf, sizeof leaf, "%s.vkey.json", name) >= (int)sizeof leaf) { rc = BNS_EPERSIST; goto fail; }
        if ((rc = join_path(vkey, sizeof vkey, out_dir, leaf)) != BNS_OK) goto fail;

        /* zKey.newZKey(r1cs, ptauFinal, zkey0) == groth16 setup */
        {
            char *a[] = { "snarkjs", "groth16", "setup",
                          r1cs, ptau_final, zkey0, NULL };
            if ((rc = run_tool(a)) != BNS_OK) goto fail;
        }
        /* zKey.contribute(zkey0, zkey, 'priscilla local', entropy-<name>) */
        if (snprintf(ename, sizeof ename, "-e=priscilla-local-entropy-%s", name) >= (int)sizeof ename) { rc = BNS_EPERSIST; goto fail; }
        {
            char *a[] = { "snarkjs", "zkey", "contribute",
                          zkey0, zkey, "--name=priscilla local", ename, NULL };
            if ((rc = run_tool(a)) != BNS_OK) goto fail;
        }
        /* exportVerificationKey(zkey) -> OUT/<name>.vkey.json
         * (snarkjs writes the same JSON object zkBuild.js JSON.stringify'd). */
        {
            char *a[] = { "snarkjs", "zkey", "export", "verificationkey",
                          zkey, vkey, NULL };
            if ((rc = run_tool(a)) != BNS_OK) goto fail;
        }
        /* copyFileSync(TMP/<name>_js/<name>.wasm, OUT/<name>.wasm) */
        if (snprintf(leaf, sizeof leaf, "%s_js/%s.wasm", name, name) >= (int)sizeof leaf) { rc = BNS_EPERSIST; goto fail; }
        if ((rc = join_path(wasm_src, sizeof wasm_src, tmp, leaf)) != BNS_OK) goto fail;
        if (snprintf(leaf, sizeof leaf, "%s.wasm", name) >= (int)sizeof leaf) { rc = BNS_EPERSIST; goto fail; }
        if ((rc = join_path(wasm_dst, sizeof wasm_dst, out_dir, leaf)) != BNS_OK) goto fail;
        if ((rc = copy_file(wasm_src, wasm_dst)) != BNS_OK) goto fail;

        printf("%s: zkey + vkey.json + wasm -> artifacts/zk/\n", name);
        fflush(stdout);
        continue;

    fail:
        fprintf(stderr, "zk-build: circuit '%s' step failed (%s)\n",
                name, bns_err_name(rc));
        rm_rf(tmp);
        if (out_exit_code != NULL)
            *out_exit_code = 1;
        return BNS_OK;
    }

    rm_rf(tmp);
    printf("\nDone. Artifacts in artifacts/zk/ (local trusted setup — see provenance note).\n");
    fflush(stdout);
    if (out_exit_code != NULL)
        *out_exit_code = 0;
    return BNS_OK;
}
