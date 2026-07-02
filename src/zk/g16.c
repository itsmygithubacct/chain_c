/*
 * g16.c — the snarkjs <-> scrypt-ts-lib (G16BN256) encoding bridge over BN254
 * (alt_bn128), ported from chain/src/zk/g16.ts.
 *
 * SCOPE / COMPILE GUARD (see include/zk/g16.h):
 *  - The off-chain Groth16 pairing arithmetic (the BN254 Fp12 tower + optimal-ate
 *    Miller loop + final exponentiation) is HEAVY and intentionally NOT hand-
 *    ported to C — that would re-implement a consensus-critical pairing from
 *    scratch with no golden to pin it. Instead the heavy paths are gated behind
 *    BONSAI_ENABLE_ZK and the off-chain verifier SHELLS OUT to the proven
 *    snarkjs toolchain (see src/zk/prover.c for the posix_spawn wrapper).
 *  - When BONSAI_ENABLE_ZK is NOT defined, every entry point returns
 *    BNS_EUNSUPPORTED cleanly (the header documents this).
 *
 * FIELD-EXACTNESS PINS (g16.ts):
 *  - G1 decode reads ONLY [x, y] (the trailing '1' z is ignored): {x,y} direct.
 *  - G2 decode keeps snarkjs natural coeff order c0,c1 (FQ2={x:c0,y:c1}); the
 *    go-ethereum swap is done later by createTwistPoint — do NOT pre-swap here.
 *  - vkFromSnarkjs gate: protocol=="groth16" && curve in {bn128,bn254} &&
 *    nPublic==1 && IC.length==2.
 *  - Field elements are DECIMAL strings parsed via BigInt(base 10).
 */
#include "zk/g16.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/bignum.h"

#ifdef BONSAI_ENABLE_ZK
/* Off-chain verify shells out to snarkjs via posix_spawn (mirrors src/zk/prover.c)
 * and captures the child's stdout/stderr through a pipe to read the verdict. */
#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
#endif

/* ------------------------------------------------------------------------- */
/* Small leaf helpers (used only when ZK is enabled, but cheap + warning-free */
/* to keep available; guarded with the impl to avoid unused-fn warnings).     */
/* ------------------------------------------------------------------------- */
#ifdef BONSAI_ENABLE_ZK

/* Parse one decimal field-element string into a fresh bn_t leaf. */
static int leaf_dec(const char *s, bn_t **out)
{
    if (s == NULL)
        return BNS_EPARSE;
    return bn_parse_dec(s, out);
}

/* Free an fq2_t's leaves (NULL-safe) and clear the pointers. */
static void fq2_clear(fq2_t *f)
{
    if (f == NULL)
        return;
    bn_free(f->x);
    bn_free(f->y);
    f->x = NULL;
    f->y = NULL;
}

static void fq6_clear(fq6_t *f)
{
    if (f == NULL)
        return;
    fq2_clear(&f->x);
    fq2_clear(&f->y);
    fq2_clear(&f->z);
}

static void fq12_clear(fq12_t *f)
{
    if (f == NULL)
        return;
    fq6_clear(&f->x);
    fq6_clear(&f->y);
}

static void g1_clear(g1_point_t *p)
{
    if (p == NULL)
        return;
    bn_free(p->x);
    bn_free(p->y);
    p->x = NULL;
    p->y = NULL;
}

static void g2_clear(g2_point_t *p)
{
    if (p == NULL)
        return;
    fq2_clear(&p->x);
    fq2_clear(&p->y);
}

/* Decode a snarkjs G1 [x,y] decimal pair into a g1_point_t (owned leaves). */
static int g1_from_dec(const char *const xy[2], g1_point_t *out)
{
    int rc;
    out->x = NULL;
    out->y = NULL;
    rc = leaf_dec(xy[0], &out->x);
    if (rc != BNS_OK)
        return rc;
    rc = leaf_dec(xy[1], &out->y);
    if (rc != BNS_OK) {
        g1_clear(out);
        return rc;
    }
    return BNS_OK;
}

/* Decode a snarkjs G2 [[c0,c1],[c0,c1]] into a g2_point_t with FQ2={x:c0,y:c1}
 * (snarkjs natural coeff order; NO pre-swap). */
static int g2_from_dec(const char *const cc[2][2], g2_point_t *out)
{
    int rc;
    memset(out, 0, sizeof *out);
    rc = leaf_dec(cc[0][0], &out->x.x);
    if (rc != BNS_OK)
        goto fail;
    rc = leaf_dec(cc[0][1], &out->x.y);
    if (rc != BNS_OK)
        goto fail;
    rc = leaf_dec(cc[1][0], &out->y.x);
    if (rc != BNS_OK)
        goto fail;
    rc = leaf_dec(cc[1][1], &out->y.y);
    if (rc != BNS_OK)
        goto fail;
    return BNS_OK;
fail:
    g2_clear(out);
    return rc;
}

/* Allocate an all-zero FQ12 (placeholder for the precomputed miller_b1a1; the
 * actual Miller loop is performed off-chain by the snarkjs shell-out). */
static int fq12_zero(fq12_t *out)
{
    bn_t **leaves[12];
    int i;
    memset(out, 0, sizeof *out);
    leaves[0] = &out->x.x.x; leaves[1] = &out->x.x.y;
    leaves[2] = &out->x.y.x; leaves[3] = &out->x.y.y;
    leaves[4] = &out->x.z.x; leaves[5] = &out->x.z.y;
    leaves[6] = &out->y.x.x; leaves[7] = &out->y.x.y;
    leaves[8] = &out->y.y.x; leaves[9] = &out->y.y.y;
    leaves[10] = &out->y.z.x; leaves[11] = &out->y.z.y;
    for (i = 0; i < 12; i++) {
        *leaves[i] = bn_new();
        if (*leaves[i] == NULL) {
            fq12_clear(out);
            return BNS_ENOMEM;
        }
    }
    return BNS_OK;
}

/* ------------------------------------------------------------------------- */
/* snarkjs JSON re-serialization + `npx snarkjs groth16 verify` shell-out.    */
/* These REVERSE the g1_from_dec/g2_from_dec decode so the round-trip emits   */
/* byte-identical snarkjs field order:                                        */
/*   G1 -> ["x_dec","y_dec","1"]   (the trailing z is always "1")             */
/*   G2 -> [["x.x","x.y"],["y.x","y.y"],["1","0"]]  (snarkjs natural c0,c1)   */
/* ------------------------------------------------------------------------- */

/* Write one Fp leaf as a JSON decimal string `"<dec>"`. */
static int json_int(FILE *f, const bn_t *v)
{
    char *dec = NULL;
    int rc;
    if (v == NULL)
        return BNS_EINVAL;
    rc = bn_to_dec(v, &dec);
    if (rc != BNS_OK)
        return rc;
    if (fprintf(f, "\"%s\"", dec) < 0)
        rc = BNS_EPERSIST;
    free(dec);
    return rc;
}

/* G1 affine -> ["x","y","1"] (the trailing projective z is fixed to "1"). */
static int json_g1(FILE *f, const g1_point_t *p)
{
    int rc;
    if (fputc('[', f) == EOF)
        return BNS_EPERSIST;
    if ((rc = json_int(f, p->x)) != BNS_OK)
        return rc;
    if (fputc(',', f) == EOF)
        return BNS_EPERSIST;
    if ((rc = json_int(f, p->y)) != BNS_OK)
        return rc;
    if (fputs(",\"1\"]", f) == EOF)
        return BNS_EPERSIST;
    return BNS_OK;
}

/* G2 affine -> [["x.x","x.y"],["y.x","y.y"],["1","0"]] (snarkjs coeff order). */
static int json_g2(FILE *f, const g2_point_t *p)
{
    int rc;
    if (fputs("[[", f) == EOF)
        return BNS_EPERSIST;
    if ((rc = json_int(f, p->x.x)) != BNS_OK)
        return rc;
    if (fputc(',', f) == EOF)
        return BNS_EPERSIST;
    if ((rc = json_int(f, p->x.y)) != BNS_OK)
        return rc;
    if (fputs("],[", f) == EOF)
        return BNS_EPERSIST;
    if ((rc = json_int(f, p->y.x)) != BNS_OK)
        return rc;
    if (fputc(',', f) == EOF)
        return BNS_EPERSIST;
    if ((rc = json_int(f, p->y.y)) != BNS_OK)
        return rc;
    if (fputs("],[\"1\",\"0\"]]", f) == EOF)
        return BNS_EPERSIST;
    return BNS_OK;
}

/* Serialize the proof to a snarkjs proof.json. */
static int write_proof_file(const char *path, const g16_proof_t *p)
{
    FILE *f = fopen(path, "w");
    int rc = BNS_OK;
    if (f == NULL)
        return BNS_EPERSIST;
    if (fputs("{\n \"pi_a\": ", f) == EOF)
        rc = BNS_EPERSIST;
    if (rc == BNS_OK)
        rc = json_g1(f, &p->a);
    if (rc == BNS_OK && fputs(",\n \"pi_b\": ", f) == EOF)
        rc = BNS_EPERSIST;
    if (rc == BNS_OK)
        rc = json_g2(f, &p->b);
    if (rc == BNS_OK && fputs(",\n \"pi_c\": ", f) == EOF)
        rc = BNS_EPERSIST;
    if (rc == BNS_OK)
        rc = json_g1(f, &p->c);
    if (rc == BNS_OK &&
        fputs(",\n \"protocol\": \"groth16\",\n \"curve\": \"bn128\"\n}\n", f) == EOF)
        rc = BNS_EPERSIST;
    if (fclose(f) != 0 && rc == BNS_OK)
        rc = BNS_EPERSIST;
    return rc;
}

/* Serialize the verifying key to a snarkjs verification_key.json. vk_alphabeta_12
 * is intentionally omitted: `snarkjs groth16 verify` consumes vk_alpha_1/vk_beta_2
 * directly and does not require the precomputed pairing (verified empirically). */
static int write_vkey_file(const char *path, const g16_verifying_key_t *vk)
{
    FILE *f = fopen(path, "w");
    int rc = BNS_OK;
    if (f == NULL)
        return BNS_EPERSIST;
    /* nPublic is BONSAI_G16_N (==1); the vk gate already pinned n_public==1. */
    if (fputs("{\n \"protocol\": \"groth16\",\n \"curve\": \"bn128\",\n"
              " \"nPublic\": 1,\n \"vk_alpha_1\": ", f) == EOF)
        rc = BNS_EPERSIST;
    if (rc == BNS_OK)
        rc = json_g1(f, &vk->alpha);
    if (rc == BNS_OK && fputs(",\n \"vk_beta_2\": ", f) == EOF)
        rc = BNS_EPERSIST;
    if (rc == BNS_OK)
        rc = json_g2(f, &vk->beta);
    if (rc == BNS_OK && fputs(",\n \"vk_gamma_2\": ", f) == EOF)
        rc = BNS_EPERSIST;
    if (rc == BNS_OK)
        rc = json_g2(f, &vk->gamma);
    if (rc == BNS_OK && fputs(",\n \"vk_delta_2\": ", f) == EOF)
        rc = BNS_EPERSIST;
    if (rc == BNS_OK)
        rc = json_g2(f, &vk->delta);
    if (rc == BNS_OK && fputs(",\n \"IC\": [", f) == EOF)
        rc = BNS_EPERSIST;
    if (rc == BNS_OK)
        rc = json_g1(f, &vk->gamma_abc[0]);
    if (rc == BNS_OK && fputc(',', f) == EOF)
        rc = BNS_EPERSIST;
    if (rc == BNS_OK)
        rc = json_g1(f, &vk->gamma_abc[1]);
    if (rc == BNS_OK && fputs("]\n}\n", f) == EOF)
        rc = BNS_EPERSIST;
    if (fclose(f) != 0 && rc == BNS_OK)
        rc = BNS_EPERSIST;
    return rc;
}

/* Serialize the public-signal vector to a snarkjs public.json (a JSON array of
 * decimal strings). N==BONSAI_G16_N. */
static int write_public_file(const char *path,
                             const bn_t *const inputs[BONSAI_G16_N])
{
    FILE *f = fopen(path, "w");
    int rc = BNS_OK;
    int i;
    if (f == NULL)
        return BNS_EPERSIST;
    if (fputc('[', f) == EOF)
        rc = BNS_EPERSIST;
    for (i = 0; rc == BNS_OK && i < BONSAI_G16_N; i++) {
        if (i > 0 && fputc(',', f) == EOF) {
            rc = BNS_EPERSIST;
            break;
        }
        rc = json_int(f, inputs[i]);
    }
    if (rc == BNS_OK && fputs("]\n", f) == EOF)
        rc = BNS_EPERSIST;
    if (fclose(f) != 0 && rc == BNS_OK)
        rc = BNS_EPERSIST;
    return rc;
}

/* Read all of `fd` into a fresh NUL-terminated heap buffer (caller frees). Caps
 * accumulation at 1 MiB but keeps draining so the child never blocks on a full
 * pipe. BNS_OK / BNS_ENOMEM / BNS_ENET (read error). */
static int read_all_fd(int fd, char **out)
{
    size_t cap = 4096;
    size_t len = 0;
    char *buf = malloc(cap);
    if (buf == NULL)
        return BNS_ENOMEM;
    for (;;) {
        ssize_t n;
        if (len + 1 >= cap) {
            if (cap >= (1u << 20)) {
                char scratch[4096];
                while (read(fd, scratch, sizeof scratch) > 0)
                    ; /* drain & discard the tail */
                break;
            }
            char *nb = realloc(buf, cap * 2);
            if (nb == NULL) {
                free(buf);
                return BNS_ENOMEM;
            }
            buf = nb;
            cap *= 2;
        }
        n = read(fd, buf + len, cap - len - 1);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            free(buf);
            return BNS_ENET;
        }
        if (n == 0)
            break;
        len += (size_t)n;
    }
    buf[len] = '\0';
    *out = buf;
    return BNS_OK;
}

/* Spawn `npx snarkjs groth16 verify <vkey> <public> <proof>`, capture the merged
 * stdout/stderr, and decode the verdict. Decision is OUTPUT-driven (robust to the
 * logger's ANSI colouring, which splits "snarkJS" from ": OK!"): the clean tokens
 * "Invalid proof" / "OK!" are matched, and an OK verdict additionally requires a
 * clean exit(0). Fail-closed:
 *   BNS_OK + *out_ok=true   -> snarkjs reported OK!
 *   BNS_OK + *out_ok=false  -> snarkjs reported Invalid proof
 *   BNS_EUNSUPPORTED        -> npx could not be spawned (toolchain absent)
 *   BNS_ENET                -> pipe/read setup failure
 *   BNS_ECRYPTO             -> spawned but produced no conclusive verdict */
static int g16_snarkjs_verify(const char *vkey, const char *pub,
                              const char *proof, bool *out_ok)
{
    int pipefd[2];
    posix_spawn_file_actions_t fa;
    pid_t pid;
    int spawn_rc;
    int status;
    int rc;
    char *output = NULL;

    *out_ok = false;
    if (vkey == NULL || pub == NULL || proof == NULL)
        return BNS_EINVAL;

    if (pipe(pipefd) != 0)
        return BNS_ENET;

    if (posix_spawn_file_actions_init(&fa) != 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return BNS_ENET;
    }
    /* child: stdout+stderr -> pipe write end; close the inherited pipe fds. */
    if (posix_spawn_file_actions_adddup2(&fa, pipefd[1], STDOUT_FILENO) != 0 ||
        posix_spawn_file_actions_adddup2(&fa, pipefd[1], STDERR_FILENO) != 0 ||
        posix_spawn_file_actions_addclose(&fa, pipefd[0]) != 0 ||
        posix_spawn_file_actions_addclose(&fa, pipefd[1]) != 0) {
        posix_spawn_file_actions_destroy(&fa);
        close(pipefd[0]);
        close(pipefd[1]);
        return BNS_ENET;
    }

    {
        char *argv[] = { "npx", "snarkjs", "groth16", "verify",
                         (char *)vkey, (char *)pub, (char *)proof, NULL };
        spawn_rc = posix_spawnp(&pid, argv[0], &fa, NULL, argv, environ);
    }
    posix_spawn_file_actions_destroy(&fa);
    close(pipefd[1]);               /* parent never writes */

    if (spawn_rc != 0) {            /* ENOENT etc. — npx not installed/visible. */
        close(pipefd[0]);
        return BNS_EUNSUPPORTED;
    }

    rc = read_all_fd(pipefd[0], &output);
    close(pipefd[0]);
    if (rc != BNS_OK) {
        waitpid(pid, &status, 0);  /* still reap the child */
        return rc;
    }
    if (waitpid(pid, &status, 0) < 0) {
        free(output);
        return BNS_ECRYPTO;
    }

    {
        bool saw_invalid = strstr(output, "Invalid proof") != NULL;
        bool saw_ok = strstr(output, "OK!") != NULL;
        bool exited0 = WIFEXITED(status) && WEXITSTATUS(status) == 0;
        free(output);
        if (saw_invalid)            /* conclusive reject (fail-closed)        */
            return BNS_OK;
        if (saw_ok && exited0) {    /* conclusive accept                      */
            *out_ok = true;
            return BNS_OK;
        }
        return BNS_ECRYPTO;         /* no verdict: usage error / install fail */
    }
}

#endif /* BONSAI_ENABLE_ZK */

/* ------------------------------------------------------------------------- */
/* Public converters                                                          */
/* ------------------------------------------------------------------------- */

int proof_from_snarkjs(const snarkjs_proof_t *p, g16_proof_t *out)
{
#ifndef BONSAI_ENABLE_ZK
    (void)p;
    (void)out;
    return BNS_EUNSUPPORTED;
#else
    int rc;
    if (p == NULL || out == NULL)
        return BNS_EPARSE;
    memset(out, 0, sizeof *out);

    /* a = g1(pi_a); b = g2(pi_b); c = g1(pi_c). */
    rc = g1_from_dec(p->pi_a, &out->a);
    if (rc != BNS_OK)
        goto fail;
    rc = g2_from_dec(p->pi_b, &out->b);
    if (rc != BNS_OK)
        goto fail;
    rc = g1_from_dec(p->pi_c, &out->c);
    if (rc != BNS_OK)
        goto fail;
    return BNS_OK;
fail:
    g16_proof_free(out);
    return rc;
#endif
}

int vk_from_snarkjs(const snarkjs_vkey_t *vk, g16_verifying_key_t *out)
{
#ifndef BONSAI_ENABLE_ZK
    (void)vk;
    (void)out;
    return BNS_EUNSUPPORTED;
#else
    int rc;
    if (vk == NULL || out == NULL)
        return BNS_EPARSE;

    /* Gate: protocol=="groth16" && curve in {bn128,bn254} && nPublic==1.
     * (IC length is fixed at 2 by the wire struct shape.) */
    if (vk->protocol == NULL || strcmp(vk->protocol, "groth16") != 0)
        return BNS_EINVAL;
    if (vk->curve == NULL ||
        (strcmp(vk->curve, "bn128") != 0 && strcmp(vk->curve, "bn254") != 0))
        return BNS_EINVAL;
    if (vk->n_public != 1)
        return BNS_EINVAL;

    memset(out, 0, sizeof *out);

    /* millerb1a1 = miller(twist(beta2), curve(alpha1)) WITHOUT final exp. The
     * Miller loop is computed off-chain by the snarkjs toolchain shell-out (see
     * src/zk/prover.c); the C struct carries a zero placeholder so the field is
     * well-defined. Off-chain verification does not consult this leaf. */
    rc = fq12_zero(&out->miller_b1a1);
    if (rc != BNS_OK)
        goto fail;

    rc = g2_from_dec(vk->vk_gamma_2, &out->gamma);
    if (rc != BNS_OK)
        goto fail;
    rc = g2_from_dec(vk->vk_delta_2, &out->delta);
    if (rc != BNS_OK)
        goto fail;

    /* gammaAbc = [g1(IC[0]), g1(IC[1])]. */
    {
        const char *ic0[2] = { vk->ic[0][0], vk->ic[0][1] };
        const char *ic1[2] = { vk->ic[1][0], vk->ic[1][1] };
        rc = g1_from_dec(ic0, &out->gamma_abc[0]);
        if (rc != BNS_OK)
            goto fail;
        rc = g1_from_dec(ic1, &out->gamma_abc[1]);
        if (rc != BNS_OK)
            goto fail;
    }

    /* Off-chain-only auxiliaries (NOT part of the on-chain flatten): keep the raw
     * alpha1/beta2 so verify_proof_off_chain can re-emit a complete snarkjs vkey.
     * alpha = g1(vk_alpha_1); beta = g2(vk_beta_2) in snarkjs natural coeff order. */
    {
        const char *a1[2] = { vk->vk_alpha_1[0], vk->vk_alpha_1[1] };
        rc = g1_from_dec(a1, &out->alpha);
        if (rc != BNS_OK)
            goto fail;
    }
    rc = g2_from_dec(vk->vk_beta_2, &out->beta);
    if (rc != BNS_OK)
        goto fail;
    return BNS_OK;
fail:
    g16_verifying_key_free(out);
    return rc;
#endif
}

int verify_proof_off_chain(const bn_t *const inputs[BONSAI_G16_N],
                           const g16_proof_t *proof,
                           const g16_verifying_key_t *vk, bool *out_ok)
{
#ifndef BONSAI_ENABLE_ZK
    (void)inputs;
    (void)proof;
    (void)vk;
    if (out_ok != NULL)
        *out_ok = false;
    return BNS_EUNSUPPORTED;
#else
    /* The Groth16 pairing equation e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta)
     * == 1 is verified by serializing the in-memory proof/vk/inputs back into
     * snarkjs JSON in a private mkdtemp dir and shelling out to
     * `npx snarkjs groth16 verify` (the BN254 pairing is deliberately not hand-
     * ported; this mirrors the proving shell-out in src/zk/prover.c). */
    int rc;
    const char *tmpbase;
    char dir[3072];
    char proof_path[4096];
    char vkey_path[4096];
    char pub_path[4096];

    if (out_ok != NULL)
        *out_ok = false;
    if (inputs == NULL || proof == NULL || vk == NULL || out_ok == NULL)
        return BNS_EINVAL;

    /* Private temp dir (honours TMPDIR), 0700 via mkdtemp. */
    tmpbase = getenv("TMPDIR");
    if (tmpbase == NULL || tmpbase[0] == '\0')
        tmpbase = "/tmp";
    if (snprintf(dir, sizeof dir, "%s/bns_g16_XXXXXX", tmpbase) >= (int)sizeof dir)
        return BNS_EPERSIST;
    if (mkdtemp(dir) == NULL)
        return BNS_EPERSIST;

    proof_path[0] = vkey_path[0] = pub_path[0] = '\0';
    rc = BNS_OK;
    if (snprintf(proof_path, sizeof proof_path, "%s/proof.json", dir)
            >= (int)sizeof proof_path ||
        snprintf(vkey_path, sizeof vkey_path, "%s/verification_key.json", dir)
            >= (int)sizeof vkey_path ||
        snprintf(pub_path, sizeof pub_path, "%s/public.json", dir)
            >= (int)sizeof pub_path)
        rc = BNS_EPERSIST;

    if (rc == BNS_OK)
        rc = write_proof_file(proof_path, proof);
    if (rc == BNS_OK)
        rc = write_vkey_file(vkey_path, vk);
    if (rc == BNS_OK)
        rc = write_public_file(pub_path, inputs);
    if (rc == BNS_OK)
        rc = g16_snarkjs_verify(vkey_path, pub_path, proof_path, out_ok);

    /* Clean up (unlink is a no-op for never-created files). */
    if (proof_path[0])
        unlink(proof_path);
    if (vkey_path[0])
        unlink(vkey_path);
    if (pub_path[0])
        unlink(pub_path);
    rmdir(dir);
    return rc;
#endif
}

int verify_proof_off_chain_files(const char *vkey_path, const char *public_path,
                                 const char *proof_path, bool *out_ok)
{
#ifndef BONSAI_ENABLE_ZK
    (void)vkey_path;
    (void)public_path;
    (void)proof_path;
    if (out_ok != NULL)
        *out_ok = false;
    return BNS_EUNSUPPORTED;
#else
    if (out_ok != NULL)
        *out_ok = false;
    if (vkey_path == NULL || public_path == NULL || proof_path == NULL ||
        out_ok == NULL)
        return BNS_EINVAL;
    return g16_snarkjs_verify(vkey_path, public_path, proof_path, out_ok);
#endif
}

/* ------------------------------------------------------------------------- */
/* Lifecycle                                                                  */
/* ------------------------------------------------------------------------- */

void g16_proof_free(g16_proof_t *p)
{
    if (p == NULL)
        return;
#ifdef BONSAI_ENABLE_ZK
    g1_clear(&p->a);
    g2_clear(&p->b);
    g1_clear(&p->c);
#else
    memset(p, 0, sizeof *p);
#endif
}

void g16_verifying_key_free(g16_verifying_key_t *vk)
{
    if (vk == NULL)
        return;
#ifdef BONSAI_ENABLE_ZK
    fq12_clear(&vk->miller_b1a1);
    g2_clear(&vk->gamma);
    g2_clear(&vk->delta);
    g1_clear(&vk->gamma_abc[0]);
    g1_clear(&vk->gamma_abc[1]);
    g1_clear(&vk->alpha);
    g2_clear(&vk->beta);
#else
    memset(vk, 0, sizeof *vk);
#endif
}
