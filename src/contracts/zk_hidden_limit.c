/*
 * contracts/zk_hidden_limit.c — the Pillar-B "hidden policy limit" companion
 * contract: locking-script reconstruction (vk + limitCommitment substituted
 * into the compiled BN254-Groth16 artifact) and the off-chain model of
 * attest(amount, proof). Ported from chain/src/contracts/zkHiddenLimit.ts.
 *
 * SCOPE / COMPILE GUARD (see include/contracts/zk_hidden_limit.h + include/zk/g16.h):
 *  - The Groth16 verifying key + proof are referenced through this header as the
 *    OPAQUE handles g16_vk_t / g16_proof_t. Their full BN254-tower definitions
 *    (g16_verifying_key_t / g16_proof_t in include/zk/g16.h) and the heavy pairing
 *    arithmetic are gated behind BONSAI_ENABLE_ZK; that header's g16_proof_t
 *    typedef collides with this module's opaque g16_proof_t, so this TU does NOT
 *    #include "zk/g16.h". Instead it forward-declares exactly the g16 entry
 *    points it needs, expressed in terms of the opaque handles (identical link
 *    symbols; the BN254 layout is treated as opaque here).
 *  - When BONSAI_ENABLE_ZK is NOT defined, both the locking-script reconstruction
 *    and the proof-verify path return BNS_EUNSUPPORTED cleanly. The amount>0
 *    precondition is still enforced first in attest (cheap, no pairing work),
 *    matching the in-script assertion ordering.
 *
 * DETERMINISM / BYTE-LAYOUT PINS (zkHiddenLimit.ts notes):
 *  - 2 ctor args in @prop declaration order: vk (VerifyingKey struct) then
 *    limitCommitment (int). The contract is STATELESS (stateProps == []), so no
 *    state blob is appended; is_genesis is irrelevant.
 *  - VerifyingKey flattens depth-first to: millerb1a1(FQ12 -> 12 ints),
 *    gamma(G2 -> 4 ints), delta(G2 -> 4 ints), gammaAbc(G1Point[2] -> 4 ints),
 *    matching the artifact structs table (FQ12{x,y}/FQ6{x,y,z}/FQ2{x,y},
 *    G2Point{x,y}, G1Point{x,y}). Each leaf is a SCRYPT_TYPE_INT (Fp base-field
 *    element) encoded by the opcode-optimized ctor int encoder.
 *  - attest: assert amount>0; input = Mimc7.hash(amount, limitCommitment) over
 *    the SCALAR field r; inputs=[input]; G16BN256.verify(inputs, proof, vk).
 */
#include "contracts/zk_hidden_limit.h"

#include <stdlib.h>
#include <string.h>

#ifdef BONSAI_ENABLE_ZK
#include "zk/mimc7.h"               /* mimc7_hash over the scalar field r */
#include "scrypt/script_codec.h"    /* reconstruct_locking_script         */

/*
 * Forward declarations of the include/zk/g16.h entry points this module needs,
 * expressed through the opaque handles from contracts/zk_hidden_limit.h so the
 * (large) BN254 tower header is not pulled in (and its conflicting g16_proof_t
 * typedef is avoided). These match the link symbols emitted by src/zk/g16.c:
 *   int verify_proof_off_chain(const bn_t *const inputs[1],
 *                              const g16_proof_t *proof,
 *                              const g16_verifying_key_t *vk, bool *out_ok);
 * The pairing-tower layout is treated as opaque here; only pointers cross.
 */
extern int verify_proof_off_chain(const bn_t *const inputs[1],
                                  const g16_proof_t *proof,
                                  const g16_vk_t *vk, bool *out_ok);
#endif /* BONSAI_ENABLE_ZK */

/* ---- lifecycle ----------------------------------------------------------- */

void zk_hidden_limit_free(zk_hidden_limit_t *c)
{
    if (c == NULL)
        return;
    bn_free(c->limit_commitment);
    /* artifact and vk are borrowed; not freed here. */
    memset(c, 0, sizeof *c);
}

/* ---- locking-script reconstruction --------------------------------------- */

#ifdef BONSAI_ENABLE_ZK

/* The opaque g16_vk_t is, at link time, an include/zk/g16.h g16_verifying_key_t.
 * Mirror just enough of that layout to read its bn_t leaves for the locking
 * script. This MUST stay field-for-field identical to include/zk/g16.h's
 * fq2_t/fq6_t/fq12_t/g1_point_t/g2_point_t/g16_verifying_key_t (it is exercised
 * by the same artifact/struct flatten order the on-chain script uses). */
typedef struct { bn_t *x; bn_t *y; }                 zkl_fq2_t;
typedef struct { zkl_fq2_t x; zkl_fq2_t y; zkl_fq2_t z; } zkl_fq6_t;
typedef struct { zkl_fq6_t x; zkl_fq6_t y; }         zkl_fq12_t;
typedef struct { bn_t *x; bn_t *y; }                 zkl_g1_t;
typedef struct { zkl_fq2_t x; zkl_fq2_t y; }         zkl_g2_t;
typedef struct {
    zkl_fq12_t miller_b1a1;
    zkl_g2_t   gamma;
    zkl_g2_t   delta;
    zkl_g1_t   gamma_abc[2];
} zkl_vk_t;

/* Initialize a SCRYPT_TYPE_INT leaf as a duplicate of src (an Fp element). */
static int zkl_arg_int_dup(scrypt_arg_t *out, const bn_t *src)
{
    memset(out, 0, sizeof *out);
    out->tag = SCRYPT_TYPE_INT;
    return bn_dup(src, &out->as.int_val);
}

/* Build a struct-typed arg shell (struct_name owned, fields array allocated). */
static int zkl_arg_struct(scrypt_arg_t *out, const char *name, size_t nfields)
{
    memset(out, 0, sizeof *out);
    out->tag = SCRYPT_TYPE_STRUCT;
    out->as.st.struct_name = NULL;
    out->as.st.fields = NULL;
    out->as.st.num_fields = 0;
    out->as.st.struct_name = malloc(strlen(name) + 1);
    if (out->as.st.struct_name == NULL)
        return BNS_ENOMEM;
    strcpy(out->as.st.struct_name, name);
    out->as.st.fields = calloc(nfields, sizeof(scrypt_arg_t));
    if (out->as.st.fields == NULL) {
        free(out->as.st.struct_name);
        out->as.st.struct_name = NULL;
        return BNS_ENOMEM;
    }
    out->as.st.num_fields = nfields;
    return BNS_OK;
}

/* Build a FixedArray-typed arg shell of `count` elements. */
static int zkl_arg_array(scrypt_arg_t *out, size_t count)
{
    memset(out, 0, sizeof *out);
    out->tag = SCRYPT_TYPE_FIXED_ARRAY;
    out->as.array.elems = calloc(count, sizeof(scrypt_arg_t));
    if (out->as.array.elems == NULL)
        return BNS_ENOMEM;
    out->as.array.count = count;
    return BNS_OK;
}

/* FQ2{x,y} -> struct "FQ2" with two int leaves. */
static int zkl_build_fq2(scrypt_arg_t *out, const zkl_fq2_t *f)
{
    int rc = zkl_arg_struct(out, "FQ2", 2);
    if (rc != BNS_OK)
        return rc;
    rc = zkl_arg_int_dup(&out->as.st.fields[0], f->x);
    if (rc != BNS_OK)
        return rc;
    return zkl_arg_int_dup(&out->as.st.fields[1], f->y);
}

/* FQ6{x,y,z} -> struct "FQ6" with three FQ2 fields. */
static int zkl_build_fq6(scrypt_arg_t *out, const zkl_fq6_t *f)
{
    int rc = zkl_arg_struct(out, "FQ6", 3);
    if (rc != BNS_OK)
        return rc;
    rc = zkl_build_fq2(&out->as.st.fields[0], &f->x);
    if (rc != BNS_OK)
        return rc;
    rc = zkl_build_fq2(&out->as.st.fields[1], &f->y);
    if (rc != BNS_OK)
        return rc;
    return zkl_build_fq2(&out->as.st.fields[2], &f->z);
}

/* FQ12{x,y} -> struct "FQ12" with two FQ6 fields. */
static int zkl_build_fq12(scrypt_arg_t *out, const zkl_fq12_t *f)
{
    int rc = zkl_arg_struct(out, "FQ12", 2);
    if (rc != BNS_OK)
        return rc;
    rc = zkl_build_fq6(&out->as.st.fields[0], &f->x);
    if (rc != BNS_OK)
        return rc;
    return zkl_build_fq6(&out->as.st.fields[1], &f->y);
}

/* G2Point{x:FQ2, y:FQ2} -> struct "G2Point". */
static int zkl_build_g2(scrypt_arg_t *out, const zkl_g2_t *p)
{
    int rc = zkl_arg_struct(out, "G2Point", 2);
    if (rc != BNS_OK)
        return rc;
    rc = zkl_build_fq2(&out->as.st.fields[0], &p->x);
    if (rc != BNS_OK)
        return rc;
    return zkl_build_fq2(&out->as.st.fields[1], &p->y);
}

/* G1Point{x:int, y:int} -> struct "G1Point". */
static int zkl_build_g1(scrypt_arg_t *out, const zkl_g1_t *p)
{
    int rc = zkl_arg_struct(out, "G1Point", 2);
    if (rc != BNS_OK)
        return rc;
    rc = zkl_arg_int_dup(&out->as.st.fields[0], p->x);
    if (rc != BNS_OK)
        return rc;
    return zkl_arg_int_dup(&out->as.st.fields[1], p->y);
}

/* VerifyingKey{millerb1a1:FQ12, gamma:G2Point, delta:G2Point,
 * gammaAbc:G1Point[2]} -> struct "VerifyingKey" (declaration order). */
static int zkl_build_vk(scrypt_arg_t *out, const zkl_vk_t *vk)
{
    int rc = zkl_arg_struct(out, "VerifyingKey", 4);
    if (rc != BNS_OK)
        return rc;
    rc = zkl_build_fq12(&out->as.st.fields[0], &vk->miller_b1a1);
    if (rc != BNS_OK)
        return rc;
    rc = zkl_build_g2(&out->as.st.fields[1], &vk->gamma);
    if (rc != BNS_OK)
        return rc;
    rc = zkl_build_g2(&out->as.st.fields[2], &vk->delta);
    if (rc != BNS_OK)
        return rc;
    /* gammaAbc: G1Point[2] FixedArray. */
    rc = zkl_arg_array(&out->as.st.fields[3], 2);
    if (rc != BNS_OK)
        return rc;
    rc = zkl_build_g1(&out->as.st.fields[3].as.array.elems[0], &vk->gamma_abc[0]);
    if (rc != BNS_OK)
        return rc;
    return zkl_build_g1(&out->as.st.fields[3].as.array.elems[1], &vk->gamma_abc[1]);
}

#endif /* BONSAI_ENABLE_ZK */

int zk_hidden_limit_locking_script(const zk_hidden_limit_t *c, byte_buf_t *out)
{
    if (c == NULL || c->artifact == NULL || c->vk == NULL ||
        c->limit_commitment == NULL || out == NULL)
        return BNS_EINVAL;

#ifndef BONSAI_ENABLE_ZK
    return BNS_EUNSUPPORTED;
#else
    const zkl_vk_t *vk = (const zkl_vk_t *)c->vk;

    /* 2 ctor args, @prop declaration order: vk (VerifyingKey), limitCommitment. */
    scrypt_arg_t cv[2];
    memset(cv, 0, sizeof cv);
    int rc = zkl_build_vk(&cv[0], vk);
    if (rc == BNS_OK) {
        cv[1].tag = SCRYPT_TYPE_INT;
        rc = bn_dup(c->limit_commitment, &cv[1].as.int_val);
    }

    if (rc == BNS_OK)
        rc = reconstruct_locking_script(c->artifact, cv, 2,
                                        NULL, 0, false, out);

    scrypt_arg_free(&cv[0]);
    scrypt_arg_free(&cv[1]);
    return rc;
#endif
}

/* ---- attest (off-chain model) -------------------------------------------- */

int zk_hidden_limit_attest_verify(const zk_hidden_limit_t *c,
                                  const bn_t *amount,
                                  const g16_proof_t *proof,
                                  bool *out_ok)
{
    if (c == NULL || c->vk == NULL || c->limit_commitment == NULL ||
        amount == NULL || proof == NULL || out_ok == NULL)
        return BNS_EINVAL;
    *out_ok = false;

    /* assert(amount > 0n, 'attest: amount must be positive') — enforced FIRST,
     * before any (expensive / possibly-compiled-out) pairing work, mirroring the
     * in-script assertion order. amount<=0 (zero or negative) => BNS_EINVAL. */
    if (bn_is_zero(amount))
        return BNS_EINVAL;
    {
        bn_t *zero = bn_new();
        if (zero == NULL)
            return BNS_ENOMEM;
        int neg = bn_cmp(amount, zero) < 0;
        bn_free(zero);
        if (neg)
            return BNS_EINVAL;
    }

#ifndef BONSAI_ENABLE_ZK
    return BNS_EUNSUPPORTED;
#else
    /* input = Mimc7.hash(amount, this.limitCommitment) over the scalar field r. */
    bn_t *input = NULL;
    int rc = mimc7_hash(amount, c->limit_commitment, &input);
    if (rc != BNS_OK)
        return rc;

    /* inputs = [input]; G16BN256.verify(inputs, proof, vk). */
    const bn_t *const inputs[1] = { input };
    rc = verify_proof_off_chain(inputs, proof, c->vk, out_ok);

    bn_free(input);
    return rc;
#endif
}
