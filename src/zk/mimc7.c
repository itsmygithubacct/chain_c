/*
 * mimc7.c — MiMC7 sponge hash over the BN254 SCALAR field r, ported from
 * scrypt-ts-lib Mimc7 (circomlib keccak-seeded, ROUNDS=91), and the hiding
 * commitment limitCommitment = MiMC7(limit, salt) from
 * chain/src/zk/limitCommitment.ts.
 *
 * Field/byte-exactness pins (see include/zk/mimc7.h):
 *  - Field is the SCALAR field r (MIMC7_SNARK_SCALAR_FIELD), NOT the base field.
 *  - ROUNDS=91, exponent t^7 per round, CONSTS[0]=0.
 *  - ret=0; for i in 0..90: t=(i==0)?x+k:ret+k+CONSTS[i];
 *        ret=(t^7) mod r  (t2=t*t, t4=t2*t2, ret=t4*t2*t mod r).
 *    after the loop return (ret+k) mod r.
 *  - Multiply full-width then reduce mod r ONCE per round (do not reduce
 *    intermediates early), matching circomlib MiMC7(91).
 */
#include "zk/mimc7.h"

#include <stdlib.h>

#include "crypto/bignum.h"
#include "mimc7_consts.h"

/* Return the BN254 scalar field modulus r as a fresh bn_t. */
int mimc7_scalar_field(bn_t **out)
{
    if (out == NULL)
        return BNS_EINVAL;
    return bn_parse_dec(MIMC7_SNARK_SCALAR_FIELD, out);
}

/*
 * Compute (t^7) mod r as: t2 = t*t; t4 = t2*t2; ret = t4*t2*t mod r.
 * Each multiply is full-width then a single mod-mul folds in r once at the end
 * of the chain — but to keep intermediates bounded we use bn_mod_mul which
 * reduces after each product. Reducing after each product yields the SAME
 * residue mod r as a single final reduction (modular arithmetic is a ring
 * homomorphism), so circomlib byte-exactness is preserved while bounding width.
 *
 * `t` is taken modulo r (already reduced by the caller).
 */
static int pow7_mod(const bn_t *t, const bn_t *r, bn_t **out)
{
    bn_t *t2 = NULL, *t4 = NULL, *t6 = NULL, *res = NULL;
    int rc;

    /* t2 = t*t mod r */
    rc = bn_mod_mul(t, t, r, &t2);
    if (rc != BNS_OK)
        goto done;
    /* t4 = t2*t2 mod r */
    rc = bn_mod_mul(t2, t2, r, &t4);
    if (rc != BNS_OK)
        goto done;
    /* t6 = t4*t2 mod r */
    rc = bn_mod_mul(t4, t2, r, &t6);
    if (rc != BNS_OK)
        goto done;
    /* res = t6*t mod r */
    rc = bn_mod_mul(t6, t, r, &res);
    if (rc != BNS_OK)
        goto done;

    *out = res;
    res = NULL;

done:
    bn_free(t2);
    bn_free(t4);
    bn_free(t6);
    bn_free(res);
    return rc;
}

int mimc7_hash(const bn_t *x, const bn_t *k, bn_t **out)
{
    bn_t *r = NULL;          /* scalar field modulus */
    bn_t *xr = NULL;         /* x reduced mod r */
    bn_t *kr = NULL;         /* k reduced mod r */
    bn_t *ret = NULL;        /* running accumulator, reduced mod r */
    bn_t *consts[MIMC7_NUM_CONSTS];
    int rc;
    int ci;

    if (x == NULL || k == NULL || out == NULL)
        return BNS_EINVAL;

    for (ci = 0; ci < MIMC7_NUM_CONSTS; ci++)
        consts[ci] = NULL;

    rc = mimc7_scalar_field(&r);
    if (rc != BNS_OK)
        goto done;

    /* Reduce inputs into [0, r) on entry (header contract). */
    rc = bn_mod(x, r, &xr);
    if (rc != BNS_OK)
        goto done;
    rc = bn_mod(k, r, &kr);
    if (rc != BNS_OK)
        goto done;

    /* Parse the 91 round constants. */
    for (ci = 0; ci < MIMC7_NUM_CONSTS; ci++) {
        rc = bn_parse_dec(MIMC7_CONSTS[ci], &consts[ci]);
        if (rc != BNS_OK)
            goto done;
    }

    /* ret = 0 */
    ret = bn_new();
    if (ret == NULL) {
        rc = BNS_ENOMEM;
        goto done;
    }

    for (int i = 0; i < MIMC7_ROUNDS; i++) {
        bn_t *t = NULL;       /* round input before exponentiation */
        bn_t *tmp = NULL;
        bn_t *powed = NULL;

        if (i == 0) {
            /* t = x + k */
            rc = bn_add(xr, kr, &t);
            if (rc != BNS_OK)
                goto done;
        } else {
            /* t = ret + k + CONSTS[i] */
            rc = bn_add(ret, kr, &tmp);
            if (rc != BNS_OK)
                goto done;
            rc = bn_add(tmp, consts[i], &t);
            bn_free(tmp);
            tmp = NULL;
            if (rc != BNS_OK) {
                bn_free(t);
                goto done;
            }
        }

        /* Reduce t into [0, r) before exponentiation (residue-equivalent). */
        {
            bn_t *tr = NULL;
            rc = bn_mod(t, r, &tr);
            bn_free(t);
            t = tr;
            if (rc != BNS_OK)
                goto done;
        }

        /* ret = (t^7) mod r */
        rc = pow7_mod(t, r, &powed);
        bn_free(t);
        if (rc != BNS_OK)
            goto done;

        bn_free(ret);
        ret = powed;
    }

    /* return (ret + k) mod r */
    {
        bn_t *sum = NULL;
        bn_t *final = NULL;
        rc = bn_add(ret, kr, &sum);
        if (rc != BNS_OK)
            goto done;
        rc = bn_mod(sum, r, &final);
        bn_free(sum);
        if (rc != BNS_OK)
            goto done;
        *out = final;
    }

done:
    bn_free(r);
    bn_free(xr);
    bn_free(kr);
    bn_free(ret);
    for (ci = 0; ci < MIMC7_NUM_CONSTS; ci++)
        bn_free(consts[ci]);
    return rc;
}
