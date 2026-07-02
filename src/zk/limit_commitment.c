/*
 * limit_commitment.c — the hiding commitment limitCommitment = MiMC7(limit,
 * salt) with a fresh ~248-bit CSPRNG salt, ported from
 * chain/src/zk/limitCommitment.ts (commitLimit).
 *
 * Field/byte-exactness pins (see include/zk/limit_commitment.h):
 *  - salt = big-endian unsigned of 31 CSPRNG bytes (248 bits) reduced mod r.
 *    Since 2^248 < r the `% r` is a defensive no-op — the draw is already a
 *    valid field element, uniform over [0, 2^248), with ZERO modulo bias.
 *    Matches randomFieldElement(): BigInt('0x'+randomBytes(31).toString('hex'))
 *    % Mimc7.SNARK_SCALAR_FIELD (the 31 bytes are interpreted big-endian).
 *  - commitment = MiMC7(limit, salt) over the SCALAR field r.
 *  - limit < 0 => BNS_EINVAL ('limit must be non-negative').
 */
#include "zk/limit_commitment.h"

#include <stdlib.h>

#include "crypto/bignum.h"
#include "crypto/rand.h"
#include "zk/mimc7.h"

/* 31 bytes = 248 bits of entropy, matching randomBytes(31) in the TS. */
#define LIMIT_SALT_BYTES 31

int commit_limit(const bn_t *limit, bn_t **out_commitment, bn_t **out_salt)
{
    bn_t *zero = NULL;
    bn_t *r = NULL;
    bn_t *salt_raw = NULL;
    bn_t *salt = NULL;
    bn_t *commitment = NULL;
    uint8_t saltbuf[LIMIT_SALT_BYTES];
    int rc;

    if (limit == NULL || out_commitment == NULL || out_salt == NULL)
        return BNS_EINVAL;

    /* limit < 0 => error ('limit must be non-negative'). */
    zero = bn_new();
    if (zero == NULL)
        return BNS_ENOMEM;
    if (bn_cmp(limit, zero) < 0) {
        bn_free(zero);
        return BNS_EINVAL;
    }
    bn_free(zero);
    zero = NULL;

    /* Draw 31 CSPRNG bytes; interpret big-endian (BigInt('0x'+hex)). */
    rc = rand_bytes(saltbuf, sizeof saltbuf);
    if (rc != BNS_OK)
        return BNS_ECRYPTO;

    rc = bn_parse_be(saltbuf, sizeof saltbuf, &salt_raw);
    if (rc != BNS_OK)
        goto done;

    /* salt = salt_raw % r (a no-op since 2^248 < r, but kept verbatim). */
    rc = mimc7_scalar_field(&r);
    if (rc != BNS_OK)
        goto done;
    rc = bn_mod(salt_raw, r, &salt);
    if (rc != BNS_OK)
        goto done;

    /* commitment = MiMC7(limit, salt). */
    rc = mimc7_hash(limit, salt, &commitment);
    if (rc != BNS_OK)
        goto done;

    *out_commitment = commitment;
    commitment = NULL;
    *out_salt = salt;
    salt = NULL;

done:
    bn_free(salt_raw);
    bn_free(salt);
    bn_free(commitment);
    bn_free(r);
    return rc;
}
