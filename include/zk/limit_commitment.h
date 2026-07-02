/*
 * limit_commitment.h — produce the hiding commitment limitCommitment =
 * MiMC7(limit, salt) with a fresh ~248-bit CSPRNG salt: the only correct way to
 * generate the secret-limit commitment a ZkHiddenLimit identity pins at deploy.
 *
 * TS origin: src/zk/limitCommitment.ts (commitLimit) over zk/mimc7.h.
 *
 * PINS (module notes):
 *  - salt = big-endian unsigned of 31 CSPRNG bytes (248 bits) mod r (the mod is
 *    a no-op since 2^248 < r); uniform over [0, 2^248). Use a real CSPRNG.
 *  - commitment = MiMC7(limit, salt) over the SCALAR field r.
 *  - limit < 0 => error ('limit must be non-negative').
 */
#ifndef BONSAI_ZK_LIMIT_COMMITMENT_H
#define BONSAI_ZK_LIMIT_COMMITMENT_H

#include "common/error.h"
#include "crypto/bignum.h"     /* bn_t */

/* commitLimit(limit): draw a fresh 248-bit salt and return commitment =
 * MiMC7(limit, salt) and the salt, both as fresh bn_t via *out_commitment /
 * *out_salt (caller frees each). `limit` must be a non-negative bn_t else
 * BNS_EINVAL. TS: limitCommitment.ts::commitLimit.
 * BNS_OK / BNS_EINVAL (limit<0) / BNS_ECRYPTO (CSPRNG) / BNS_ENOMEM. */
int commit_limit(const bn_t *limit, bn_t **out_commitment, bn_t **out_salt);

#endif /* BONSAI_ZK_LIMIT_COMMITMENT_H */
