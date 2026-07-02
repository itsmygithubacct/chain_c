/*
 * stake_policy.c — consumer-side economic floor predicates
 * (ECONOMIC-CALIBRATION §2.3/§8.1, §3.2).
 *
 * Port of src/verifier/stakePolicy.ts. Pure arithmetic over satoshi amounts.
 *
 * TS uses arbitrary-precision BigInt; we model amounts as int64_t. The only
 * arithmetic that can leave int64_t range is VALIDATOR_STAKE_MULTIPLIER *
 * perTxLimit. TS BigInt never overflows, so to stay faithful we compute the
 * product in 128-bit and compare against stakedSats promoted to 128-bit —
 * giving the same answer TS would for every input that fits these int64_t
 * fields. The guard order (negative/non-positive returns false BEFORE the
 * comparison) mirrors the TS exactly.
 */
#include "verifier/stake_policy.h"

bool meets_validator_stake_floor(int64_t staked_sats, int64_t per_tx_limit)
{
    /* if (stakedSats < 0n || perTxLimit <= 0n) return false */
    if (staked_sats < 0 || per_tx_limit <= 0) {
        return false;
    }
    /* return stakedSats >= VALIDATOR_STAKE_MULTIPLIER * perTxLimit
     * Compute the product in 128-bit to match TS's unbounded BigInt: per_tx_limit
     * is > 0 here, multiplier is +4, so the product is a non-negative 128-bit
     * value that cannot wrap. */
    __int128 floor = (__int128)BONSAI_VALIDATOR_STAKE_MULTIPLIER * (__int128)per_tx_limit;
    return (__int128)staked_sats >= floor;
}

bool meets_attestor_bond_floor(int64_t bond_sats)
{
    /* return bondSats >= ATTESTOR_BOND_FLOOR_SATS (a negative bond returns false
     * via the comparison). */
    return bond_sats >= BONSAI_ATTESTOR_BOND_FLOOR_SATS;
}
