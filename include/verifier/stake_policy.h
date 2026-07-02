/*
 * stake_policy.h — consumer-side economic floor policy (ECONOMIC-CALIBRATION
 * 2.3/8.1): calibrated constants + two predicates deciding whether a validator's
 * stake / an attestor's bond meets the floor required to count its attestations.
 * Pure arithmetic over satoshi amounts, no I/O.
 *
 * TS origin: src/verifier/stakePolicy.ts (VALIDATOR_STAKE_MULTIPLIER,
 * ATTESTOR_BOND_FLOOR_SATS, meetsValidatorStakeFloor, meetsAttestorBondFloor).
 *
 * PINS (module notes):
 *  - Comparisons are TS bigint; modelled as int64_t. The 4*perTxLimit multiply
 *    can overflow for absurd inputs — the impl guards it (faithful to TS's
 *    arbitrary precision).
 *  - Inclusive >= floors; strict guards (perTxLimit<=0 and stakedSats<0 both
 *    return false). A false result means 'treat as unstaked', NOT an error.
 *  - Constants must stay in sync with docs/ECONOMIC-CALIBRATION.md.
 */
#ifndef BONSAI_VERIFIER_STAKE_POLICY_H
#define BONSAI_VERIFIER_STAKE_POLICY_H

#include <stdint.h>
#include <stdbool.h>

/* Calibrated validator stake multiplier: S_v >= 4 * perTxLimit (p_d=0.5,
 * beta=1/2). TS: stakePolicy.ts::VALIDATOR_STAKE_MULTIPLIER (4n). */
#define BONSAI_VALIDATOR_STAKE_MULTIPLIER ((int64_t)4)

/* Absolute attestor bond floor in satoshis (10,000,000), ECONOMIC-CALIBRATION
 * 3.2. TS: stakePolicy.ts::ATTESTOR_BOND_FLOOR_SATS (10_000_000n). */
#define BONSAI_ATTESTOR_BOND_FLOOR_SATS ((int64_t)10000000)

/* true iff stakedSats >= 4*perTxLimit; false (NOT error) if stakedSats<0 or
 * perTxLimit<=0. Inclusive floor, strict guards. Pure predicate.
 * TS: stakePolicy.ts::meetsValidatorStakeFloor. */
bool meets_validator_stake_floor(int64_t staked_sats, int64_t per_tx_limit);

/* true iff bondSats >= 10,000,000 (inclusive; a negative bond returns false via
 * the comparison). Pure predicate. TS: stakePolicy.ts::meetsAttestorBondFloor. */
bool meets_attestor_bond_floor(int64_t bond_sats);

#endif /* BONSAI_VERIFIER_STAKE_POLICY_H */
