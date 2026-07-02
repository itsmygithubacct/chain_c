pragma circom 2.0.0;

include "circomlib/circuits/mimc.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/*
 * WithinLimit — the Pillar B "hidden limit" compliance circuit
 * (docs/gdpr-zk-outline.md Part B; statement chosen per the B0 decision:
 * the LIMIT is the private policy, the action cost is public).
 *
 * Statement: "this action's cost is within a secret limit committed on-chain"
 *
 *   private witnesses: cost, limit, salt
 *   public output (the single G16BN256 input):
 *       out = MiMC7(cost, MiMC7(limit, salt))
 *
 * Binding with N = 1: the verifying CONTRACT recomputes `out` in-script from
 * the cleartext `amount` it is metering and the `limitCommitment` pinned as a
 * @prop at deploy (= MiMC7(limit, salt)). By MiMC7 collision resistance, a
 * proof can only satisfy that public input if the circuit's `cost` equals the
 * cleartext amount and the prover knows an opening (limit, salt) of the
 * commitment with cost <= limit. The limit itself never appears on-chain.
 *
 * Range constraints: LessEqThan(64) is only sound for inputs already known to
 * fit 64 bits, so both cost and limit are explicitly bit-decomposed first —
 * without this a malicious prover could wrap around the field.
 */
template WithinLimit() {
    signal input cost;   // private; equals the cleartext metered amount (bound via `out`)
    signal input limit;  // private; the hidden policy threshold
    signal input salt;   // private; commitment blinding
    signal output out;   // public: MiMC7(cost, MiMC7(limit, salt))

    // Range-check both comparands to 64 bits (satoshi-scale values fit easily).
    component costBits = Num2Bits(64);
    costBits.in <== cost;
    component limitBits = Num2Bits(64);
    limitBits.in <== limit;

    // The compliance predicate: cost <= limit.
    component leq = LessEqThan(64);
    leq.in[0] <== cost;
    leq.in[1] <== limit;
    leq.out === 1;

    // The limit commitment (what the contract pins at deploy).
    component limitCommit = MiMC7(91);
    limitCommit.x_in <== limit;
    limitCommit.k <== salt;

    // The public binding of (cost, commitment) into one field element.
    component bind = MiMC7(91);
    bind.x_in <== cost;
    bind.k <== limitCommit.out;
    out <== bind.out;
}

component main = WithinLimit();
