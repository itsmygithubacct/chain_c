/*
 * contracts/rabin_spike.c — the RabinSpike proof-of-concept contract.
 *
 * Port of src/contracts/rabinSpike.ts: one oracle Rabin pubkey @prop and an
 * unlock(msg, sig) that asserts RabinVerifier.verifySig(msg, sig, oraclePubKey).
 *
 * The locking script is reconstructed from the compiled artifact
 * (artifacts/rabinSpike.json, template starts with the literal "<oraclePubKey>")
 * by substituting the serialized Rabin modulus n via the opcode-optimized
 * CONSTRUCTOR int encoder (script_codec to_script_hex). The contract is
 * stateless (artifact stateProps is empty), so no state suffix is appended.
 *
 * The off-chain model of unlock() delegates to the shared rabin_verifier
 * (lib/rabin_verifier.h), which mirrors scrypt-ts-lib RabinVerifier.verifySig.
 */
#include "contracts/rabin_spike.h"

#include "scrypt/artifact_loader.h" /* (only for documentation of the model)   */
#include "scrypt/script_codec.h"

void rabin_spike_free(rabin_spike_t *c)
{
    if (!c) {
        return;
    }
    bn_free(c->oracle_pubkey);
    c->oracle_pubkey = NULL;
    c->artifact = NULL;
}

int rabin_spike_locking_script(const rabin_spike_t *c, byte_buf_t *out)
{
    if (!c || !c->artifact || !c->oracle_pubkey || !out) {
        return BNS_EINVAL;
    }

    /* The single constructor argument `oraclePubKey`. The artifact declares it as
     * scrypt `int` (a RabinPubKey is an int alias), so the value tag must be
     * SCRYPT_TYPE_INT — flatten_args validates the value tag against the resolved
     * ctor-param type, and to_script_hex emits the same opcode-optimized int push
     * for INT and RABIN_PUBKEY alike. The bn_t is BORROWED by the arg; we do NOT
     * transfer ownership and scrypt_arg_free is therefore not called on it. */
    scrypt_arg_t ctor_arg = {0};
    ctor_arg.tag = SCRYPT_TYPE_INT;
    ctor_arg.as.int_val = c->oracle_pubkey;

    /* Stateless contract: no state values, is_genesis ignored. */
    return reconstruct_locking_script(c->artifact,
                                      &ctor_arg, 1,
                                      NULL, 0,
                                      false,
                                      out);
}

bool rabin_spike_unlock_verify(const rabin_spike_t *c,
                               const uint8_t *msg, size_t msg_len,
                               const rabin_verifier_sig_t *sig)
{
    /* Fail-closed on any malformed input (TS assert => abort on bad witness). */
    if (!c || !c->oracle_pubkey || !sig) {
        return false;
    }
    if (!msg && msg_len != 0) {
        return false;
    }

    /* unlock(): assert(RabinVerifier.verifySig(msg, sig, this.oraclePubKey)).
     * The verified preimage is exactly msg || sig.padding — no extra framing. */
    return rabin_verifier_verify_sig(msg, msg_len, sig, c->oracle_pubkey);
}
