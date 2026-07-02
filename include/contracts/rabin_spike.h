/*
 * contracts/rabin_spike.h — the RabinSpike proof-of-concept contract: one oracle
 * Rabin pubkey @prop and an unlock(msg, sig) that asserts the Rabin signature.
 * The simplest end-to-end RabinVerifier test vector; the locking script is
 * reconstructed from artifacts/rabinSpike.json (template starts '<oraclePubKey>').
 *
 * TS origin: src/contracts/rabinSpike.ts (RabinSpike, oraclePubKey, constructor,
 * unlock); the in-contract check is RabinVerifier.verifySig (lib/rabin_verifier.h).
 *
 * NOTE: the artifact ABI has exactly two entries (constructor + unlock). The
 * single ctor arg `oraclePubKey` is a RabinPubKey (bigint) encoded as the
 * opcode-optimized CONSTRUCTOR int (script_codec.h), NOT the state encoder.
 */
#ifndef BONSAI_CONTRACTS_RABIN_SPIKE_H
#define BONSAI_CONTRACTS_RABIN_SPIKE_H

#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/bignum.h"
#include "crypto/rabin.h"
#include "scrypt/scrypt_contract.h"
#include "lib/rabin_verifier.h"

/* A live RabinSpike instance: the loaded artifact bound to the single oracle
 * Rabin pubkey. `oracle_pubkey` is an owned bn_t; the artifact is borrowed.
 * TS: an instantiated RabinSpike SmartContract. */
typedef struct {
    const scrypt_artifact_t *artifact;     /* borrowed compiled rabinSpike.json   */
    bn_t                    *oracle_pubkey;/* owned oracle Rabin modulus n         */
} rabin_spike_t;

/* Release the owned oracle_pubkey and zero the struct (NULL-safe; artifact is
 * borrowed and NOT freed). */
void rabin_spike_free(rabin_spike_t *c);

/* Reconstruct the locking script bytes into `out` (init'd): substitutes
 * oracle_pubkey into artifact->hex_template via the opcode-optimized ctor int
 * encoder (stateless contract — no state suffix). Delegates to script_codec.h.
 * TS: scryptlib lockingScript. BNS_OK / BNS_EINVAL / BNS_EPARSE / BNS_ENOMEM. */
int rabin_spike_locking_script(const rabin_spike_t *c, byte_buf_t *out);

/* The unlock() assertion modeled off-chain: RabinVerifier.verifySig(msg, sig,
 * oraclePubKey). `msg`/`msg_len` are the RAW message bytes. Pure predicate;
 * fail-closed. TS: rabinSpike.ts::unlock -> RabinVerifier.verifySig. */
bool rabin_spike_unlock_verify(const rabin_spike_t *c,
                               const uint8_t *msg, size_t msg_len,
                               const rabin_verifier_sig_t *sig);

#endif /* BONSAI_CONTRACTS_RABIN_SPIKE_H */
