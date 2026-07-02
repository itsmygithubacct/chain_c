/*
 * rabin_verifier.c — thin scrypt-ts-lib RabinVerifier adapter over crypto/rabin.
 *
 * RabinVerifier.verifySig(msg, sig, pubKey): append sig.padding to msg,
 * rabin_hash the result, return (hash mod n) == (s*s mod n). The contract-side
 * wire shape carries the raw padding ByteString; this adapter derives
 * padding_byte_count = padding_len and delegates to rabin_verify.
 *
 * TS origin: scrypt-ts-lib RabinVerifier.verifySig / RabinVerifier.hash.
 */
#include "lib/rabin_verifier.h"
#include "crypto/rabin.h"
#include "crypto/bignum.h"
#include "common/error.h"

bool rabin_verifier_verify_sig(const uint8_t *msg, size_t msg_len,
                               const rabin_verifier_sig_t *sig,
                               const bn_t *n) {
    if (!sig || !sig->s || !n) return false;
    /* Enforce the padding bound BEFORE scanning padding_len bytes (rabin_verify applies the
     * same RABIN_MAX_PADDING_BYTES cap, but only after this O(padding_len) scan) — review-2 #16. */
    if (sig->padding_len > RABIN_MAX_PADDING_BYTES) return false;

    /* rabin_verify reconstructs the padding as `padding_len` ZERO bytes, so this is
     * byte-faithful to the on-chain RabinVerifier (which appends the actual sig.padding)
     * ONLY when the padding really is all-zero. Honest signers always pad with 0x00;
     * reject any non-zero (or NULL-but-claimed) padding rather than verify msg||zeros
     * against a chain that would hash msg||(actual bytes). */
    if (sig->padding_len > 0 && sig->padding == NULL) return false;
    for (size_t i = 0; i < sig->padding_len; i++) {
        if (sig->padding[i] != 0x00) return false;
    }

    /* Adapt {s, padding bytes} -> rabin_sig_t {s, padding_byte_count}.
     * rabin_verify treats sig->s as borrowed (it never frees it), so casting
     * away const here is safe — the verify path only reads it. */
    rabin_sig_t adapted = {
        .s = (bn_t *)sig->s,
        .padding_byte_count = sig->padding_len,
    };
    return rabin_verify(msg, msg_len, &adapted, n);
}

int rabin_verifier_hash(const uint8_t *msg, size_t msg_len, bn_t **out) {
    return rabin_hash(msg, msg_len, out);
}
