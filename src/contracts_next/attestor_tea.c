/*
 * contracts_next/attestor_tea.c — AttestorTea (ARP-1 bonded-attestor v1) port.
 *
 * TS origin: src/contracts-next/attestorTea.ts (AttestorTea: operator,
 * attestorRabinPubKey, unbondNotBefore; slashEquivocation, stake, withdraw).
 *
 * This module owns:
 *   1. params lifecycle,
 *   2. stateless locking-script reconstruction (3 ctor @props, no state suffix),
 *   3. the off-chain model of slashEquivocation()'s acceptance test.
 *
 * The compiled artifact (artifacts/.../attestorTea.json) ctor param order/types
 * are: operator :: PubKey, attestorRabinPubKey :: int, unbondNotBefore :: int.
 * Both int ctor args are encoded with the OPCODE-OPTIMIZED ctor int encoder
 * (script_codec to_script_hex), matching scryptlib substitution.
 *
 * DETERMINISM PINS (header notes):
 *  (6) Both equivocation messages are ArpAttest.attestationMsg(seq, digest) —
 *      the canonical 54-byte linchpin (arp_attest.c).
 *  (2)/(3) Rabin verify (SECURITY_LEVEL=6, LE fromLEUnsigned, padding appended
 *      before hashing) is delegated to lib/rabin_verifier.h verbatim.
 */
#include "contracts_next/attestor_tea.h"
#include "scrypt/script_codec.h"

#include <stdlib.h>
#include <string.h>

/* ---- lifecycle ---------------------------------------------------------- */

void attestor_tea_params_free(attestor_tea_params_t *p)
{
    if (p == NULL)
        return;
    byte_buf_free(&p->operator_pubkey);
    bn_free(p->attestor_rabin_pubkey);
    bn_free(p->unbond_not_before);
    p->attestor_rabin_pubkey = NULL;
    p->unbond_not_before = NULL;
}

void attestor_tea_free(attestor_tea_t *c)
{
    if (c == NULL)
        return;
    attestor_tea_params_free(&c->params);
    c->artifact = NULL;
}

/* ---- locking-script reconstruction -------------------------------------- */

int attestor_tea_locking_script(const attestor_tea_t *c, byte_buf_t *out)
{
    if (c == NULL || c->artifact == NULL || out == NULL)
        return BNS_EINVAL;
    if (c->params.attestor_rabin_pubkey == NULL ||
        c->params.unbond_not_before == NULL)
        return BNS_EINVAL;

    /* Build the 3 ctor values in @prop declaration order:
     *   0. operator           :: PubKey (33B)
     *   1. attestorRabinPubKey :: int   (bn_t)
     *   2. unbondNotBefore     :: int   (bn_t)
     * bn values are duplicated so the values array owns them independently of
     * the params (scrypt_instance/arg ownership semantics). */
    scrypt_arg_t values[3];
    memset(values, 0, sizeof(values));
    int rc = BNS_OK;

    /* 0. operator PubKey: BYTES-style raw payload via bytes_val. */
    values[0].tag = SCRYPT_TYPE_PUBKEY;
    byte_buf_init(&values[0].as.bytes_val);
    rc = byte_buf_append(&values[0].as.bytes_val,
                         c->params.operator_pubkey.data,
                         c->params.operator_pubkey.len);
    if (rc != BNS_OK)
        goto done;

    /* 1. attestorRabinPubKey: int (artifact type is `int`). */
    values[1].tag = SCRYPT_TYPE_INT;
    rc = bn_dup(c->params.attestor_rabin_pubkey, &values[1].as.int_val);
    if (rc != BNS_OK)
        goto done;

    /* 2. unbondNotBefore: int. */
    values[2].tag = SCRYPT_TYPE_INT;
    rc = bn_dup(c->params.unbond_not_before, &values[2].as.int_val);
    if (rc != BNS_OK)
        goto done;

    /* Stateless: no state suffix (state_values NULL, is_genesis ignored). */
    rc = reconstruct_locking_script(c->artifact, values, 3, NULL, 0, false, out);

done:
    scrypt_arg_free(&values[0]);
    scrypt_arg_free(&values[1]);
    scrypt_arg_free(&values[2]);
    return rc;
}

/* ---- slashEquivocation acceptance test ---------------------------------- */

int attestor_tea_check_equivocation(const attestor_tea_t *c,
                                    const bn_t *seq,
                                    const uint8_t digest_a[32],
                                    const rabin_verifier_sig_t *sig_a,
                                    const uint8_t digest_b[32],
                                    const rabin_verifier_sig_t *sig_b,
                                    bool *out_ok)
{
    if (c == NULL || seq == NULL || digest_a == NULL || digest_b == NULL ||
        sig_a == NULL || sig_b == NULL || out_ok == NULL)
        return BNS_EINVAL;
    if (c->params.attestor_rabin_pubkey == NULL)
        return BNS_EINVAL;

    *out_ok = false;

    /* TS: assert(digestA != digestB). Fail-closed on identical digests. */
    if (memcmp(digest_a, digest_b, 32) == 0)
        return BNS_OK; /* not an equivocation; *out_ok stays false */

    /* Build msgA = ArpAttest.attestationMsg(seq, digestA), verify sigA. */
    byte_buf_t msg_a;
    byte_buf_init(&msg_a);
    int rc = arp_attestation_msg(seq, digest_a, &msg_a);
    if (rc != BNS_OK) {
        byte_buf_free(&msg_a);
        return rc;
    }
    bool ok_a = rabin_verifier_verify_sig(msg_a.data, msg_a.len, sig_a,
                                          c->params.attestor_rabin_pubkey);
    byte_buf_free(&msg_a);
    if (!ok_a)
        return BNS_OK; /* first signature not by this attestor */

    /* Build msgB = ArpAttest.attestationMsg(seq, digestB), verify sigB. */
    byte_buf_t msg_b;
    byte_buf_init(&msg_b);
    rc = arp_attestation_msg(seq, digest_b, &msg_b);
    if (rc != BNS_OK) {
        byte_buf_free(&msg_b);
        return rc;
    }
    bool ok_b = rabin_verifier_verify_sig(msg_b.data, msg_b.len, sig_b,
                                          c->params.attestor_rabin_pubkey);
    byte_buf_free(&msg_b);
    if (!ok_b)
        return BNS_OK; /* second signature not by this attestor */

    *out_ok = true;
    return BNS_OK;
}
