/*
 * contract_sign.c — per-method SIGN + FINALIZE entry points. See
 * include/txbuilders/contract_sign.h.
 *
 * Each fills the scriptSig of every input on the caller's UNSIGNED skeleton
 * (b->tx) in place, then serializes the raw tx hex. The contract input's scriptSig
 * is assembled from typed script pushes in scryptlib ABI order via the helpers in
 * scrypt/contract_call.h; funding inputs are P2PKH SIGHASH_ALL|FORKID.
 */
#include "txbuilders/contract_sign.h"
#include "scrypt/contract_call.h"
#include "bsv/sighash.h"
#include "common/error.h"

#include <string.h>
#include <stdlib.h>

#define FLAG BONSAI_SIGHASH_ALL_FORKID  /* 0x41 */

/* Replace input[index]'s scriptSig with the bytes in `script` (consumes a copy). */
static int set_script_sig(tx_builder_t *b, size_t index, const byte_buf_t *script)
{
    if (b == NULL || index >= b->tx.num_inputs) return BNS_EINVAL;
    bsv_txin_t *in = &b->tx.inputs[index];
    byte_buf_free(&in->script_sig);
    byte_buf_init(&in->script_sig);
    if (script->len == 0) return BNS_OK;
    return byte_buf_append(&in->script_sig, script->data, script->len);
}

int contract_sign_funding_inputs(tx_builder_t *b,
                                 const contract_funding_input_t *funding,
                                 size_t n_funding)
{
    int rc = BNS_OK;
    if (b == NULL || (n_funding > 0 && funding == NULL)) return BNS_EINVAL;
    for (size_t i = 0; i < n_funding; i++) {
        const contract_funding_input_t *f = &funding[i];
        byte_buf_t ss;
        byte_buf_init(&ss);
        rc = contract_call_p2pkh_scriptsig(&b->tx, f->input_index,
                                           f->script_code, f->script_code_len,
                                           f->value, FLAG, f->key, &ss);
        if (rc == BNS_OK) rc = set_script_sig(b, f->input_index, &ss);
        byte_buf_free(&ss);
        if (rc != BNS_OK) return rc;
    }
    return BNS_OK;
}

int build_contract_deploy(tx_builder_t *b,
                          const contract_funding_input_t *funding,
                          size_t n_funding,
                          char **out_hex)
{
    int rc;
    if (b == NULL || out_hex == NULL) return BNS_EINVAL;
    rc = contract_sign_funding_inputs(b, funding, n_funding);
    if (rc != BNS_OK) return rc;
    return tx_builder_build_hex(b, out_hex);
}

int contract_revoke_sign(tx_builder_t *b,
                         size_t contract_input_index,
                         const uint8_t *contract_script_code,
                         size_t contract_script_code_len,
                         uint64_t identity_value,
                         const ecdsa_key_t *owner_key,
                         int64_t change_amount,
                         const uint8_t change_hash160[20],
                         int64_t method_selector,
                         const contract_funding_input_t *funding,
                         size_t n_funding,
                         char **out_hex)
{
    int rc;
    byte_buf_t preimage, owner_sig, scriptsig;

    if (b == NULL || contract_script_code == NULL || owner_key == NULL ||
        change_hash160 == NULL || out_hex == NULL)
        return BNS_EINVAL;

    byte_buf_init(&preimage);
    byte_buf_init(&owner_sig);
    byte_buf_init(&scriptsig);

    /* BIP143/FORKID preimage of the contract input (scriptCode = locking script,
     * value = identity sats). */
    rc = bip143_preimage(&b->tx, contract_input_index,
                         contract_script_code, contract_script_code_len,
                         identity_value, FLAG, &preimage);
    if (rc != BNS_OK) goto done;

    /* ownerSig = sign(sha256d(preimage)) || 0x41 */
    rc = contract_call_sign_preimage(preimage.data, preimage.len, owner_key,
                                     FLAG, &owner_sig);
    if (rc != BNS_OK) goto done;

    /* scriptSig assembly (ABI order, no prevouts):
     *   <ownerSig> <SigHashPreimage> <changeAmount> <changeAddress> <selector> */
    rc = contract_call_push_bytes(owner_sig.data, owner_sig.len, &scriptsig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_push_bytes(preimage.data, preimage.len, &scriptsig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_push_int_i64(change_amount, &scriptsig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_push_bytes(change_hash160, 20, &scriptsig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_push_int_i64(method_selector, &scriptsig);
    if (rc != BNS_OK) goto done;

    rc = set_script_sig(b, contract_input_index, &scriptsig);
    if (rc != BNS_OK) goto done;

    /* funding inputs */
    rc = contract_sign_funding_inputs(b, funding, n_funding);
    if (rc != BNS_OK) goto done;

    rc = tx_builder_build_hex(b, out_hex);

done:
    byte_buf_free(&preimage);
    byte_buf_free(&owner_sig);
    byte_buf_free(&scriptsig);
    return rc;
}

int contract_execute_sign(tx_builder_t *b,
                          size_t contract_input_index,
                          const uint8_t *contract_script_code,
                          size_t contract_script_code_len,
                          uint64_t identity_value,
                          const contract_execute_args_t *args,
                          int64_t change_amount,
                          const uint8_t change_hash160[20],
                          int64_t method_selector,
                          const contract_funding_input_t *funding,
                          size_t n_funding,
                          char **out_hex)
{
    int rc;
    byte_buf_t preimage, agent_sig, cp_sig, prevouts, scriptsig;

    if (b == NULL || contract_script_code == NULL || args == NULL ||
        change_hash160 == NULL || out_hex == NULL)
        return BNS_EINVAL;
    if (args->agent_key == NULL || args->counterparty_key == NULL ||
        args->counterparty_pub33 == NULL || args->amount == NULL ||
        args->hash32 == NULL || args->provenance_hash32 == NULL ||
        args->attested_limit == NULL || args->rabin_s == NULL)
        return BNS_EINVAL;

    byte_buf_init(&preimage);
    byte_buf_init(&agent_sig);
    byte_buf_init(&cp_sig);
    byte_buf_init(&prevouts);
    byte_buf_init(&scriptsig);

    /* contract input BIP143/FORKID preimage */
    rc = bip143_preimage(&b->tx, contract_input_index,
                         contract_script_code, contract_script_code_len,
                         identity_value, FLAG, &preimage);
    if (rc != BNS_OK) goto done;

    /* both sigs are over the SAME preimage */
    rc = contract_call_sign_preimage(preimage.data, preimage.len,
                                     args->agent_key, FLAG, &agent_sig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_sign_preimage(preimage.data, preimage.len,
                                     args->counterparty_key, FLAG, &cp_sig);
    if (rc != BNS_OK) goto done;

    /* prevouts = every outpoint (txidLE || voutLE) */
    rc = contract_call_prevouts(&b->tx, &prevouts);
    if (rc != BNS_OK) goto done;

    /* scriptSig assembly, ABI order:
     *  agentSig, counterpartySig, counterparty(PubKey), amount(int),
     *  hash32(Sha256), provenanceHash(Sha256), attestedLimit(int),
     *  RabinSig.s(int), RabinSig.padding(bytes), SigHashPreimage,
     *  changeAmount(int), changeAddress(20B), prevouts(PUSHDATA1), selector(int) */
    rc = contract_call_push_bytes(agent_sig.data, agent_sig.len, &scriptsig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_push_bytes(cp_sig.data, cp_sig.len, &scriptsig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_push_bytes(args->counterparty_pub33, 33, &scriptsig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_push_int_bn(args->amount, &scriptsig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_push_bytes(args->hash32, 32, &scriptsig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_push_bytes(args->provenance_hash32, 32, &scriptsig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_push_int_bn(args->attested_limit, &scriptsig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_push_int_bn(args->rabin_s, &scriptsig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_push_bytes(args->rabin_padding, args->rabin_padding_len, &scriptsig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_push_bytes(preimage.data, preimage.len, &scriptsig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_push_int_i64(change_amount, &scriptsig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_push_bytes(change_hash160, 20, &scriptsig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_push_bytes(prevouts.data, prevouts.len, &scriptsig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_push_int_i64(method_selector, &scriptsig);
    if (rc != BNS_OK) goto done;

    rc = set_script_sig(b, contract_input_index, &scriptsig);
    if (rc != BNS_OK) goto done;

    rc = contract_sign_funding_inputs(b, funding, n_funding);
    if (rc != BNS_OK) goto done;

    rc = tx_builder_build_hex(b, out_hex);

done:
    byte_buf_free(&preimage);
    byte_buf_free(&agent_sig);
    byte_buf_free(&cp_sig);
    byte_buf_free(&prevouts);
    byte_buf_free(&scriptsig);
    return rc;
}

int contract_recover_sign(tx_builder_t *b,
                          size_t contract_input_index,
                          const uint8_t *contract_script_code,
                          size_t contract_script_code_len,
                          uint64_t identity_value,
                          const uint8_t new_agent33[33],
                          const contract_recover_sig_t recover_sigs[3],
                          int64_t change_amount,
                          const uint8_t change_hash160[20],
                          int64_t method_selector,
                          const contract_funding_input_t *funding,
                          size_t n_funding,
                          char **out_hex)
{
    int rc;
    byte_buf_t preimage, prevouts, scriptsig;

    if (b == NULL || contract_script_code == NULL || new_agent33 == NULL ||
        recover_sigs == NULL || change_hash160 == NULL || out_hex == NULL)
        return BNS_EINVAL;

    byte_buf_init(&preimage);
    byte_buf_init(&prevouts);
    byte_buf_init(&scriptsig);

    /* contract input BIP143/FORKID preimage (read by the contract as ctx; recover
     * carries NO contract ECDSA sig, so the preimage is pushed as data, not signed). */
    rc = bip143_preimage(&b->tx, contract_input_index,
                         contract_script_code, contract_script_code_len,
                         identity_value, FLAG, &preimage);
    if (rc != BNS_OK) goto done;

    /* prevouts = every outpoint (txidLE || voutLE) — recover is a checkInputZero method. */
    rc = contract_call_prevouts(&b->tx, &prevouts);
    if (rc != BNS_OK) goto done;

    /* scriptSig assembly, ABI order (AgentTea.recover, index 3):
     *  newAgent(PubKey 33B), recoverUsed[0..2](bool), recoverySigs[0..2]
     *  (RabinSig: s int2Asm then padding bytes), SigHashPreimage,
     *  changeAmount(int), changeAddress(20B), prevouts(PUSHDATA1), selector(int).
     * A bool pushes OP_1(0x51)/OP_0(0x00) == int2Asm(1/0); an unused slot pushes a
     * dummy RabinSig{s:0,padding:''} (OP_0,OP_0). */
    rc = contract_call_push_bytes(new_agent33, 33, &scriptsig);
    if (rc != BNS_OK) goto done;
    for (int i = 0; i < 3; i++) {
        rc = contract_call_push_int_i64(recover_sigs[i].used ? 1 : 0, &scriptsig);
        if (rc != BNS_OK) goto done;
    }
    for (int i = 0; i < 3; i++) {
        if (recover_sigs[i].s != NULL)
            rc = contract_call_push_int_bn(recover_sigs[i].s, &scriptsig);
        else
            rc = contract_call_push_int_i64(0, &scriptsig);   /* dummy RabinSig.s = OP_0 */
        if (rc != BNS_OK) goto done;

        size_t pad = recover_sigs[i].padding_len;
        if (pad > 0) {
            uint8_t zeros[256];
            if (pad > sizeof zeros) { rc = BNS_EINVAL; goto done; }
            memset(zeros, 0, pad);
            rc = contract_call_push_bytes(zeros, pad, &scriptsig);   /* padding zero bytes */
        } else {
            rc = contract_call_push_bytes(NULL, 0, &scriptsig);      /* empty -> OP_0 */
        }
        if (rc != BNS_OK) goto done;
    }
    rc = contract_call_push_bytes(preimage.data, preimage.len, &scriptsig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_push_int_i64(change_amount, &scriptsig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_push_bytes(change_hash160, 20, &scriptsig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_push_bytes(prevouts.data, prevouts.len, &scriptsig);
    if (rc != BNS_OK) goto done;
    rc = contract_call_push_int_i64(method_selector, &scriptsig);
    if (rc != BNS_OK) goto done;

    rc = set_script_sig(b, contract_input_index, &scriptsig);
    if (rc != BNS_OK) goto done;

    rc = contract_sign_funding_inputs(b, funding, n_funding);
    if (rc != BNS_OK) goto done;

    rc = tx_builder_build_hex(b, out_hex);

done:
    byte_buf_free(&preimage);
    byte_buf_free(&prevouts);
    byte_buf_free(&scriptsig);
    return rc;
}
