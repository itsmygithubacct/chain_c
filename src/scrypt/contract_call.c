/*
 * contract_call.c — the scrypt public-method unlocking-script assembler + the
 * BIP143/FORKID preimage-sign helpers. See scrypt/contract_call.h.
 *
 * The integer pushes route through to_script_hex(SCRYPT_TYPE_INT) so they use the
 * IDENTICAL CONSTRUCTOR int2Asm encoder (OP_0/OP_n/OP_1NEGATE small-int opt, else
 * minimal CScriptNum) that scryptlib substitutes for ctor ints and method-call
 * ints; the byte pushes mirror bsv `Script.fromASM(hexbody).toHex()` for a single
 * data chunk (empty -> OP_0).
 */
#include "scrypt/contract_call.h"
#include "scrypt/script_codec.h"
#include "scrypt/scrypt_contract.h"
#include "bsv/sighash.h"
#include "crypto/hash.h"
#include "common/hex.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ---- byte push (bsv Script.fromASM(hex).toHex() for one chunk) ----------- */

int contract_call_push_bytes(const uint8_t *data, size_t len, byte_buf_t *out)
{
    int rc;
    if (out == NULL) return BNS_EINVAL;
    if (len == 0) {
        return byte_buf_append_byte(out, 0x00);           /* OP_0 */
    }
    if (data == NULL) return BNS_EINVAL;
    if (len <= 75) {
        if ((rc = byte_buf_append_byte(out, (uint8_t)len)) != BNS_OK) return rc;
    } else if (len <= 0xff) {
        if ((rc = byte_buf_append_byte(out, 0x4c)) != BNS_OK) return rc;      /* PUSHDATA1 */
        if ((rc = byte_buf_append_byte(out, (uint8_t)len)) != BNS_OK) return rc;
    } else if (len <= 0xffff) {
        uint8_t l2[2] = { (uint8_t)(len & 0xff), (uint8_t)((len >> 8) & 0xff) };
        if ((rc = byte_buf_append_byte(out, 0x4d)) != BNS_OK) return rc;      /* PUSHDATA2 */
        if ((rc = byte_buf_append(out, l2, 2)) != BNS_OK) return rc;
    } else {
        uint8_t l4[4] = { (uint8_t)(len & 0xff), (uint8_t)((len >> 8) & 0xff),
                          (uint8_t)((len >> 16) & 0xff), (uint8_t)((len >> 24) & 0xff) };
        if ((rc = byte_buf_append_byte(out, 0x4e)) != BNS_OK) return rc;      /* PUSHDATA4 */
        if ((rc = byte_buf_append(out, l4, 4)) != BNS_OK) return rc;
    }
    return byte_buf_append(out, data, len);
}

/* ---- int2Asm pushes (route through the CONSTRUCTOR encoder) --------------- */

int contract_call_push_int_bn(const bn_t *value, byte_buf_t *out)
{
    scrypt_arg_t arg;
    if (value == NULL || out == NULL) return BNS_EINVAL;
    memset(&arg, 0, sizeof arg);
    arg.tag = SCRYPT_TYPE_INT;
    arg.as.int_val = (bn_t *)value; /* to_script_hex reads, never mutates/frees */
    return to_script_hex(&arg, SCRYPT_TYPE_INT, out);
}

int contract_call_push_int_i64(int64_t value, byte_buf_t *out)
{
    int rc;
    bn_t *bn = NULL;
    char dec[32];
    if (out == NULL) return BNS_EINVAL;
    snprintf(dec, sizeof dec, "%lld", (long long)value);
    if ((rc = bn_parse_dec(dec, &bn)) != BNS_OK) return rc;
    rc = contract_call_push_int_bn(bn, out);
    bn_free(bn);
    return rc;
}

/* ---- Sig push ------------------------------------------------------------ */

int contract_call_push_sig(const uint8_t *der, size_t der_len,
                           uint8_t sighash_flag, byte_buf_t *out)
{
    int rc;
    byte_buf_t sig;
    if (der == NULL || out == NULL) return BNS_EINVAL;
    byte_buf_init(&sig);
    if ((rc = byte_buf_append(&sig, der, der_len)) != BNS_OK) { byte_buf_free(&sig); return rc; }
    if ((rc = byte_buf_append_byte(&sig, sighash_flag)) != BNS_OK) { byte_buf_free(&sig); return rc; }
    rc = contract_call_push_bytes(sig.data, sig.len, out);
    byte_buf_free(&sig);
    return rc;
}

/* ---- prevouts (every outpoint, txidLE || voutLE) ------------------------- */

int contract_call_prevouts(const bsv_tx_t *tx, byte_buf_t *out)
{
    int rc;
    if (tx == NULL || out == NULL) return BNS_EINVAL;
    for (size_t i = 0; i < tx->num_inputs; i++) {
        const bsv_txin_t *in = &tx->inputs[i];
        uint8_t txid_be[32];
        uint8_t txid_le[32];
        uint8_t vout_le[4];
        if (hex_decode_fixed(in->prev_txid_display, txid_be, 32) != BNS_OK)
            return BNS_EINVAL;
        for (size_t j = 0; j < 32; j++) txid_le[j] = txid_be[31 - j]; /* display(BE) -> wire(LE) */
        vout_le[0] = (uint8_t)(in->vout & 0xff);
        vout_le[1] = (uint8_t)((in->vout >> 8) & 0xff);
        vout_le[2] = (uint8_t)((in->vout >> 16) & 0xff);
        vout_le[3] = (uint8_t)((in->vout >> 24) & 0xff);
        if ((rc = byte_buf_append(out, txid_le, 32)) != BNS_OK) return rc;
        if ((rc = byte_buf_append(out, vout_le, 4)) != BNS_OK) return rc;
    }
    return BNS_OK;
}

/* ---- signing helpers ----------------------------------------------------- */

int contract_call_sign_preimage(const uint8_t *preimage, size_t preimage_len,
                                const ecdsa_key_t *key, uint8_t sighash_flag,
                                byte_buf_t *out)
{
    int rc;
    uint8_t digest[BONSAI_SHA256_LEN];
    if (preimage == NULL || key == NULL || out == NULL) return BNS_EINVAL;
    sha256d(preimage, preimage_len, digest);
    if ((rc = ecdsa_sign_low_s(digest, key, out)) != BNS_OK) return rc;
    return byte_buf_append_byte(out, sighash_flag);
}

int contract_call_sign_input(const bsv_tx_t *tx, size_t input_index,
                             const uint8_t *script_code, size_t script_code_len,
                             uint64_t value, uint8_t sighash_flag,
                             const ecdsa_key_t *key, byte_buf_t *out)
{
    int rc;
    uint8_t digest[BONSAI_SHA256_LEN];
    if (tx == NULL || script_code == NULL || key == NULL || out == NULL)
        return BNS_EINVAL;
    rc = bip143_sighash(tx, input_index, script_code, script_code_len,
                        value, sighash_flag, digest);
    if (rc != BNS_OK) return rc;
    if ((rc = ecdsa_sign_low_s(digest, key, out)) != BNS_OK) return rc;
    return byte_buf_append_byte(out, sighash_flag);
}

int contract_call_p2pkh_scriptsig(const bsv_tx_t *tx, size_t input_index,
                                  const uint8_t *script_code, size_t script_code_len,
                                  uint64_t value, uint8_t sighash_flag,
                                  const ecdsa_key_t *key, byte_buf_t *out)
{
    int rc;
    byte_buf_t sig_flag;
    ecdsa_pubkey_t *pub = NULL;
    uint8_t pubkey[BONSAI_ECDSA_PUBKEY_COMPRESSED_LEN];

    if (tx == NULL || script_code == NULL || key == NULL || out == NULL)
        return BNS_EINVAL;

    byte_buf_init(&sig_flag);
    rc = contract_call_sign_input(tx, input_index, script_code, script_code_len,
                                  value, sighash_flag, key, &sig_flag);
    if (rc != BNS_OK) goto done;

    /* <push sig||flag> */
    if ((rc = contract_call_push_bytes(sig_flag.data, sig_flag.len, out)) != BNS_OK)
        goto done;

    /* <push 33B compressed pubkey> */
    if ((rc = ecdsa_key_derive_pubkey(key, &pub)) != BNS_OK) goto done;
    if ((rc = ecdsa_pubkey_serialize_compressed(pub, pubkey)) != BNS_OK) goto done;
    rc = contract_call_push_bytes(pubkey, sizeof pubkey, out);

done:
    ecdsa_pubkey_free(pub);
    byte_buf_free(&sig_flag);
    return rc;
}
