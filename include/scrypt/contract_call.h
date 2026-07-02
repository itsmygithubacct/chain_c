/*
 * contract_call.h — the scrypt PUBLIC-METHOD unlocking-script assembler plus the
 * BIP143/FORKID preimage-sign helpers that turn the contract tx-builders'
 * UNSIGNED transactions into fully-signed, broadcast-valid BSV transactions.
 *
 * This is the "sign + finalize" layer. The tx-builders (txbuilders/) lay out the
 * UNSIGNED input/output skeleton (input[0] = contract, NULL scriptSig; funding
 * inputs; state/payout/OP_RETURN/change outputs). This module:
 *
 *   (1) computes the BIP143/FORKID sighash for each input (sighash.h) and signs
 *       it with ecdsa_sign_low_s (RFC6979 + low-S DER, byte-exact to bsv);
 *   (2) assembles the P2PKH funding scriptSigs (<sig||flag> <33B pubkey>);
 *   (3) assembles the contract input's scriptSig as the concatenation of typed
 *       script pushes in ABI order, exactly as scryptlib substitutes a public
 *       method call (see encodingRules in tests/golden/broadcast.json):
 *         user args (Sig / PubKey / int / Sha256 / bytes / RabinSig) ->
 *         __scrypt_ts_txPreimage (SigHashPreimage, PUSHDATA2) ->
 *         __scrypt_ts_changeAmount (int2Asm) ->
 *         __scrypt_ts_changeAddress (20B push) ->
 *         [__scrypt_ts_prevouts (PUSHDATA1) — only for checkInputZero methods] ->
 *         method selector (the ABI index, int2Asm).
 *
 * The integer encoder used for every `int` push (amount, changeAmount, selector,
 * RabinSig.s) is the scryptlib CONSTRUCTOR int2Asm encoder == to_script_hex over
 * SCRYPT_TYPE_INT (OP_0/OP_1..OP_16/OP_1NEGATE small-int optimization, else
 * minimal CScriptNum sign-magnitude push). Byte pushes (Sig, PubKey, Sha256,
 * bytes, preimage, prevouts, changeAddress) use the same minimal-pushdata wrap
 * scryptlib uses for method-call args (empty -> OP_0).
 *
 * TS origin: scryptlib Contract method-call unlocking-script assembly
 * (the auto-injected __scrypt_ts_* params + selector), bsv Sighash + ECDSA.
 */
#ifndef BONSAI_SCRYPT_CONTRACT_CALL_H
#define BONSAI_SCRYPT_CONTRACT_CALL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/bignum.h"
#include "crypto/ecdsa.h"
#include "bsv/tx.h"

/* ---- single typed script pushes (appended to an init'd `out`) ------------- */

/* int2Asm push of `value` (CONSTRUCTOR int encoder): n==-1 -> OP_1NEGATE;
 * 0<=n<=16 -> OP_n; else minimal LE sign-magnitude CScriptNum pushed by length.
 * Same encoder used for amount/changeAmount/RabinSig.s/method-selector pushes. */
int contract_call_push_int_i64(int64_t value, byte_buf_t *out);
int contract_call_push_int_bn(const bn_t *value, byte_buf_t *out);

/* Raw data push of `len` bytes (the scryptlib method-call byte push):
 * '' -> OP_0 (0x00); 1..75 -> len||data; 76..255 -> 4c||len||data;
 * 256..65535 -> 4d||len_le16||data; else -> 4e||len_le32||data.
 * Used for PubKey / Sha256 / Ripemd160 changeAddress / SigHashPreimage /
 * prevouts / RabinSig.padding. */
int contract_call_push_bytes(const uint8_t *data, size_t len, byte_buf_t *out);

/* Sig push: the DER signature with the 1-byte `sighash_flag` appended, pushed by
 * length (e.g. 0x47/0x48 for a 71/72-byte sig+flag). */
int contract_call_push_sig(const uint8_t *der, size_t der_len,
                           uint8_t sighash_flag, byte_buf_t *out);

/* ---- signing helpers ----------------------------------------------------- */

/* Compute the BIP143/FORKID sighash for spending `tx`.inputs[input_index] under
 * `script_code` (the prevout's locking script or the contract code part) at value
 * `value`, sign it with `key` (RFC6979 + low-S), and append DER||sighash_flag to
 * `out` (init'd). TS: Sighash.sign(...). BNS_OK / BNS_EINVAL / BNS_ECRYPTO. */
int contract_call_sign_input(const bsv_tx_t *tx, size_t input_index,
                             const uint8_t *script_code, size_t script_code_len,
                             uint64_t value, uint8_t sighash_flag,
                             const ecdsa_key_t *key, byte_buf_t *out);

/* Build the full P2PKH funding scriptSig for `tx`.inputs[input_index]:
 *   <push sig||flag> <push 33B compressed pubkey>
 * appended to `out` (init'd). `script_code` is the prevout P2PKH locking script.
 * TS: bsv P2PKH input signing. BNS_OK / BNS_EINVAL / BNS_ECRYPTO. */
int contract_call_p2pkh_scriptsig(const bsv_tx_t *tx, size_t input_index,
                                  const uint8_t *script_code, size_t script_code_len,
                                  uint64_t value, uint8_t sighash_flag,
                                  const ecdsa_key_t *key, byte_buf_t *out);

/* Sign a PRECOMPUTED BIP143 preimage: digest = sha256d(preimage), then
 * ecdsa_sign_low_s, then append `sighash_flag`. Result (DER||flag) appended to
 * `out` (init'd). Used for the contract method sig args (the preimage is already
 * assembled / recovered). BNS_OK / BNS_EINVAL / BNS_ECRYPTO. */
int contract_call_sign_preimage(const uint8_t *preimage, size_t preimage_len,
                                const ecdsa_key_t *key, uint8_t sighash_flag,
                                byte_buf_t *out);

/* Concatenate every input outpoint of `tx` (txid LE 32B || vout LE 4B) into
 * `out` (init'd) — the raw __scrypt_ts_prevouts payload (NOT yet pushed).
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int contract_call_prevouts(const bsv_tx_t *tx, byte_buf_t *out);

#endif /* BONSAI_SCRYPT_CONTRACT_CALL_H */
