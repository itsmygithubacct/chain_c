/*
 * txbuilders/contract_sign.h — per-method SIGN + FINALIZE entry points that turn
 * an UNSIGNED contract transaction (from the txbuilders) into a fully-signed,
 * broadcast-valid BSV tx whose raw hex is byte-exact to the captured goldens.
 *
 * These wrap the generic assembler/sign helpers in scrypt/contract_call.h with
 * the per-method ABI push order (see tests/golden/broadcast.json .abiOrder /
 * .encodingRules). The caller provides the UNSIGNED skeleton in a tx_builder_t
 * (input[0] = contract with placeholder scriptSig, funding inputs, all outputs
 * laid out) plus the prevout scriptCodes/values and the method-arg VALUES; each
 * function fills every input's scriptSig in place and serializes the raw hex.
 *
 * Funding inputs are signed SIGHASH_ALL|FORKID (0x41) P2PKH; the contract input's
 * method sig args are signed over the BIP143/FORKID preimage of the contract
 * input (scriptCode = the contract's full locking script, value = identity sats).
 *
 * TS origin: scrypt-ts SmartContract.methods.<m>(...).to({tx}) + bsv signing.
 */
#ifndef BONSAI_TXBUILDERS_CONTRACT_SIGN_H
#define BONSAI_TXBUILDERS_CONTRACT_SIGN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/bignum.h"
#include "crypto/ecdsa.h"
#include "bsv/tx_builder.h"

/* A funding (P2PKH) input to sign: its prevout locking script + value + key.
 * `input_index` is the index of this input within the tx. */
typedef struct {
    size_t             input_index;
    const uint8_t     *script_code;     /* prevout P2PKH locking script bytes  */
    size_t             script_code_len;
    uint64_t           value;           /* prevout satoshis                    */
    const ecdsa_key_t *key;             /* signing key (funder)                */
} contract_funding_input_t;

/* Sign all `n_funding` P2PKH funding inputs of `b`->tx in place (each gets
 * <sig||0x41> <pubkey> as its scriptSig). Used by every finalize path and by the
 * deploy builder. BNS_OK / BNS_EINVAL / BNS_ECRYPTO. */
int contract_sign_funding_inputs(tx_builder_t *b,
                                 const contract_funding_input_t *funding,
                                 size_t n_funding);

/* ---- DEPLOY: P2PKH funding -> contract locking output + change ----------- */

/* Finalize a DEPLOY tx: `b` already holds the funding input(s) (placeholder
 * scriptSig) and the outputs (output[0] = contract locking script at identity
 * value, then change). Signs the funding inputs and serializes to *out_hex
 * (caller frees). This is the simplest case: no contract unlocking script.
 * TS: hand-built deploy tx. BNS_OK / BNS_EINVAL / BNS_ECRYPTO / BNS_ENOMEM. */
int build_contract_deploy(tx_builder_t *b,
                          const contract_funding_input_t *funding,
                          size_t n_funding,
                          char **out_hex);

/* ---- REVOKE: ownerSig, preimage, changeAmount, changeAddress, selector --- */

/* Finalize a contract REVOKE spend (RicardianTea.revoke index 3 / AgentTea.revoke
 * index 4 — both share this exact push shape; no __scrypt_ts_prevouts).
 *   contract input[0].scriptSig =
 *     <ownerSig||0x41> <SigHashPreimage> <changeAmount int2Asm>
 *     <changeAddress 20B> <method-selector int2Asm>
 * Inputs:
 *   contract_input_index   index of the contract input in `b`->tx (typically 0)
 *   contract_script_code   the contract's full locking script (scriptCode)
 *   identity_value         the identity UTXO satoshis
 *   owner_key              the owner (Elder) signing key
 *   change_amount          satoshis of the change output (for the changeAmount push)
 *   change_hash160         20-byte change Ripemd160
 *   method_selector        ABI index (3 RicardianTea, 4 AgentTea)
 *   funding/n_funding      the P2PKH funding inputs to sign
 * Fills every scriptSig and writes the raw hex to *out_hex (caller frees).
 * BNS_OK / BNS_EINVAL / BNS_ECRYPTO / BNS_ENOMEM. */
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
                         char **out_hex);

/* ---- EXECUTE: the full action/tea spend (with __scrypt_ts_prevouts) ------ */

/* Method-call user args for the executeAction (AgentTea#0) / executeTea
 * (RicardianTea#0) shapes, which share the same push order:
 *   <agentSig><counterpartySig><counterparty PubKey><amount int>
 *   <hash32 (actionHash|invoiceHash)><provenanceHash 32>
 *   <attestedLimit int><RabinSig.s int><RabinSig.padding bytes>
 *   <SigHashPreimage><changeAmount int><changeAddress 20B>
 *   <prevouts PUSHDATA1><selector OP_0>
 * agentSig/counterpartySig are signed over the SAME contract BIP143 preimage. */
typedef struct {
    const ecdsa_key_t *agent_key;          /* signs agentSig                     */
    const ecdsa_key_t *counterparty_key;   /* signs counterpartySig              */
    const uint8_t     *counterparty_pub33; /* 33-byte counterparty PubKey push   */
    const bn_t        *amount;             /* amount int2Asm                     */
    const uint8_t     *hash32;             /* actionHash (Agent) / invoiceHash   */
    const uint8_t     *provenance_hash32;  /* provenanceHash                     */
    const bn_t        *attested_limit;     /* attestedLimit int2Asm              */
    const bn_t        *rabin_s;            /* RabinSig.s int2Asm                 */
    const uint8_t     *rabin_padding;      /* RabinSig.padding bytes (may be NULL */
    size_t             rabin_padding_len;  /*   when len==0 -> OP_0)             */
} contract_execute_args_t;

/* Finalize an executeAction/executeTea spend: signs both contract sigs over the
 * contract input's BIP143 preimage, assembles the contract scriptSig in ABI order
 * (with __scrypt_ts_prevouts), signs the funding inputs, serializes raw hex.
 *   contract_input_index / contract_script_code / identity_value  as above
 *   args                  the typed user-method args
 *   change_amount / change_hash160 / method_selector              auto-injected
 *   funding / n_funding   the P2PKH funding inputs
 * BNS_OK / BNS_EINVAL / BNS_ECRYPTO / BNS_ENOMEM. */
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
                          char **out_hex);

/* ---- RECOVER: newAgent, recoverUsed[3], recoverySigs[3], preimage, ------- *
 * ---- changeAmount, changeAddress, prevouts, selector --------------------- */

/* One guardian slot of the M-of-3 social-recovery quorum. `used` is recoverUsed[i]
 * (bool, encoded OP_1/OP_0). `s`/`padding_len` are the RabinSig fields: when `used`
 * the guardian's signature over AgentTea.recoveryMsg; when unused pass {false,NULL,0}
 * so a dummy RabinSig{s:0,padding:''} (OP_0,OP_0) is pushed to keep the array shape. */
typedef struct {
    bool        used;        /* recoverUsed[i]                                 */
    const bn_t *s;           /* RabinSig.s (NULL -> OP_0)                       */
    size_t      padding_len; /* RabinSig.padding = this many 0x00 bytes (0->OP_0) */
} contract_recover_sig_t;

/* Finalize an AgentTea.recover (index 3) spend. The contract input carries NO
 * ECDSA signature — authorization is the M-of-3 Rabin guardian sigs. Assembles the
 * contract input[0] scriptSig in ABI order:
 *   <newAgent 33B> <recoverUsed[0..2] bool> <recoverySigs[0..2]: s int2Asm, padding
 *   bytes> <SigHashPreimage> <changeAmount int2Asm> <changeAddress 20B>
 *   <prevouts PUSHDATA1> <selector int2Asm>
 * then signs the P2PKH funding inputs and serializes the raw hex (caller frees).
 * `recover_sigs` is a 3-element array. BNS_OK / BNS_EINVAL / BNS_ECRYPTO / BNS_ENOMEM. */
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
                          char **out_hex);

#endif /* BONSAI_TXBUILDERS_CONTRACT_SIGN_H */
