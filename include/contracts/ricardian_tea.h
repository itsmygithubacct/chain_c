/*
 * contracts/ricardian_tea.h — the RicardianTea legal-technical identity contract:
 * its 13-arg constructor params + 5-field mutable state, the locking-script
 * reconstruction handle, and the byte-exact receipt / attestation / slash preimage
 * builders the off-chain producer & verifier must reproduce.
 *
 * The contract's on-chain bytecode is produced ONLY by the sCrypt compiler; the
 * C port does NOT reimplement script — it reconstructs the lockingScript from the
 * compiled artifact (artifacts/ricardianTea.json) by substituting the 13 ctor
 * @props (in @prop declaration order) + the 5 mutable state props as trailing
 * stateful state (via scrypt/script_codec.h). What this module DOES own is the
 * byte-exact preimage layouts (receipt, attestationMsg) that hashOutputs pins.
 *
 * TS origin: src/contracts/ricardianTea.ts (RicardianTea: 14 immutable @props
 * incl. the constructor's 13 args + an implicit, the 5 @prop(true) state fields,
 * checkInputZero, attestationMsg, executeTea, slash, updateSlashCheckpoint, revoke).
 *
 * DETERMINISM PINS (ricardianTea.ts notes):
 *  (1) int2ByteString one-arg sign-magnitude (num2bin.h int2bytestring_minimal)
 *      vs two-arg fixed-width (int2bytestring_sized) are DIFFERENT encoders —
 *      the wrong one breaks every preimage. CTOR ints use the opcode-optimized
 *      script encoder; STATE ints use the no-opcode state encoder (script_codec.h).
 *  (2) ricardianHash/receiptHash/attReceiptHash are 32 RAW bytes; pubkeys 33
 *      bytes; field widths are load-bearing.
 *  (3) txCount in the receipt is the PRE-increment value.
 *  (4) `now` is ctx.locktime encoded as int2ByteString(now, 4) — a SIGNED 4-byte
 *      CScriptNum (2038 bound) — NOT block time; do not widen.
 *  (5) Rabin uses SECURITY_LEVEL=6 (6 expandHash blocks) + half-split SHA256
 *      (crypto/rabin.h / lib/rabin_verifier.h).
 *  (6) attestationMsg domain tag = the 13-byte hex 0x525445415f4154544553545f5631
 *      ('RTEA_ATTEST_V1'); validatorPubKey via int2ByteString one-arg minimal.
 *  (7) slash() is SUPERSEDED — DO NOT DEPLOY (cross-agent binding bug); built for
 *      test parity only.
 */
#ifndef BONSAI_CONTRACTS_RICARDIAN_TEA_H
#define BONSAI_CONTRACTS_RICARDIAN_TEA_H

#include <stddef.h>
#include <stdint.h>
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/bignum.h"
#include "scrypt/scrypt_contract.h"

/* RTEA attestation domain tag, as the exact preimage bytes (13 bytes):
 * 'RTEA_ATTEST_V1'. TS: ricardianTea.ts attestationMsg const tag. */
#define BONSAI_RTEA_ATTEST_TAG_HEX "525445415f4154544553545f5631"

/* The 13 RicardianTea constructor arguments, in @prop DECLARATION ORDER (which
 * IS the on-chain locking-script substitution order). PubKeys are 33-byte
 * compressed SEC bytes; Sha256 fields are 32 raw bytes; the bigint policy/slash
 * params and the two RabinPubKeys are bn_t. Owns its bn_t/byte_buf members;
 * ricardian_tea_params_free releases them. TS: ricardianTea.ts constructor. */
typedef struct {
    byte_buf_t owner;                     /* 1. owner PubKey (33B)               */
    byte_buf_t agent;                     /* 2. agent PubKey (33B)               */
    byte_buf_t ricardian_hash;            /* 3. ricardianHash Sha256 (32B)       */
    bn_t      *per_tx_limit;              /* 4. perTxLimit                       */
    bn_t      *daily_limit;               /* 5. dailyLimit                       */
    bn_t      *window_duration;           /* 6. windowDuration                   */
    bn_t      *graduation_threshold;      /* 7. graduationThreshold              */
    bn_t      *validator_threshold;       /* 8. validatorThreshold               */
    bn_t      *designated_validator_pubkey;/* 9. designatedValidatorPubKey (Rabin n)*/
    bn_t      *validator_rabin_pubkey;    /* 10. validatorRabinPubKey (Rabin n)   */
    bn_t      *max_slashing_target;       /* 11. maxSlashingTarget               */
    bn_t      *min_slash_confirmations;   /* 12. minSlashConfirmations           */
    byte_buf_t initial_slash_checkpoint_hash;/* 13. initialSlashCheckpointHash (32B)*/
} ricardian_tea_params_t;

/* The 5 mutable @prop(true) state fields, in declaration order. Genesis values:
 * txCount=0, spentInWindow=0, windowStart=0, tier=1, slashCheckpointHash=
 * initialSlashCheckpointHash. Owns its bn_t/byte_buf members.
 * TS: ricardianTea.ts @prop(true) txCount/spentInWindow/windowStart/tier/
 * slashCheckpointHash. */
typedef struct {
    bn_t      *tx_count;             /* txCount                                  */
    bn_t      *spent_in_window;      /* spentInWindow                            */
    bn_t      *window_start;         /* windowStart (nLocktime units)            */
    bn_t      *tier;                 /* 1=agent, 2=validator                     */
    byte_buf_t slash_checkpoint_hash;/* slashCheckpointHash Sha256 (32B)         */
} ricardian_tea_state_t;

/* A live RicardianTea instance: the loaded artifact bound to ctor params + the
 * current mutable state. The locking script is reconstructed from this handle
 * via scrypt/script_codec.h reconstruct_locking_script. The artifact is borrowed
 * (not owned). TS: an instantiated RicardianTea SmartContract. */
typedef struct {
    const scrypt_artifact_t *artifact;  /* borrowed compiled ricardianTea.json   */
    ricardian_tea_params_t   params;    /* owned ctor args                       */
    ricardian_tea_state_t    state;     /* owned current state                   */
} ricardian_tea_t;

/* ---- lifecycle ---------------------------------------------------------- */

void ricardian_tea_params_free(ricardian_tea_params_t *p);
void ricardian_tea_state_free(ricardian_tea_state_t *s);
void ricardian_tea_free(ricardian_tea_t *c);

/* Initialise genesis state from the ctor params: txCount/spentInWindow/
 * windowStart=0, tier=1, slashCheckpointHash=initial_slash_checkpoint_hash.
 * Fills *out (caller frees via ricardian_tea_state_free).
 * TS: ricardianTea.ts constructor state init. BNS_OK / BNS_ENOMEM. */
int ricardian_tea_genesis_state(const ricardian_tea_params_t *params,
                                ricardian_tea_state_t *out);

/* Advance the @prop(true) state as RicardianTea.executeTea does: window roll, spentInWindow +=
 * amount, txCount += 1, tier graduation (slashCheckpointHash unchanged). The executeTea builder
 * must recreate output[0] from THIS post-spend state so the contract's hashOutputs assert passes.
 * Fills *next (caller frees via ricardian_tea_state_free). TS: ricardianTea.ts executeTea state
 * mutation. BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int ricardian_tea_apply_action(const ricardian_tea_t *c, const bn_t *amount, int64_t now,
                               ricardian_tea_state_t *next);

/* ---- locking-script reconstruction -------------------------------------- */

/* Reconstruct the full locking script bytes for `c` into `out` (init'd):
 * substitutes the 13 ctor args into artifact->hex_template (opcode-optimized
 * ctor encoders) and appends the 5-field state suffix (state encoders + state
 * meta). `is_genesis` selects the genesis flag byte. Delegates to
 * scrypt/script_codec.h. TS: scryptlib lockingScript + scrypt-ts state suffix.
 * BNS_OK / BNS_EINVAL / BNS_EPARSE / BNS_ENOMEM. */
int ricardian_tea_locking_script(const ricardian_tea_t *c, bool is_genesis,
                                 byte_buf_t *out);

/* ---- byte-exact preimage builders --------------------------------------- */

/* Build the RTEA Rabin attestation preimage appended to `out` (init'd):
 *   tag(13) || ricardianHash(32) || agent(33) || int2ByteString(validatorPubKey)
 *   || int2ByteString(amount,8) || int2ByteString(attestedLimit,8) || receiptHash(32)
 * validatorPubKey uses the ONE-ARG minimal sign-magnitude encoder; amount and
 * attestedLimit use the TWO-ARG fixed 8-byte LE encoder (num2bin.h).
 * `ricardian_hash`/`receipt_hash` are 32 raw bytes; `agent` is 33 raw bytes.
 * TS: ricardianTea.ts::attestationMsg. BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int ricardian_tea_attestation_msg(const uint8_t ricardian_hash[32],
                                  const uint8_t agent[33],
                                  const bn_t *validator_pubkey,
                                  const bn_t *amount,
                                  const bn_t *attested_limit,
                                  const uint8_t receipt_hash[32],
                                  byte_buf_t *out);

/* Build the executeTea receipt preimage appended to `out` (init'd) exactly as
 * the contract assembles it before sha256, using `state.tx_count` at its
 * PRE-increment value and `now` as int2ByteString(now,4) signed CScriptNum.
 * (Exact field order/widths are reproduced from ricardianTea.ts ~lines 275-284.)
 * `counterparty` is 33 raw bytes; invoice/provenance hashes are 32 raw bytes.
 * TS: ricardianTea.ts::executeTea receipt build. BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int ricardian_tea_receipt_preimage(const ricardian_tea_t *c,
                                   const uint8_t counterparty[33],
                                   const bn_t *amount,
                                   const uint8_t invoice_hash[32],
                                   const uint8_t provenance_hash[32],
                                   int64_t now,
                                   byte_buf_t *out);

/* sha256(receipt preimage) as a freshly malloc'd 64-char lowercase hex string
 * (*out_hex; caller frees). Convenience over ricardian_tea_receipt_preimage.
 * TS: ricardianTea.ts receiptHash = sha256(...). BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int ricardian_tea_receipt_hash(const ricardian_tea_t *c,
                               const uint8_t counterparty[33],
                               const bn_t *amount,
                               const uint8_t invoice_hash[32],
                               const uint8_t provenance_hash[32],
                               int64_t now,
                               char **out_hex);

#endif /* BONSAI_CONTRACTS_RICARDIAN_TEA_H */
