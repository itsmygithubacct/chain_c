/*
 * script_codec.h — the scrypt LOCKING-SCRIPT encoders + full locking-script
 * reconstruction. This is where the THREE distinct integer encoders converge.
 *
 * =====================  CRITICAL: THREE INT ENCODERS  =======================
 * Picking the wrong integer encoder silently changes EVERY locking script,
 * receipt hash, and on-chain binding. There are THREE, and they are NOT
 * interchangeable (plan.risks #1 / #2):
 *
 *   (A) CONSTRUCTOR int encoder  — to_script_hex(value, SCRYPT_TYPE_INT):
 *       OPCODE-OPTIMIZED, emitted as Bitcoin Script pushdata exactly like
 *       scryptlib substitutes a ctor `int` arg:
 *         0      -> OP_0          (single byte 0x00)
 *         1..16  -> OP_1..OP_16   (0x51..0x60)
 *         -1     -> OP_1NEGATE    (0x4f)
 *         else   -> minimal CScriptNum body (int2bytestring_minimal) prefixed
 *                   with its pushdata length opcode (minimal push).
 *       This is the encoder used for ctor-arg leaves in the locking script.
 *
 *   (B) STATE int encoder        — build_state() internal "int2hex":
 *       NO opcode optimization. Emits the minimal sign-magnitude CScriptNum body
 *       (int2bytestring_minimal) prefixed by its OWN pushdata length opcode, with
 *       NO OP_0/OP_1..OP_16/OP_1NEGATE special-casing. So state txCount==1 is a
 *       1-byte push '01' (51-style is FORBIDDEN here), state 0 is an empty push.
 *       Used for every stateProps `int`/`Sha256` value in the appended state.
 *
 *   (C) FIXED-WIDTH int encoder  — bsv/num2bin.h int2bytestring_sized():
 *       Receipt/attestation preimage fields (num2bin two-arg). NOT a script
 *       encoder; lives in num2bin.h. Listed here only so the distinction is
 *       complete — do NOT call it from this module for ctor/state ints.
 *
 * The ONLY non-opcode difference between (A) and (B) is the OP_0/OP_1..16/
 * OP_1NEGATE small-int optimization, which (A) applies and (B) does NOT.
 * Golden vector (rabinSpike int2hex sign-byte case): oracle
 * 12345678901234567890 -> minimal body 'd20a1feb8ca954ab00' (high bit of 0xab
 * set => 0x00 sign byte appended), pushdata-prefixed '09d20a1feb8ca954ab00'.
 * ============================================================================
 *
 * TS origin: scryptlib `Contract` locking-script assembly + scrypt-ts
 * `buildContractState` / state getter; bsv.Script number pushes; the `int2hex`
 * stateful encoder; src/contracts (*.ts) getStateScript() state suffix.
 */
#ifndef BONSAI_SCRYPT_SCRIPT_CODEC_H
#define BONSAI_SCRYPT_SCRIPT_CODEC_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"
#include "scrypt/scrypt_contract.h"

/* State-metadata constants (the suffix appended after the flattened state).
 * TS: scrypt-ts buildContractState. */
#define BONSAI_SCRYPT_STATE_LEN_WIDTH 4    /* num2bin(stateByteLen, 4)            */
#define BONSAI_SCRYPT_STATE_VERSION   0x00 /* trailing state version byte         */

/* ---- (A) CONSTRUCTOR encoders ------------------------------------------- */

/* Encode a single typed CONSTRUCTOR argument value into its locking-script
 * pushdata bytes, appended to `out` (init'd). Dispatches on `value->tag`
 * (which must equal `type`, passed for the caller's intent/assertion):
 *   INT          -> OPCODE-OPTIMIZED int push (see (A) above)
 *   BOOL         -> OP_0 (false) / OP_1 (true)
 *   BYTES/PUBKEY/SHA256/RIPEMD160 -> minimal pushdata of the raw payload
 *   RABIN_PUBKEY -> same opcode-optimized int push as INT (it is an int alias)
 * Compound tags (FIXED_ARRAY/STRUCT) are NOT accepted here — flatten first via
 * flatten_args, then encode each scalar leaf. TS: scryptlib ctor-arg substitution.
 * BNS_OK / BNS_EINVAL (compound tag or tag/type mismatch) / BNS_ENOMEM. */
int to_script_hex(const scrypt_arg_t *value, scrypt_type_t type, byte_buf_t *out);

/* ---- (B) STATE encoders ------------------------------------------------- */

/* Build the appended on-chain STATE blob for a stateful contract, appended to
 * `out` (init'd). Layout (scrypt-ts buildContractState):
 *   [ isGenesis flag byte ]                 (0x01 genesis, 0x00 otherwise)
 *   [ each stateProps value via the STATE int encoder (B) / pushdata ]
 *   [ num2bin(stateByteLen, 4) ]            (4-byte LE length of the state body)
 *   [ version byte 0x00 ]
 * `state_props`/`values` are parallel arrays (length `count`). Each value is
 * encoded with the STATE encoder (B): NO opcode optimization for ints; Sha256/
 * bytes as minimal pushdata. `stateByteLen` is the length of the encoded state
 * body that the 4-byte meta measures (matching scrypt-ts). TS: scrypt-ts
 * buildContractState(isGenesis). BNS_OK / BNS_EINVAL / BNS_ENOMEM.
 *
 * WARNING: do NOT use to_script_hex()'s int path here — state ints must use (B). */
int build_state(const scrypt_param_t *state_props,
                const scrypt_arg_t *values, size_t count,
                bool is_genesis, byte_buf_t *out);

/* ---- full locking-script reconstruction --------------------------------- */

/* Reconstruct a contract's complete locking script bytes into `out` (init'd):
 *   1. flatten_args(artifact, ctor_values) -> ordered leaves;
 *   2. substitute each <name> placeholder in artifact->hex_template with its
 *      leaf encoded via to_script_hex (A) (in flatten order);
 *   3. if artifact->stateful, append the OP_RETURN state separator and
 *      build_state(stateProps, state_values, is_genesis) (B).
 * The compiled hex template already contains the COMPILED CODE PART (any '6a'
 * bytes inside it are code, NOT the state separator — plan.risks #9); the state
 * separator + blob are appended only for stateful contracts.
 * `state_values` may be NULL for stateless contracts (then is_genesis is
 * ignored). TS: scryptlib lockingScript reconstruction + scrypt-ts state suffix.
 * BNS_OK / BNS_EINVAL (arity/type) / BNS_EPARSE (bad template) / BNS_ENOMEM. */
int reconstruct_locking_script(const scrypt_artifact_t *artifact,
                               const scrypt_arg_t *ctor_values,
                               size_t num_ctor_values,
                               const scrypt_arg_t *state_values,
                               size_t num_state_values,
                               bool is_genesis,
                               byte_buf_t *out);

#endif /* BONSAI_SCRYPT_SCRIPT_CODEC_H */
