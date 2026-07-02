/*
 * scrypt_state.c — get_state_script: thin delegate to script_codec build_state.
 *
 * TS origin: scrypt-ts SmartContract.getStateScript() returns
 *   codePart + VarIntWriter.serializeState(sBuf)
 * where codePart ends with the OP_RETURN separator byte 0x6a
 * (scryptlib Contract.codePart: `_wrapNOPScript(...).add(Script.fromHex('6a'))`)
 * and serializeState wraps the flattened state body (which begins with the
 * isGenesis bool flag) with the trailing num2bin(stateByteLen,4) + version byte.
 *
 * This helper appends ONLY the genuine state suffix: the OP_RETURN state
 * separator (0x6a) followed by build_state()'s blob. Any '6a' bytes already
 * inside a contract's COMPILED hex template are code, NOT this separator
 * (plan.risks #9); reconstruct_locking_script handles the code part, this
 * helper handles only the appended state suffix.
 */
#include "lib/scrypt_state.h"

#include "scrypt/script_codec.h"   /* build_state */

/* OP_RETURN — the on-chain state separator that precedes the state blob. */
#define BONSAI_OP_RETURN 0x6a

int get_state_script(const scrypt_param_t *state_props,
                     const scrypt_arg_t *values, size_t count,
                     bool is_genesis, byte_buf_t *out)
{
    int rc;

    /* Append the OP_RETURN state separator. */
    rc = byte_buf_append_byte(out, BONSAI_OP_RETURN);
    if (rc != BNS_OK) return rc;

    /* Delegate the state blob assembly to script_codec build_state (encoder B). */
    return build_state(state_props, values, count, is_genesis, out);
}
