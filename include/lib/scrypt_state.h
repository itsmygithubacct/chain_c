/*
 * scrypt_state.h — get_state_script: build the appended state-script suffix for
 * a stateful contract. A thin helper that DELEGATES to script_codec build_state
 * (scrypt/script_codec.h) so contract modules and resumable agentd share one
 * implementation rather than reassembling the state blob by hand.
 *
 * The state suffix is the OP_RETURN state separator followed by build_state()'s
 * blob: [isGenesis flag][flattened stateProps via the STATE int encoder]
 * [num2bin(stateByteLen,4)][version byte 0x00]. The '6a' inside a contract's
 * COMPILED hex template is code, NOT this separator (plan.risks #9) — this
 * helper appends only the genuine state suffix.
 *
 * TS origin: scrypt-ts SmartContract state getter / getStateScript();
 * src/contracts (*.ts) state-script assembly.
 */
#ifndef BONSAI_LIB_SCRYPT_STATE_H
#define BONSAI_LIB_SCRYPT_STATE_H

#include <stddef.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"
#include "scrypt/scrypt_contract.h"   /* scrypt_param_t, scrypt_arg_t */

/* Build the state-script suffix for the given stateProps + values into `out`
 * (init'd): appends the OP_RETURN state separator then delegates to script_codec
 * build_state(state_props, values, count, is_genesis). `state_props`/`values`
 * are parallel arrays of length `count`. TS: contract getStateScript().
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int get_state_script(const scrypt_param_t *state_props,
                     const scrypt_arg_t *values, size_t count,
                     bool is_genesis, byte_buf_t *out);

#endif /* BONSAI_LIB_SCRYPT_STATE_H */
