/*
 * script_utils.h — the output-serialization contract: build P2PKH / OP_RETURN
 * scripts and full tx outputs. Shared by every contract method and tx builder.
 *
 * TS origin: bsv.Script.buildPublicKeyHashOut, Script.buildDataOut /
 * buildSafeDataOut, and the output (satoshis||scriptLen||script) wire layout.
 */
#ifndef BONSAI_BSV_SCRIPT_UTILS_H
#define BONSAI_BSV_SCRIPT_UTILS_H

#include <stddef.h>
#include <stdint.h>
#include "common/error.h"
#include "common/bytes.h"

/* Build a P2PKH locking script for `hash160` (20 bytes), appended to `out`
 * (init'd): 76a914 <20B> 88ac. TS: bsv.Script.buildPublicKeyHashOut(addr).hex.
 * BNS_OK / BNS_ENOMEM. */
int build_p2pkh_script(const uint8_t hash160[20], byte_buf_t *out);

/* Build a full P2PKH OUTPUT (8-byte LE satoshis || varint scriptLen || script)
 * for `hash160`, appended to `out` (init'd). TS: new bsv.Transaction.Output
 * { script: buildPublicKeyHashOut, satoshis }. BNS_OK / BNS_ENOMEM. */
int build_p2pkh_output(const uint8_t hash160[20], uint64_t satoshis,
                       byte_buf_t *out);

/* Build an OP_RETURN data-carrier script for `data`/`data_len`, appended to
 * `out` (init'd). Emits the '006a'-prefixed 0-sat receipt form
 * (OP_0 OP_RETURN <pushdata data>). TS: receipt OP_RETURN builder /
 * Script.buildSafeDataOut. BNS_OK / BNS_ENOMEM. */
int build_opreturn_script(const uint8_t *data, size_t data_len, byte_buf_t *out);

/* Build a generic OUTPUT (8-byte LE satoshis || varint scriptLen || script)
 * from an arbitrary locking `script`/`script_len`, appended to `out` (init'd).
 * TS: tx output serialization. BNS_OK / BNS_ENOMEM. */
int build_output(const uint8_t *script, size_t script_len, uint64_t satoshis,
                 byte_buf_t *out);

#endif /* BONSAI_BSV_SCRIPT_UTILS_H */
