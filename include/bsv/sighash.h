/*
 * sighash.h — BIP143/FORKID sighash preimage + digest for BSV signing.
 *
 * Computes the BSV (BIP143-style, FORKID) sighash preimage and its double-SHA256
 * digest, which is then signed by ecdsa_sign_low_s. The default sighash flag is
 * 0x41 = SIGHASH_ALL | SIGHASH_FORKID — BSV mainnet REQUIRES FORKID or the
 * broadcast is rejected (plan.risks). This is distinct from the charter, which
 * signs a single-SHA256 digest directly (see crypto/ecdsa.h).
 *
 * TS origin: bsv.Transaction.Sighash.sighashPreimage / sighash with
 * SIGHASH_ALL|SIGHASH_FORKID; the cpfp/agentTea/liveAgentSmoke signing paths.
 *
 * Preimage field order (BIP143):
 *   nVersion | hashPrevouts | hashSequence | outpoint | scriptCode |
 *   amount | nSequence | hashOutputs | nLocktime | sighashType
 */
#ifndef BONSAI_BSV_SIGHASH_H
#define BONSAI_BSV_SIGHASH_H

#include <stddef.h>
#include <stdint.h>
#include "common/error.h"
#include "common/bytes.h"
#include "bsv/tx.h"
#include "crypto/hash.h"

/* SIGHASH_ALL | SIGHASH_FORKID — the BSV default sighash flag byte. */
#define BONSAI_SIGHASH_ALL_FORKID 0x41

/* Build the BIP143/FORKID sighash PREIMAGE for signing `input_index` of `tx`,
 * appended to `out` (init'd). `script_code`/`script_code_len` is the scriptCode
 * being signed (the prevout's locking script, or the contract code part);
 * `input_satoshis` is the value of the output being spent; `sighash_type` is
 * typically BONSAI_SIGHASH_ALL_FORKID. TS: Sighash.sighashPreimage(...).
 * BNS_OK / BNS_EINVAL (bad index) / BNS_ENOMEM. */
int bip143_preimage(const bsv_tx_t *tx, size_t input_index,
                    const uint8_t *script_code, size_t script_code_len,
                    uint64_t input_satoshis, uint8_t sighash_type,
                    byte_buf_t *out);

/* Build the preimage (as bip143_preimage) and return its double-SHA256 digest
 * in out_digest32 — the 32-byte value handed to ecdsa_sign_low_s.
 * TS: hash256(sighashPreimage(...)). BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int bip143_sighash(const bsv_tx_t *tx, size_t input_index,
                   const uint8_t *script_code, size_t script_code_len,
                   uint64_t input_satoshis, uint8_t sighash_type,
                   uint8_t out_digest32[BONSAI_SHA256_LEN]);

#endif /* BONSAI_BSV_SIGHASH_H */
