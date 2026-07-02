/*
 * tx_builder.h — incremental transaction builder.
 *
 * Accumulates inputs/outputs onto a bsv_tx_t and serializes to raw hex.
 *
 * TS origin: bsv.Transaction builder chain (.addInput/.addOutput/.from/
 * .change/.lockUntilDate/sequence) used by the tx builders and cpfp/agentd.
 */
#ifndef BONSAI_BSV_TX_BUILDER_H
#define BONSAI_BSV_TX_BUILDER_H

#include <stddef.h>
#include <stdint.h>
#include "common/error.h"
#include "common/bytes.h"
#include "bsv/tx.h"

/* Builder over an owned bsv_tx_t. TS: a bsv.Transaction being assembled. */
typedef struct {
    bsv_tx_t tx;   /* the tx under construction (owned) */
} tx_builder_t;

/* Initialise an empty builder (version 1, locktime 0). TS: new bsv.Transaction(). */
void tx_builder_init(tx_builder_t *b);

/* Release the builder and its tx (NULL-safe). */
void tx_builder_free(tx_builder_t *b);

/* Add an input spending `prev_txid_display`:`vout` (DISPLAY/big-endian txid hex,
 * 64 chars) with an initial `script_sig` (may be NULL/0) and `sequence`.
 * TS: tx.addInput(...). BNS_OK / BNS_EINVAL (bad txid) / BNS_ENOMEM. */
int tx_builder_add_input(tx_builder_t *b, const char *prev_txid_display,
                         uint32_t vout, const uint8_t *script_sig,
                         size_t script_sig_len, uint32_t sequence);

/* Add an output with locking `script`/`script_len` and `satoshis`.
 * TS: tx.addOutput(new Output({script, satoshis})). BNS_OK / BNS_ENOMEM. */
int tx_builder_add_output(tx_builder_t *b, const uint8_t *script,
                          size_t script_len, uint64_t satoshis);

/* Set nLockTime. TS: tx.lockUntilDate / nLockTime. */
void tx_builder_set_locktime(tx_builder_t *b, uint32_t locktime);

/* Set nSequence on input `index`. TS: input.sequenceNumber = seq.
 * BNS_OK / BNS_EINVAL (index out of range). */
int tx_builder_set_sequence(tx_builder_t *b, size_t index, uint32_t sequence);

/* Serialize the assembled tx to a freshly malloc'd lowercase raw-tx hex string
 * (*out; caller frees). TS: tx.uncheckedSerialize(). BNS_OK / BNS_ENOMEM. */
int tx_builder_build_hex(const tx_builder_t *b, char **out);

#endif /* BONSAI_BSV_TX_BUILDER_H */
