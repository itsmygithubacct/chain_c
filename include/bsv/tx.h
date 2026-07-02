/*
 * tx.h — the BSV transaction model: parse, serialize, txid.
 *
 * The tx model contract for the indexer, oracle, view, builders, and cpfp.
 *
 * TS origin: bsv.Transaction (fromString/uncheckedSerialize/.id),
 * Transaction.Input, Transaction.Output; chainSources parsePrevout / getRawTx.
 *
 * ============================================================================
 * prevTxId ENDIANNESS CONVENTION (plan.risks: the single most likely byte-level
 * porting bug — read carefully):
 *
 *   On the WIRE, a tx input's outpoint stores the previous txid in LITTLE-ENDIAN
 *   (reversed) order. bsv.js's Input.prevTxId Buffer + .toString('hex') yields
 *   the BIG-ENDIAN DISPLAY txid (bsv reverses internally), and the TS
 *   indexer/parsePrevout uses that display hex directly as the next txid to
 *   fetch with getRawTx.
 *
 *   THEREFORE: this model stores `prev_txid_display` as the 64-char DISPLAY
 *   (big-endian) hex string — already reversed from the wire bytes. tx_deserialize
 *   MUST reverse the 32 wire bytes when filling it; tx_serialize MUST reverse it
 *   back to little-endian on the wire. tx_id() returns the same DISPLAY hex
 *   (reversed double-SHA256). Test pin: parsePrevout.txid length == 64.
 * ============================================================================
 */
#ifndef BONSAI_BSV_TX_H
#define BONSAI_BSV_TX_H

#include <stddef.h>
#include <stdint.h>
#include "common/error.h"
#include "common/bytes.h"

/* A transaction input. TS: bsv.Transaction.Input. */
typedef struct {
    char       prev_txid_display[65]; /* 64-hex DISPLAY (big-endian) txid + NUL;
                                       * reversed from the LE wire outpoint */
    uint32_t   vout;                  /* previous output index (outputIndex)   */
    byte_buf_t script_sig;            /* unlocking script (owned)              */
    uint32_t   sequence;              /* nSequence                             */
} bsv_txin_t;

/* A transaction output. TS: bsv.Transaction.Output. */
typedef struct {
    uint64_t   satoshis;  /* value (8-byte LE on the wire)        */
    byte_buf_t script;    /* locking script bytes (owned)         */
} bsv_txout_t;

/* A full transaction. TS: bsv.Transaction. Owns its inputs/outputs arrays. */
typedef struct {
    uint32_t     version;     /* nVersion (4-byte LE)              */
    bsv_txin_t  *inputs;      /* owned array, `num_inputs` entries  */
    size_t       num_inputs;
    bsv_txout_t *outputs;     /* owned array, `num_outputs` entries */
    size_t       num_outputs;
    uint32_t     locktime;    /* nLockTime (4-byte LE)             */
} bsv_tx_t;

/* ---- lifecycle ---------------------------------------------------------- */

/* Zero-initialise an empty tx (no allocation). */
void tx_init(bsv_tx_t *tx);

/* Release all owned inputs/outputs/scripts and reset (NULL-safe). */
void tx_free(bsv_tx_t *tx);

/* ---- parse / serialize -------------------------------------------------- */

/* Deserialize a raw-tx hex string into `tx` (caller later tx_free's). Reverses
 * each input's wire LE outpoint into prev_txid_display. TS: new bsv.Transaction(hex).
 * BNS_OK / BNS_EPARSE / BNS_ENOMEM. */
int tx_deserialize(const char *hex, bsv_tx_t *tx);

/* Serialize `tx` to raw wire bytes appended to `out` (init'd). Mirrors bsv
 * uncheckedSerialize (no fee/dust sanity checks). Reverses prev_txid_display
 * back to LE on the wire. TS: tx.uncheckedSerialize() (as bytes).
 * BNS_OK / BNS_ENOMEM. */
int tx_serialize(const bsv_tx_t *tx, byte_buf_t *out);

/* Compute the txid: reversed double-SHA256 of the serialized tx, as a freshly
 * malloc'd 64-char lowercase DISPLAY hex string (*out; caller frees).
 * TS: tx.id (== tx.hash reversed). BNS_OK / BNS_ENOMEM. */
int tx_id(const bsv_tx_t *tx, char **out);

#endif /* BONSAI_BSV_TX_H */
