/*
 * tx_parse.h — the minimal shared tx-shape parser used by the reputation
 * indexer, the chain revocation oracle, and the identity chain view.
 *
 * These three modules need only a few cheap reads off a raw tx hex (the outpoint
 * an input spends, whether output[0] is a terminal P2PKH spend, the receipt
 * OP_RETURN hash). Rather than each parsing the wire format independently, they
 * share these helpers, which delegate to the frozen bsv/tx.h model and therefore
 * inherit its DISPLAY-hex (big-endian) prevTxId convention.
 *
 * TS origin: src/reputationIndexer.ts parsePrevout / isTerminalIdentitySpend /
 * parseReceiptHash, reused by src/broker/chainRevocationOracle.ts and
 * src/broker/identityChainView.ts.
 *
 * ENDIANNESS (plan.risks #7): parse_prevout's txid is the DISPLAY (big-endian)
 * hex — bsv's prevTxId.toString('hex') — i.e. the 32 LE wire outpoint bytes
 * reversed. It is directly usable as the next txid for get_raw_tx. length == 64.
 */
#ifndef BONSAI_CHAIN_TX_PARSE_H
#define BONSAI_CHAIN_TX_PARSE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"

/* An outpoint (prev txid display-hex + output index). TS: Prevout. */
typedef struct {
    char     txid[65]; /* 64-hex DISPLAY (big-endian) prev txid + NUL             */
    uint32_t vout;     /* previous output index                                   */
} tx_prevout_t;

/* Parse the outpoint spent by input[input_index] (use 0 for the identity input)
 * of the raw tx hex into *out. txid is the DISPLAY hex (length 64). BNS_OK /
 * BNS_EPARSE (malformed tx or no such input). TS: parsePrevout(rawTxHex, idx). */
int parse_prevout(const char *raw_tx_hex, size_t input_index, tx_prevout_t *out);

/* True iff output[0] is a standard 25-byte P2PKH (76a914..88ac) OR the tx has no
 * outputs — i.e. the spend does NOT recreate the identity (revoke/slash/refund),
 * terminating a chain walk. On a malformed tx the predicate is fail-closed
 * (returns false); callers needing to distinguish parse errors should pre-parse.
 * TS: isTerminalIdentitySpend(rawTxHex). */
bool is_terminal_spend(const char *raw_tx_hex);

#endif /* BONSAI_CHAIN_TX_PARSE_H */
