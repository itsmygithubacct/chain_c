/*
 * tx_helper.h — deterministic multi-key signing + dummy funding helpers for the
 * contract tx-builder tests. The C port of chain/tests/utils/txHelper.ts
 * (getDefaultSigner — a multi-key TestWallet over a DummyProvider — and the
 * inline `funding()` UTXO providers in ricardianTea/agentd tests).
 *
 * Goals (mirroring the TS):
 *  - DETERMINISM: keys come from fixed seed bytes (not fromRandom), so signers,
 *    pubkeys, hash160 change-addresses, and funding outputs are byte-stable and
 *    output ordering in the built tx never moves between runs.
 *  - EXPLICIT FUNDING: a single fixed funding UTXO (txid='bb'*64, vout 0, a
 *    P2PKH over the agent key, fixed sats) so fee/change math is reproducible.
 *
 * All ecdsa_key_t / ecdsa_pubkey_t out-params are owned (free with the matching
 * ecdsa_*_free). char* out-params are freshly malloc'd (caller frees).
 */
#ifndef BONSAI_TEST_TX_HELPER_H
#define BONSAI_TEST_TX_HELPER_H

#include <stddef.h>
#include <stdint.h>
#include "common/error.h"
#include "crypto/ecdsa.h"
#include "chainSources/utxo_select.h"   /* funding_utxos_t, funding_utxo_t */

/* Canonical seed roles for the deterministic test keys. The seed byte is
 * replicated 32 times to form the secret (e.g. ELDER => 0x01..01). These are the
 * C analogues of the TS `elder` / `agent` / `counterparty` PrivateKeys. */
typedef enum {
    TX_KEY_ELDER        = 0x01,
    TX_KEY_AGENT        = 0x02,
    TX_KEY_COUNTERPARTY = 0x03,
    TX_KEY_VALIDATOR    = 0x04,
    TX_KEY_REPORTER     = 0x05,
} tx_key_role_t;

/* The fixed funding txid the TS funding() uses ('bb'*64) and its sats. */
#define TX_HELPER_FUNDING_TXID \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define TX_HELPER_FUNDING_SATS 10000000  /* TS funding(): satoshis: 10_000_000 */

/* ---- deterministic keys ------------------------------------------------- */

/* Build the deterministic private key for `role` (secret = role byte x32) into
 * *out (owned; ecdsa_key_free). TS: bsv.PrivateKey for elder/agent/...
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int tx_helper_key(tx_key_role_t role, ecdsa_key_t **out);

/* Build a deterministic key from an arbitrary `seed_byte` (secret = byte x32).
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int tx_helper_key_from_seed(uint8_t seed_byte, ecdsa_key_t **out);

/* The compressed pubkey of `role` as a freshly malloc'd 66-hex string (*out;
 * caller frees). TS: PubKey(toHex(key.publicKey)). BNS_OK / BNS_ENOMEM. */
int tx_helper_pubkey_hex(tx_key_role_t role, char **out);

/* The 33 raw compressed-pubkey bytes of `role` into `out33`. (Many builders take
 * a 33-byte counterparty/reporter pubkey.) BNS_OK / BNS_ECRYPTO / BNS_ENOMEM. */
int tx_helper_pubkey_bytes(tx_key_role_t role, uint8_t out33[33]);

/* The hash160 (BSV pubkey hash / P2PKH address body) of `role` into `out20`.
 * Used as a change_hash160 / counterparty payout address. BNS_OK / errors. */
int tx_helper_hash160(tx_key_role_t role, uint8_t out20[20]);

/* ---- multi-key signer --------------------------------------------------- */

/* A deterministic multi-key signer: the set of private keys allowed to sign a
 * tx, the C analogue of getDefaultSigner([elder, agent, counterparty]). Owns its
 * keys; release with tx_signer_free. */
typedef struct {
    ecdsa_key_t *keys[8];
    size_t       count;
} tx_signer_t;

/* Build a signer holding the deterministic keys for the given `roles`/`n`
 * (n <= 8). TS: getDefaultSigner([...]). BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int tx_signer_new(const tx_key_role_t *roles, size_t n, tx_signer_t *out);

/* Release all owned keys (NULL-safe). */
void tx_signer_free(tx_signer_t *s);

/* Borrowed pointer to the signer's key for `role`, or NULL if absent. */
const ecdsa_key_t *tx_signer_key(const tx_signer_t *s, tx_key_role_t role);

/* ---- dummy funding provider --------------------------------------------- */

/* Fill *out with a single explicit, deterministic funding UTXO
 * (txid=TX_HELPER_FUNDING_TXID, vout 0, satoshis=`sats`, confirmed=true). Pass
 * sats 0 to use TX_HELPER_FUNDING_SATS. Owns one funding_utxo_t; release with
 * funding_utxos_free. TS: the inline funding() UTXO. BNS_OK / BNS_ENOMEM. */
int tx_helper_funding(int64_t sats, funding_utxos_t *out);

/* Fill *out with `n` deterministic confirmed funding UTXOs:
 * txid 'b0'..(little incrementing last byte), each vout 0, value `sats_each`
 * (0 => TX_HELPER_FUNDING_SATS), confirmed. Output ordering is therefore stable.
 * Release with funding_utxos_free. BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int tx_helper_funding_n(size_t n, int64_t sats_each, funding_utxos_t *out);

#endif /* BONSAI_TEST_TX_HELPER_H */
