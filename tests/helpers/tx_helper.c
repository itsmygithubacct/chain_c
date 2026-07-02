/* tx_helper.c — see tx_helper.h. */
#include "tx_helper.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "crypto/hash.h"   /* hash160 */

/* ---- deterministic keys ------------------------------------------------- */

int tx_helper_key_from_seed(uint8_t seed_byte, ecdsa_key_t **out)
{
    if (!out) return BNS_EINVAL;
    uint8_t secret[BONSAI_ECDSA_SECKEY_LEN];
    memset(secret, seed_byte, sizeof(secret));
    return ecdsa_key_from_bytes(secret, out);
}

int tx_helper_key(tx_key_role_t role, ecdsa_key_t **out)
{
    return tx_helper_key_from_seed((uint8_t)role, out);
}

int tx_helper_pubkey_hex(tx_key_role_t role, char **out)
{
    if (!out) return BNS_EINVAL;
    *out = NULL;
    ecdsa_key_t *k = NULL;
    int rc = tx_helper_key(role, &k);
    if (rc != BNS_OK) return rc;
    ecdsa_pubkey_t *pub = NULL;
    rc = ecdsa_key_derive_pubkey(k, &pub);
    ecdsa_key_free(k);
    if (rc != BNS_OK) return rc;
    rc = ecdsa_pubkey_to_hex(pub, out);
    ecdsa_pubkey_free(pub);
    return rc;
}

int tx_helper_pubkey_bytes(tx_key_role_t role, uint8_t out33[33])
{
    if (!out33) return BNS_EINVAL;
    ecdsa_key_t *k = NULL;
    int rc = tx_helper_key(role, &k);
    if (rc != BNS_OK) return rc;
    ecdsa_pubkey_t *pub = NULL;
    rc = ecdsa_key_derive_pubkey(k, &pub);
    ecdsa_key_free(k);
    if (rc != BNS_OK) return rc;
    rc = ecdsa_pubkey_serialize_compressed(pub, out33);
    ecdsa_pubkey_free(pub);
    return rc;
}

int tx_helper_hash160(tx_key_role_t role, uint8_t out20[20])
{
    if (!out20) return BNS_EINVAL;
    uint8_t pub33[33];
    int rc = tx_helper_pubkey_bytes(role, pub33);
    if (rc != BNS_OK) return rc;
    hash160(pub33, sizeof(pub33), out20);
    return BNS_OK;
}

/* ---- multi-key signer --------------------------------------------------- */

int tx_signer_new(const tx_key_role_t *roles, size_t n, tx_signer_t *out)
{
    if (!roles || !out || n > 8) return BNS_EINVAL;
    memset(out, 0, sizeof(*out));
    for (size_t i = 0; i < n; i++) {
        int rc = tx_helper_key(roles[i], &out->keys[i]);
        if (rc != BNS_OK) { tx_signer_free(out); return rc; }
        out->count++;
    }
    return BNS_OK;
}

void tx_signer_free(tx_signer_t *s)
{
    if (!s) return;
    for (size_t i = 0; i < s->count; i++) {
        ecdsa_key_free(s->keys[i]);
        s->keys[i] = NULL;
    }
    s->count = 0;
}

const ecdsa_key_t *tx_signer_key(const tx_signer_t *s, tx_key_role_t role)
{
    if (!s) return NULL;
    for (size_t i = 0; i < s->count; i++) {
        uint8_t secret[BONSAI_ECDSA_SECKEY_LEN];
        if (ecdsa_key_to_bytes(s->keys[i], secret) != BNS_OK) continue;
        if (secret[0] == (uint8_t)role) return s->keys[i];
    }
    return NULL;
}

/* ---- dummy funding provider --------------------------------------------- */

int tx_helper_funding(int64_t sats, funding_utxos_t *out)
{
    if (!out) return BNS_EINVAL;
    out->items = calloc(1, sizeof(funding_utxo_t));
    if (!out->items) { out->count = 0; return BNS_ENOMEM; }
    out->count = 1;
    funding_utxo_t *u = &out->items[0];
    snprintf(u->tx_id, sizeof(u->tx_id), "%s", TX_HELPER_FUNDING_TXID);
    u->output_index = 0;
    u->satoshis = sats ? sats : TX_HELPER_FUNDING_SATS;
    u->confirmed = true;
    return BNS_OK;
}

int tx_helper_funding_n(size_t n, int64_t sats_each, funding_utxos_t *out)
{
    if (!out || n == 0) return BNS_EINVAL;
    out->items = calloc(n, sizeof(funding_utxo_t));
    if (!out->items) { out->count = 0; return BNS_ENOMEM; }
    out->count = n;
    for (size_t i = 0; i < n; i++) {
        funding_utxo_t *u = &out->items[i];
        /* Deterministic distinct txids: 'b'*62 + 2 hex of the index. */
        memset(u->tx_id, 'b', 62);
        snprintf(u->tx_id + 62, sizeof(u->tx_id) - 62, "%02x", (unsigned)(i & 0xff));
        u->output_index = 0;
        u->satoshis = sats_each ? sats_each : TX_HELPER_FUNDING_SATS;
        u->confirmed = true;
    }
    return BNS_OK;
}
