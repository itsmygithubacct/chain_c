/*
 * address.c — P2PKH address derivation + WIF encode/decode.
 *
 * address = base58check(versionByte || hash160(compressed_pubkey)).
 * WIF      = base58check(0x80/0xef || 32-byte secret || [0x01 if compressed]).
 *
 * TS origin: bsv.Address.fromPublicKey / .toString(), bsv.PrivateKey.{fromWIF,
 * toWIF}.
 */
#include "bsv/address.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h> /* OPENSSL_cleanse — scrub cleartext WIF secret material */

#include "bsv/base58.h"
#include "crypto/hash.h"    /* hash160 */

/* P2PKH version bytes per network. */
#define P2PKH_VERSION_MAINNET 0x00
#define P2PKH_VERSION_TESTNET 0x6f
/* WIF prefix bytes per network. */
#define WIF_PREFIX_MAINNET    0x80
#define WIF_PREFIX_TESTNET    0xef

int address_from_hash160(const uint8_t hash160_bytes[20], bsv_network_t net,
                         char **out)
{
    if (!hash160_bytes || !out) return BNS_EINVAL;
    *out = NULL;

    uint8_t payload[1 + BONSAI_HASH160_LEN];
    payload[0] = (net == BSV_TESTNET) ? P2PKH_VERSION_TESTNET
                                      : P2PKH_VERSION_MAINNET;
    memcpy(payload + 1, hash160_bytes, BONSAI_HASH160_LEN);

    return base58check_encode(payload, sizeof(payload), out);
}

int address_from_pubkey(const ecdsa_pubkey_t *pub, bsv_network_t net,
                        char **out)
{
    if (!pub || !out) return BNS_EINVAL;
    *out = NULL;

    uint8_t sec[BONSAI_ECDSA_PUBKEY_COMPRESSED_LEN];
    int rc = ecdsa_pubkey_serialize_compressed(pub, sec);
    if (rc != BNS_OK) return rc;

    uint8_t h160[BONSAI_HASH160_LEN];
    hash160(sec, sizeof(sec), h160);

    return address_from_hash160(h160, net, out);
}

int wif_decode(const char *wif, uint8_t out_secret[32], bool *out_compressed,
               bsv_network_t *out_net)
{
    if (!wif) return BNS_EINVAL;

    byte_buf_t payload;
    byte_buf_init(&payload);
    int rc = base58check_decode(wif, &payload);
    if (rc != BNS_OK) { byte_buf_free(&payload); return rc; }

    /* payload = prefix(1) || secret(32) || [0x01 if compressed]. The decoded buffer
     * holds the cleartext private key: copy out what we need, then OPENSSL_cleanse +
     * free it on EVERY exit path (a plain byte_buf_free leaves the key recoverable
     * from freed heap / swap / a core dump in this long-lived notary). */
    bool compressed = (payload.len == 34 && payload.data[33] == 0x01);
    bool len_ok = (payload.len == 33) || compressed;
    uint8_t prefix = len_ok ? payload.data[0] : 0;
    uint8_t secret[32];
    if (len_ok) memcpy(secret, payload.data + 1, 32);
    OPENSSL_cleanse(payload.data, payload.len);
    byte_buf_free(&payload);
    if (!len_ok) { OPENSSL_cleanse(secret, sizeof secret); return BNS_EPARSE; }

    bsv_network_t net;
    if (prefix == WIF_PREFIX_MAINNET) {
        net = BSV_MAINNET;
    } else if (prefix == WIF_PREFIX_TESTNET) {
        net = BSV_TESTNET;
    } else {
        OPENSSL_cleanse(secret, sizeof secret);
        return BNS_EPARSE;
    }

    if (out_secret) memcpy(out_secret, secret, 32);
    if (out_compressed) *out_compressed = compressed;
    if (out_net) *out_net = net;

    OPENSSL_cleanse(secret, sizeof secret);
    return BNS_OK;
}

int wif_encode(const uint8_t secret[32], bool compressed, bsv_network_t net,
               char **out)
{
    if (!secret || !out) return BNS_EINVAL;
    *out = NULL;

    uint8_t payload[1 + 32 + 1];
    size_t plen = 1 + 32;
    payload[0] = (net == BSV_TESTNET) ? WIF_PREFIX_TESTNET : WIF_PREFIX_MAINNET;
    memcpy(payload + 1, secret, 32);
    if (compressed) {
        payload[33] = 0x01;
        plen = 34;
    }

    int rc = base58check_encode(payload, plen, out);
    OPENSSL_cleanse(payload, sizeof payload);   /* scrub the cleartext secret copy */
    return rc;
}
