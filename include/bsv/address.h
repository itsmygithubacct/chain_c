/*
 * address.h — P2PKH address derivation + WIF encode/decode.
 *
 * address = base58check(versionByte || hash160(compressed_pubkey)).
 * WIF      = base58check(0x80/0xef || 32-byte secret || [0x01 if compressed]).
 *
 * TS origin: bsv.Address.fromPublicKey / .toString(), bsv.PrivateKey.{fromWIF,
 * toWIF}, and the cpfp.ts WIF-decode / P2PKH derivation notes.
 */
#ifndef BONSAI_BSV_ADDRESS_H
#define BONSAI_BSV_ADDRESS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/ecdsa.h"

/* Network selector controlling version bytes. TS: bsv.Networks.{mainnet,testnet}. */
typedef enum {
    BSV_MAINNET = 0,   /* P2PKH version 0x00, WIF prefix 0x80 */
    BSV_TESTNET = 1    /* P2PKH version 0x6f, WIF prefix 0xef */
} bsv_network_t;

/* Derive the base58check P2PKH address string from a compressed pubkey on the
 * given network. *out is freshly malloc'd (caller frees).
 * TS: bsv.Address.fromPublicKey(pub, network).toString().
 * BNS_OK / BNS_ECRYPTO / BNS_ENOMEM. */
int address_from_pubkey(const ecdsa_pubkey_t *pub, bsv_network_t net,
                        char **out);

/* Derive the base58check P2PKH address from a precomputed 20-byte hash160.
 * *out is freshly malloc'd (caller frees). TS: Address from hash160.
 * BNS_OK / BNS_ENOMEM. */
int address_from_hash160(const uint8_t hash160[20], bsv_network_t net,
                         char **out);

/* Decode a WIF string -> 32-byte secret + compressed flag + network. Any
 * out-param may be NULL if not needed. Verifies the base58check checksum and
 * the version byte. TS: bsv.PrivateKey.fromWIF.
 * BNS_OK / BNS_EPARSE (base58/version) / BNS_EINTEGRITY (checksum). */
int wif_decode(const char *wif, uint8_t out_secret[32], bool *out_compressed,
               bsv_network_t *out_net);

/* Encode a 32-byte secret as WIF for the given network and compressed flag.
 * *out is freshly malloc'd (caller frees). TS: privKey.toWIF().
 * BNS_OK / BNS_ENOMEM. */
int wif_encode(const uint8_t secret[32], bool compressed, bsv_network_t net,
               char **out);

#endif /* BONSAI_BSV_ADDRESS_H */
