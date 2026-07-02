/*
 * wallet/keygen.h — generate a fresh random P2PKH key (WIF + address).
 *
 * Reusable library primitive (part of libbonsai_chain) used by the `keygen` CLI
 * and by the chain_c_wallet (`ccw`) key store. Uses ecdsa_key_random (crypto/
 * rand.h) -> compressed pubkey -> base58check address, and wif_encode for the
 * WIF. Keys are compressed (the wallet default).
 */
#ifndef BONSAI_WALLET_KEYGEN_H
#define BONSAI_WALLET_KEYGEN_H

#include "common/error.h"
#include "bsv/address.h"  /* bsv_network_t */

/* Generate a fresh random compressed P2PKH key on `net`.
 * *out_wif and *out_address are freshly malloc'd (caller frees); both are set
 * to NULL on failure. BNS_OK / BNS_EINVAL (NULL out) / BNS_ECRYPTO / BNS_ENOMEM. */
int wallet_generate_key(bsv_network_t net, char **out_wif, char **out_address);

#endif /* BONSAI_WALLET_KEYGEN_H */
