/*
 * wallet/keygen.c — implementation of wallet_generate_key (see wallet/keygen.h).
 */
#include "wallet/keygen.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h> /* OPENSSL_cleanse — scrub secret key material */

#include "crypto/ecdsa.h"

int wallet_generate_key(bsv_network_t net, char **out_wif, char **out_address)
{
    if (!out_wif || !out_address) return BNS_EINVAL;
    *out_wif = NULL;
    *out_address = NULL;

    ecdsa_key_t *key = NULL;
    int rc = ecdsa_key_random(&key);
    if (rc != BNS_OK) return rc;

    uint8_t secret[BONSAI_ECDSA_SECKEY_LEN];
    rc = ecdsa_key_to_bytes(key, secret);
    if (rc != BNS_OK) { ecdsa_key_free(key); return rc; }

    ecdsa_pubkey_t *pub = NULL;
    rc = ecdsa_key_derive_pubkey(key, &pub);
    if (rc != BNS_OK) {
        OPENSSL_cleanse(secret, sizeof secret);
        ecdsa_key_free(key);
        return rc;
    }

    char *wif = NULL;
    char *addr = NULL;
    rc = wif_encode(secret, /*compressed=*/true, net, &wif);
    if (rc == BNS_OK) rc = address_from_pubkey(pub, net, &addr);

    /* Scrub the raw secret from the stack; the WIF carries it onward. */
    OPENSSL_cleanse(secret, sizeof secret);

    ecdsa_pubkey_free(pub);
    ecdsa_key_free(key);

    if (rc != BNS_OK) {
        /* wif_encode may have already produced the cleartext WIF before
         * address_from_pubkey failed — scrub it before freeing. */
        if (wif) OPENSSL_cleanse(wif, strlen(wif));
        free(wif);
        free(addr);
        return rc;
    }

    *out_wif = wif;
    *out_address = addr;
    return BNS_OK;
}
