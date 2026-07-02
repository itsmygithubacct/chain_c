/*
 * aes_gcm.h — AES-256-GCM authenticated encryption for the PrivateEnclave.
 *
 * Wraps OpenSSL EVP AES-256-GCM (no <openssl/...> exposed here). Used by the
 * privacy enclave to seal/unseal secret payloads with a 256-bit key, a 96-bit
 * IV, optional AAD, and a 128-bit auth tag.
 *
 * TS origin: src/privacy/enclave.ts — Node crypto.createCipheriv('aes-256-gcm')
 * / createDecipheriv with getAuthTag/setAuthTag.
 *
 * Convention: fallible fns return int (bonsai_err_t); outputs via byte_buf_t
 * out-params (init'd by caller). open returns BNS_ECRYPTO on auth-tag mismatch.
 */
#ifndef BONSAI_CRYPTO_AES_GCM_H
#define BONSAI_CRYPTO_AES_GCM_H

#include <stddef.h>
#include <stdint.h>
#include "common/error.h"
#include "common/bytes.h"

#define BONSAI_AES256_KEY_LEN 32  /* 256-bit key */
#define BONSAI_AES_GCM_IV_LEN 12  /* 96-bit nonce */
#define BONSAI_AES_GCM_TAG_LEN 16 /* 128-bit auth tag */

/* Encrypt+authenticate. Appends ciphertext to `ciphertext_out` (init'd) and
 * writes the 16-byte auth tag to `tag_out`. `aad`/`aad_len` may be NULL/0.
 * TS: createCipheriv('aes-256-gcm', key, iv) -> update/final + getAuthTag.
 * BNS_OK / BNS_ECRYPTO / BNS_ENOMEM. */
int aes256gcm_seal(const uint8_t key[BONSAI_AES256_KEY_LEN],
                   const uint8_t iv[BONSAI_AES_GCM_IV_LEN],
                   const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *aad, size_t aad_len,
                   byte_buf_t *ciphertext_out,
                   uint8_t tag_out[BONSAI_AES_GCM_TAG_LEN]);

/* Decrypt+verify. Appends recovered plaintext to `plaintext_out` (init'd) ONLY
 * if the tag verifies. `aad`/`aad_len` may be NULL/0.
 * TS: createDecipheriv('aes-256-gcm', key, iv) + setAuthTag -> update/final.
 * BNS_OK / BNS_ECRYPTO (tag mismatch / tamper) / BNS_ENOMEM. */
int aes256gcm_open(const uint8_t key[BONSAI_AES256_KEY_LEN],
                   const uint8_t iv[BONSAI_AES_GCM_IV_LEN],
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t tag[BONSAI_AES_GCM_TAG_LEN],
                   byte_buf_t *plaintext_out);

#endif /* BONSAI_CRYPTO_AES_GCM_H */
