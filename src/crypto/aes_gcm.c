/*
 * aes_gcm.c — AES-256-GCM authenticated encryption (PrivateEnclave seal/open).
 *
 * Wraps OpenSSL EVP. Matches the Node crypto construction used by
 * src/privacy/enclave.ts:
 *   seal: createCipheriv('aes-256-gcm', key, iv); setAAD(aad);
 *         ct = update(pt) || final(); tag = getAuthTag()   (16 bytes)
 *   open: createDecipheriv('aes-256-gcm', key, iv); setAAD(aad);
 *         setAuthTag(tag); pt = update(ct) || final()      (final fails on tag
 *                                                            mismatch / AAD edit)
 *
 * Fixed parameters: 256-bit key, 96-bit (12-byte) IV, 128-bit (16-byte) tag.
 * EVP_aes_256_gcm defaults to a 12-byte IV, so SET_IVLEN is unnecessary for the
 * standard nonce, but we set it explicitly to make the 12-byte contract loud and
 * to be robust if the default ever differs.
 */
#include "crypto/aes_gcm.h"

#include <limits.h>
#include <stdint.h>

#include <openssl/evp.h>

/* AAD must be fed with a NULL output buffer before the plaintext. Node's
 * setAAD maps onto exactly this. May be empty (NULL/0) — Node's seal does not
 * call setAAD when there is no AAD; feeding zero AAD bytes is equivalent. */
static int feed_aad(EVP_CIPHER_CTX *ctx,
                    const uint8_t *aad, size_t aad_len,
                    int encrypt)
{
    if (aad == NULL || aad_len == 0)
        return BNS_OK;
    if (aad_len > (size_t)INT_MAX)
        return BNS_EINVAL;

    int outl = 0;
    int rc = encrypt
        ? EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)aad_len)
        : EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)aad_len);
    return rc == 1 ? BNS_OK : BNS_ECRYPTO;
}

int aes256gcm_seal(const uint8_t key[BONSAI_AES256_KEY_LEN],
                   const uint8_t iv[BONSAI_AES_GCM_IV_LEN],
                   const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *aad, size_t aad_len,
                   byte_buf_t *ciphertext_out,
                   uint8_t tag_out[BONSAI_AES_GCM_TAG_LEN])
{
    if (key == NULL || iv == NULL || ciphertext_out == NULL || tag_out == NULL)
        return BNS_EINVAL;
    if (plaintext == NULL && plaintext_len != 0)
        return BNS_EINVAL;
    if (plaintext_len > (size_t)INT_MAX)
        return BNS_EINVAL;

    int rc = BNS_ECRYPTO;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return BNS_ENOMEM;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            BONSAI_AES_GCM_IV_LEN, NULL) != 1)
        goto out;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto out;

    if (feed_aad(ctx, aad, aad_len, 1) != BNS_OK)
        goto out;

    /* Reserve worst-case output. For GCM (a stream cipher) ciphertext_len ==
     * plaintext_len, but EVP may write up to plaintext_len in update + 0 in
     * final; reserve plaintext_len to receive update output. */
    if (byte_buf_reserve(ciphertext_out,
                         ciphertext_out->len + plaintext_len) != BNS_OK) {
        rc = BNS_ENOMEM;
        goto out;
    }

    int outl = 0;
    uint8_t *wp = ciphertext_out->data + ciphertext_out->len;
    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(ctx, wp, &outl, plaintext,
                              (int)plaintext_len) != 1)
            goto out;
        ciphertext_out->len += (size_t)outl;
    }

    int finl = 0;
    /* No more output expected for GCM, but call final to flush + auth. */
    if (EVP_EncryptFinal_ex(ctx,
                            ciphertext_out->data + ciphertext_out->len,
                            &finl) != 1)
        goto out;
    ciphertext_out->len += (size_t)finl;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            BONSAI_AES_GCM_TAG_LEN, tag_out) != 1)
        goto out;

    rc = BNS_OK;

out:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

int aes256gcm_open(const uint8_t key[BONSAI_AES256_KEY_LEN],
                   const uint8_t iv[BONSAI_AES_GCM_IV_LEN],
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t tag[BONSAI_AES_GCM_TAG_LEN],
                   byte_buf_t *plaintext_out)
{
    if (key == NULL || iv == NULL || tag == NULL || plaintext_out == NULL)
        return BNS_EINVAL;
    if (ciphertext == NULL && ciphertext_len != 0)
        return BNS_EINVAL;
    if (ciphertext_len > (size_t)INT_MAX)
        return BNS_EINVAL;

    int rc = BNS_ECRYPTO;
    /* Track how many plaintext bytes we appended so we can roll back the
     * buffer length if authentication fails (open MUST NOT emit unverified
     * plaintext). */
    size_t start_len = plaintext_out->len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return BNS_ENOMEM;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            BONSAI_AES_GCM_IV_LEN, NULL) != 1)
        goto out;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto out;

    if (feed_aad(ctx, aad, aad_len, 0) != BNS_OK)
        goto out;

    if (byte_buf_reserve(plaintext_out,
                         plaintext_out->len + ciphertext_len) != BNS_OK) {
        rc = BNS_ENOMEM;
        goto out;
    }

    int outl = 0;
    if (ciphertext_len > 0) {
        if (EVP_DecryptUpdate(ctx,
                              plaintext_out->data + plaintext_out->len,
                              &outl, ciphertext, (int)ciphertext_len) != 1)
            goto out;
        plaintext_out->len += (size_t)outl;
    }

    /* Set the expected tag before final; the cast drops const but OpenSSL does
     * not modify the buffer for SET_TAG. */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            BONSAI_AES_GCM_TAG_LEN, (void *)(uintptr_t)tag) != 1)
        goto out;

    int finl = 0;
    /* Final returns 0 on tag mismatch / AAD mismatch / tamper. */
    if (EVP_DecryptFinal_ex(ctx,
                            plaintext_out->data + plaintext_out->len,
                            &finl) != 1) {
        /* Authentication failed: discard any tentative plaintext. */
        plaintext_out->len = start_len;
        rc = BNS_ECRYPTO;
        goto out;
    }
    plaintext_out->len += (size_t)finl;

    rc = BNS_OK;

out:
    if (rc != BNS_OK)
        plaintext_out->len = start_len; /* never leak unverified output */
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}
