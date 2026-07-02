/*
 * base58.c — Base58 and Base58Check encode/decode.
 *
 * Big-endian base58 (Bitcoin alphabet); each leading 0x00 byte maps to a
 * leading '1'. Base58Check appends first 4 bytes of SHA256(SHA256(payload)).
 *
 * TS origin: bsv.encoding.Base58 / Base58Check.{encode,decode}.
 */
#include "bsv/base58.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/hash.h"   /* sha256d */
#include <openssl/crypto.h> /* OPENSSL_cleanse — the WIF paths route secret key bytes through these */

/* cleanse-then-free: base58 is also used for non-secret addresses, but the WIF decode/encode paths
 * put the cleartext private key into these scratch buffers, and a plain free leaves it recoverable
 * from freed heap / swap / a core dump (review-2 #4/#5). Cleansing the small buffers is cheap. */
static void secure_free(void *p, size_t n) { if (p) { OPENSSL_cleanse(p, n); free(p); } }

static const char B58_ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* Reverse lookup: byte value -> base58 digit (0..57), or -1 if not a digit. */
static int b58_value(unsigned char c)
{
    static int8_t table[256];
    static int init = 0;
    if (!init) {
        for (int i = 0; i < 256; i++) table[i] = -1;
        for (int i = 0; i < 58; i++)
            table[(unsigned char)B58_ALPHABET[i]] = (int8_t)i;
        init = 1;
    }
    return table[c];
}

int base58_encode(const uint8_t *data, size_t len, char **out)
{
    if (!out) return BNS_EINVAL;
    *out = NULL;

    /* Count leading zero bytes (each -> a leading '1'). */
    size_t zeros = 0;
    while (zeros < len && data[zeros] == 0) zeros++;

    /* Upper bound on output digits: len * log(256)/log(58) ~= len * 1.365 + 1.
     * Use len * 138 / 100 + 1 (standard Bitcoin bound). */
    size_t size = (len * 138u) / 100u + 1u;
    uint8_t *buf = (uint8_t *)calloc(size, 1);
    if (!buf) return BNS_ENOMEM;

    size_t high = size; /* index of highest set digit, working from the end */
    for (size_t i = zeros; i < len; i++) {
        int carry = data[i];
        size_t j = size - 1;
        /* Process from end backwards until carry consumed and reaching `high`. */
        for (;; j--) {
            carry += 256 * buf[j];
            buf[j] = (uint8_t)(carry % 58);
            carry /= 58;
            if (j <= high && carry == 0) break;
            if (j == 0) break;
        }
        high = j;
    }

    /* Skip leading zero digits in buf (after the computed range). */
    size_t it = 0;
    while (it < size && buf[it] == 0) it++;

    /* Output = zeros * '1' + remaining digits. */
    size_t out_len = zeros + (size - it);
    char *s = (char *)malloc(out_len + 1);
    if (!s) { secure_free(buf, size); return BNS_ENOMEM; }

    size_t k = 0;
    for (size_t i = 0; i < zeros; i++) s[k++] = '1';
    for (; it < size; it++) s[k++] = B58_ALPHABET[buf[it]];
    s[k] = '\0';

    secure_free(buf, size);
    *out = s;
    return BNS_OK;
}

int base58_decode(const char *str, byte_buf_t *out)
{
    if (!str || !out) return BNS_EINVAL;

    size_t slen = strlen(str);

    /* Count leading '1' chars (each -> a leading 0x00 byte). */
    size_t zeros = 0;
    while (zeros < slen && str[zeros] == '1') zeros++;

    /* Upper bound on output bytes: slen * log(58)/log(256) ~= slen * 0.733. */
    size_t size = (slen * 733u) / 1000u + 1u;
    uint8_t *buf = (uint8_t *)calloc(size, 1);
    if (!buf) return BNS_ENOMEM;

    size_t high = size;
    for (size_t i = zeros; i < slen; i++) {
        int v = b58_value((unsigned char)str[i]);
        if (v < 0) { secure_free(buf, size); return BNS_EPARSE; }
        int carry = v;
        size_t j = size - 1;
        for (;; j--) {
            carry += 58 * buf[j];
            buf[j] = (uint8_t)(carry & 0xff);
            carry >>= 8;
            if (j <= high && carry == 0) break;
            if (j == 0) break;
        }
        high = j;
    }

    /* Skip leading zero bytes in buf. */
    size_t it = 0;
    while (it < size && buf[it] == 0) it++;

    size_t out_len = zeros + (size - it);
    int rc = byte_buf_reserve(out, out_len ? out_len : 1);
    if (rc != BNS_OK) { secure_free(buf, size); return rc; }

    for (size_t i = 0; i < zeros; i++) {
        rc = byte_buf_append_byte(out, 0x00);
        if (rc != BNS_OK) { secure_free(buf, size); return rc; }
    }
    rc = byte_buf_append(out, buf + it, size - it);
    secure_free(buf, size);
    return rc;
}

int base58check_encode(const uint8_t *data, size_t len, char **out)
{
    if (!out) return BNS_EINVAL;
    *out = NULL;

    uint8_t digest[BONSAI_SHA256_LEN];
    sha256d(data, len, digest);

    uint8_t *payload = (uint8_t *)malloc(len + 4);
    if (!payload) return BNS_ENOMEM;
    if (len) memcpy(payload, data, len);
    memcpy(payload + len, digest, 4);

    int rc = base58_encode(payload, len + 4, out);
    secure_free(payload, len + 4);
    return rc;
}

int base58check_decode(const char *str, byte_buf_t *out)
{
    if (!str || !out) return BNS_EINVAL;

    byte_buf_t raw;
    byte_buf_init(&raw);
    int rc = base58_decode(str, &raw);
    if (rc != BNS_OK) { (OPENSSL_cleanse(raw.data, raw.len), byte_buf_free(&raw)); return rc; }

    if (raw.len < 4) { (OPENSSL_cleanse(raw.data, raw.len), byte_buf_free(&raw)); return BNS_EPARSE; }

    size_t plen = raw.len - 4;
    uint8_t digest[BONSAI_SHA256_LEN];
    sha256d(raw.data, plen, digest);

    if (memcmp(digest, raw.data + plen, 4) != 0) {
        (OPENSSL_cleanse(raw.data, raw.len), byte_buf_free(&raw));
        return BNS_EINTEGRITY;
    }

    rc = byte_buf_append(out, raw.data, plen);
    (OPENSSL_cleanse(raw.data, raw.len), byte_buf_free(&raw));
    return rc;
}
