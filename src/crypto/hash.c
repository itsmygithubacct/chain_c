/*
 * hash.c — the single hashing contract for the whole port.
 *
 * SHA256/SHA512 via OpenSSL default provider; RIPEMD160 via the vendored
 * third_party/ripemd160 (so hash160/address derivation never depends on the
 * OpenSSL 3 legacy provider). See include/crypto/hash.h for the contract.
 *
 *   sha256d  = SHA256(SHA256(x))          (txid, BIP143 double-hash)
 *   hash160  = RIPEMD160(SHA256(x))       (BSV pubkey hash / P2PKH address)
 */
#include "crypto/hash.h"

#include <openssl/sha.h>

#include "common/hex.h"
#include "ripemd160.h"

/* ---- raw byte forms ----------------------------------------------------- */

/* Empty-input sentinel so we never hand a NULL pointer to OpenSSL/ripemd160
 * for a zero-length message (the digest of "" is still well defined). */
static const uint8_t kEmpty[1] = { 0 };

void sha256(const uint8_t *data, size_t len, uint8_t out[BONSAI_SHA256_LEN])
{
    SHA256((data != NULL) ? data : kEmpty, len, out);
}

void sha256d(const uint8_t *data, size_t len, uint8_t out[BONSAI_SHA256_LEN])
{
    uint8_t first[BONSAI_SHA256_LEN];
    SHA256((data != NULL) ? data : kEmpty, len, first);
    SHA256(first, sizeof(first), out);
}

void ripemd160_hash(const uint8_t *data, size_t len,
                    uint8_t out[BONSAI_RIPEMD160_LEN])
{
    ripemd160((data != NULL) ? data : kEmpty, len, out);
}

void hash160(const uint8_t *data, size_t len, uint8_t out[BONSAI_HASH160_LEN])
{
    uint8_t sha[BONSAI_SHA256_LEN];
    SHA256((data != NULL) ? data : kEmpty, len, sha);
    ripemd160(sha, sizeof(sha), out);
}

void sha512(const uint8_t *data, size_t len, uint8_t out[BONSAI_SHA512_LEN])
{
    SHA512((data != NULL) ? data : kEmpty, len, out);
}

/* ---- hex-in / hex-out convenience forms --------------------------------- */

/* Shared driver: decode hex_in, run `fn` over the bytes producing `out_len`
 * digest bytes, then encode lowercase hex into *hex_out (caller frees). */
static int hash_hex_impl(const char *hex_in, char **hex_out,
                         void (*fn)(const uint8_t *, size_t, uint8_t *),
                         size_t out_len)
{
    byte_buf_t in;
    uint8_t digest[BONSAI_SHA512_LEN]; /* largest possible digest */
    char *encoded;
    int rc;

    if (hex_out == NULL) {
        return BNS_EINVAL;
    }
    *hex_out = NULL;

    byte_buf_init(&in);
    rc = hex_decode(hex_in, &in);
    if (rc != BNS_OK) {
        byte_buf_free(&in);
        return rc; /* BNS_EPARSE on bad hex */
    }

    fn(in.data, in.len, digest);
    byte_buf_free(&in);

    encoded = hex_encode(digest, out_len);
    if (encoded == NULL) {
        return BNS_ENOMEM;
    }
    *hex_out = encoded;
    return BNS_OK;
}

int sha256_hex(const char *hex_in, char **hex_out)
{
    return hash_hex_impl(hex_in, hex_out, sha256, BONSAI_SHA256_LEN);
}

int sha256d_hex(const char *hex_in, char **hex_out)
{
    return hash_hex_impl(hex_in, hex_out, sha256d, BONSAI_SHA256_LEN);
}

int ripemd160_hex(const char *hex_in, char **hex_out)
{
    return hash_hex_impl(hex_in, hex_out, ripemd160_hash,
                         BONSAI_RIPEMD160_LEN);
}

int hash160_hex(const char *hex_in, char **hex_out)
{
    return hash_hex_impl(hex_in, hex_out, hash160, BONSAI_HASH160_LEN);
}

int sha512_hex(const char *hex_in, char **hex_out)
{
    return hash_hex_impl(hex_in, hex_out, sha512, BONSAI_SHA512_LEN);
}

/* ---- byte_buf convenience ----------------------------------------------- */

int sha256_buf(const byte_buf_t *in, byte_buf_t *out)
{
    uint8_t digest[BONSAI_SHA256_LEN];
    const uint8_t *data = (in != NULL) ? in->data : NULL;
    size_t len = (in != NULL) ? in->len : 0;

    sha256(data, len, digest);
    return byte_buf_append(out, digest, sizeof(digest));
}
