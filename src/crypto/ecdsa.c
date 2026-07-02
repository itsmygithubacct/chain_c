/*
 * ecdsa.c — secp256k1 ECDSA signing/verification over libsecp256k1.
 *
 * Implements include/crypto/ecdsa.h. Mirrors bsv.PrivateKey / bsv.PublicKey and
 * bsv.crypto.ECDSA.{sign,verify} / Signature.{toDER,fromDER}.
 *
 * Hashing convention: this module signs/verifies a 32-byte digest VERBATIM.
 * The charter (ricardianCharter.ts signCharter) feeds in SHA256(contractBytes)
 * directly — a single hash — so we never hash again here.
 *
 * Determinism: secp256k1_ecdsa_sign uses RFC6979 deterministic-k (the library
 * default nonce function) and produces a LOW-S signature by default, matching
 * bsv/BIP62. We additionally normalize-low-S defensively before DER output.
 */
#include "crypto/ecdsa.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <secp256k1.h>
#include <openssl/crypto.h>   /* OPENSSL_cleanse for scrubbing the blinding seed */

#include "bsv/base58.h"   /* base58check_decode for WIF */
#include "crypto/rand.h"  /* rand_bytes for ecdsa_key_random */
#include "common/hex.h"

/* ------------------------------------------------------------------------- */
/* Opaque handle definitions.                                                */

struct ecdsa_key_s {
    uint8_t secret[BONSAI_ECDSA_SECKEY_LEN];
};

struct ecdsa_pubkey_s {
    secp256k1_pubkey pub;
};

/* ------------------------------------------------------------------------- */
/* Shared library context.                                                    */
/*
 * One process-wide secp256k1 context with sign+verify capability. Created
 * lazily; never destroyed (lives for the process lifetime). secp256k1 contexts
 * are safe for concurrent use once created with the required flags; creation
 * itself is serialized via pthread_once so concurrent first-callers cannot race
 * (double-create / leak / torn read of g_ctx). Randomization (side-channel
 * blinding) is applied when available but is not required for
 * correctness/determinism.
 */
static secp256k1_context *g_ctx = NULL;
static pthread_once_t      g_ctx_once = PTHREAD_ONCE_INIT;

static void ctx_init(void)
{
    secp256k1_context *c =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                 SECP256K1_CONTEXT_VERIFY);
    if (c == NULL) {
        return; /* g_ctx stays NULL; callers map to BNS_ENOMEM */
    }
    /* Best-effort blinding; ignore failure (does not affect output bytes). */
    uint8_t seed[32];
    if (rand_bytes_secure(seed, sizeof seed) == BNS_OK) {
        int rnd = secp256k1_context_randomize(c, seed);
        (void)rnd; /* blinding is best-effort; failure does not affect bytes */
    }
    /* The seed is RNG secret material; scrub it off the stack. */
    OPENSSL_cleanse(seed, sizeof seed);
    g_ctx = c;
}

static secp256k1_context *ctx_get(void)
{
    pthread_once(&g_ctx_once, ctx_init);
    return g_ctx;
}

/* ------------------------------------------------------------------------- */
/* Private key construction.                                                  */

int ecdsa_key_from_bytes(const uint8_t secret[BONSAI_ECDSA_SECKEY_LEN],
                         ecdsa_key_t **out)
{
    if (secret == NULL || out == NULL) {
        return BNS_EINVAL;
    }
    secp256k1_context *ctx = ctx_get();
    if (ctx == NULL) {
        return BNS_ENOMEM;
    }
    if (!secp256k1_ec_seckey_verify(ctx, secret)) {
        return BNS_EINVAL; /* zero or >= curve order */
    }
    ecdsa_key_t *k = calloc(1, sizeof *k);
    if (k == NULL) {
        return BNS_ENOMEM;
    }
    memcpy(k->secret, secret, BONSAI_ECDSA_SECKEY_LEN);
    *out = k;
    return BNS_OK;
}

int ecdsa_key_from_wif(const char *wif, ecdsa_key_t **out, bool *out_compressed)
{
    if (wif == NULL || out == NULL) {
        return BNS_EINVAL;
    }
    byte_buf_t payload;
    byte_buf_init(&payload);
    int rc = base58check_decode(wif, &payload);
    if (rc != BNS_OK) {
        byte_buf_free(&payload);
        return BNS_EPARSE; /* bad base58check / checksum */
    }

    /*
     * WIF payload layout (after checksum stripped):
     *   [0]            version byte (0x80 mainnet, 0xef testnet)
     *   [1 .. 32]      32-byte secret
     *   [33] (optional) 0x01 => key was generated compressed
     * So total len is 33 (uncompressed) or 34 (compressed) bytes.
     *
     * The decoded buffer holds the cleartext private key: copy out what we need,
     * then OPENSSL_cleanse + free it (and the local copy) on EVERY exit path, so the
     * key is not left recoverable in freed heap / swap / a core dump.
     */
    bool compressed = (payload.len == 1 + BONSAI_ECDSA_SECKEY_LEN + 1 &&
                       payload.data[1 + BONSAI_ECDSA_SECKEY_LEN] == 0x01);
    bool len_ok = (payload.len == 1 + BONSAI_ECDSA_SECKEY_LEN) || compressed;
    uint8_t version = len_ok ? payload.data[0] : 0;
    uint8_t secret[BONSAI_ECDSA_SECKEY_LEN];
    if (len_ok) memcpy(secret, &payload.data[1], BONSAI_ECDSA_SECKEY_LEN);
    OPENSSL_cleanse(payload.data, payload.len);
    byte_buf_free(&payload);
    if (!len_ok || (version != 0x80 && version != 0xef)) {
        OPENSSL_cleanse(secret, sizeof secret);
        return BNS_EPARSE; /* bad length / not a WIF version byte */
    }

    rc = ecdsa_key_from_bytes(secret, out);
    OPENSSL_cleanse(secret, sizeof secret);
    if (rc != BNS_OK) {
        /* in-range secret check failed -> treat as parse error for WIF */
        return (rc == BNS_ENOMEM) ? BNS_ENOMEM : BNS_EPARSE;
    }
    if (out_compressed != NULL) {
        *out_compressed = compressed;
    }
    return BNS_OK;
}

int ecdsa_key_random(ecdsa_key_t **out)
{
    if (out == NULL) {
        return BNS_EINVAL;
    }
    secp256k1_context *ctx = ctx_get();
    if (ctx == NULL) {
        return BNS_ENOMEM;
    }
    uint8_t secret[BONSAI_ECDSA_SECKEY_LEN];
    /* Reject the (astronomically unlikely) out-of-range draws by retrying. */
    for (int attempt = 0; attempt < 16; attempt++) {
        if (rand_bytes_secure(secret, sizeof secret) != BNS_OK) {
            OPENSSL_cleanse(secret, sizeof secret);
            return BNS_ECRYPTO;
        }
        if (secp256k1_ec_seckey_verify(ctx, secret)) {
            int rc = ecdsa_key_from_bytes(secret, out);
            OPENSSL_cleanse(secret, sizeof secret);
            return rc;
        }
    }
    OPENSSL_cleanse(secret, sizeof secret);
    return BNS_ECRYPTO;
}

void ecdsa_key_free(ecdsa_key_t *key)
{
    if (key == NULL) {
        return;
    }
    OPENSSL_cleanse(key->secret, sizeof key->secret); /* scrub secret material (not elidable) */
    free(key);
}

int ecdsa_key_derive_pubkey(const ecdsa_key_t *key, ecdsa_pubkey_t **out)
{
    if (key == NULL || out == NULL) {
        return BNS_EINVAL;
    }
    secp256k1_context *ctx = ctx_get();
    if (ctx == NULL) {
        return BNS_ENOMEM;
    }
    ecdsa_pubkey_t *p = calloc(1, sizeof *p);
    if (p == NULL) {
        return BNS_ENOMEM;
    }
    if (!secp256k1_ec_pubkey_create(ctx, &p->pub, key->secret)) {
        free(p);
        return BNS_ECRYPTO;
    }
    *out = p;
    return BNS_OK;
}

int ecdsa_key_to_bytes(const ecdsa_key_t *key,
                       uint8_t out[BONSAI_ECDSA_SECKEY_LEN])
{
    if (key == NULL || out == NULL) {
        return BNS_EINVAL;
    }
    memcpy(out, key->secret, BONSAI_ECDSA_SECKEY_LEN);
    return BNS_OK;
}

/* ------------------------------------------------------------------------- */
/* Public key parse / serialize.                                              */

int ecdsa_pubkey_parse(const uint8_t *sec, size_t len, ecdsa_pubkey_t **out)
{
    if (sec == NULL || out == NULL) {
        return BNS_EINVAL;
    }
    /* secp256k1_ec_pubkey_parse accepts 33B compressed and 65B uncompressed. */
    if (len != 33 && len != 65) {
        return BNS_EPARSE;
    }
    secp256k1_context *ctx = ctx_get();
    if (ctx == NULL) {
        return BNS_ENOMEM;
    }
    ecdsa_pubkey_t *p = calloc(1, sizeof *p);
    if (p == NULL) {
        return BNS_ENOMEM;
    }
    if (!secp256k1_ec_pubkey_parse(ctx, &p->pub, sec, len)) {
        free(p);
        return BNS_EPARSE;
    }
    *out = p;
    return BNS_OK;
}

int ecdsa_pubkey_from_hex(const char *hex, ecdsa_pubkey_t **out)
{
    if (hex == NULL || out == NULL) {
        return BNS_EINVAL;
    }
    byte_buf_t raw;
    byte_buf_init(&raw);
    int rc = hex_decode(hex, &raw);
    if (rc != BNS_OK) {
        byte_buf_free(&raw);
        return BNS_EPARSE;
    }
    rc = ecdsa_pubkey_parse(raw.data, raw.len, out);
    byte_buf_free(&raw);
    return rc;
}

int ecdsa_pubkey_serialize_compressed(
        const ecdsa_pubkey_t *pub,
        uint8_t out[BONSAI_ECDSA_PUBKEY_COMPRESSED_LEN])
{
    if (pub == NULL || out == NULL) {
        return BNS_EINVAL;
    }
    secp256k1_context *ctx = ctx_get();
    if (ctx == NULL) {
        return BNS_ENOMEM;
    }
    size_t outlen = BONSAI_ECDSA_PUBKEY_COMPRESSED_LEN;
    if (!secp256k1_ec_pubkey_serialize(ctx, out, &outlen, &pub->pub,
                                       SECP256K1_EC_COMPRESSED) ||
        outlen != BONSAI_ECDSA_PUBKEY_COMPRESSED_LEN) {
        return BNS_ECRYPTO;
    }
    return BNS_OK;
}

int ecdsa_pubkey_to_hex(const ecdsa_pubkey_t *pub, char **out)
{
    if (pub == NULL || out == NULL) {
        return BNS_EINVAL;
    }
    uint8_t sec[BONSAI_ECDSA_PUBKEY_COMPRESSED_LEN];
    int rc = ecdsa_pubkey_serialize_compressed(pub, sec);
    if (rc != BNS_OK) {
        return rc;
    }
    char *hex = hex_encode(sec, sizeof sec);
    if (hex == NULL) {
        return BNS_ENOMEM;
    }
    *out = hex;
    return BNS_OK;
}

void ecdsa_pubkey_free(ecdsa_pubkey_t *pub)
{
    free(pub);
}

/* ------------------------------------------------------------------------- */
/* Sign / verify.                                                             */

int ecdsa_sign_low_s(const uint8_t digest32[BONSAI_SHA256_LEN],
                     const ecdsa_key_t *key, byte_buf_t *out)
{
    if (digest32 == NULL || key == NULL || out == NULL) {
        return BNS_EINVAL;
    }
    secp256k1_context *ctx = ctx_get();
    if (ctx == NULL) {
        return BNS_ENOMEM;
    }

    secp256k1_ecdsa_signature sig;
    /* NULL noncefp => library default RFC6979 deterministic-k (matches bsv). */
    if (!secp256k1_ecdsa_sign(ctx, &sig, digest32, key->secret, NULL, NULL)) {
        return BNS_ECRYPTO;
    }
    /* Defensive low-S normalization (sign already returns low-S). */
    (void)secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);

    /* DER is at most 72 bytes for a secp256k1 ECDSA signature. */
    uint8_t der[72];
    size_t der_len = sizeof der;
    if (!secp256k1_ecdsa_signature_serialize_der(ctx, der, &der_len, &sig)) {
        return BNS_ECRYPTO;
    }
    return byte_buf_append(out, der, der_len);
}

bool ecdsa_verify(const uint8_t digest32[BONSAI_SHA256_LEN],
                  const uint8_t *der, size_t der_len,
                  const ecdsa_pubkey_t *pub)
{
    if (digest32 == NULL || der == NULL || pub == NULL || der_len == 0) {
        return false;
    }
    secp256k1_context *ctx = ctx_get();
    if (ctx == NULL) {
        return false;
    }
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_der(ctx, &sig, der, der_len)) {
        return false;
    }
    /* bsv accepts both S parities; secp256k1 verify rejects high-S, so
     * normalize to low-S first to faithfully accept what bsv would. */
    (void)secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);
    return secp256k1_ecdsa_verify(ctx, &sig, digest32, &pub->pub) == 1;
}
