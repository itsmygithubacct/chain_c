/*
 * rand.c — CSPRNG byte source with an injectable test seam.
 *
 * Default source wraps OpenSSL RAND_bytes. Tests may install a deterministic
 * override via rand_set_source so ephemeral-key / GCM-IV paths are reproducible.
 *
 * TS origin: Node crypto.randomBytes(len); the seam mirrors the DI'd RNG used in
 * the test fixtures. The default path MUST stay a true CSPRNG.
 */
#include "crypto/rand.h"

#include <limits.h>
#include <openssl/rand.h>

/* Installed override (NULL => use OpenSSL RAND_bytes). Not thread-safe by
 * design: the header documents "set before use". */
static rand_source_fn g_rand_fn = NULL;
static void          *g_rand_ctx = NULL;

void rand_set_source(rand_source_fn fn, void *ctx)
{
    g_rand_fn  = fn;
    g_rand_ctx = ctx;
}

/* CSPRNG-only fill: ALWAYS OpenSSL RAND_bytes, never the test override.
 * RAND_bytes takes an int length; fill in <=INT_MAX chunks so very large requests
 * still work without overflowing the int conversion. */
static int rand_bytes_csprng(uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > (size_t)INT_MAX)
            chunk = (size_t)INT_MAX;
        if (RAND_bytes(buf + off, (int)chunk) != 1)
            return BNS_ECRYPTO;
        off += chunk;
    }
    return BNS_OK;
}

int rand_bytes(uint8_t *buf, size_t len)
{
    if (buf == NULL && len != 0)
        return BNS_EINVAL;

    if (len == 0)
        return BNS_OK;

    if (g_rand_fn != NULL) {
        /* Any non-zero return from the injected source is a failure. */
        return g_rand_fn(g_rand_ctx, buf, len) != 0 ? BNS_ECRYPTO : BNS_OK;
    }

    return rand_bytes_csprng(buf, len);
}

int rand_bytes_secure(uint8_t *buf, size_t len)
{
    /* Long-term KEY material must never be drawn from the process-global override
     * (rand_set_source is for reproducible GCM-IV / ephemeral-nonce test paths only).
     * A test that installs a deterministic source and forgets to reset it would
     * otherwise make ecdsa_key_random produce a fully predictable private key. This
     * path bypasses the override unconditionally. */
    if (buf == NULL && len != 0)
        return BNS_EINVAL;
    if (len == 0)
        return BNS_OK;
    return rand_bytes_csprng(buf, len);
}
