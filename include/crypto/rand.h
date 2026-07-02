/*
 * rand.h — CSPRNG byte source with an injectable test seam.
 *
 * Default impl wraps OpenSSL RAND_bytes (no <openssl/...> exposed here). The
 * function-pointer override lets tests inject deterministic bytes so keygen /
 * ephemeral-key paths are reproducible under test.
 *
 * TS origin: bsv random key generation / Node crypto.randomBytes; the test seam
 * mirrors the DummyProvider / fixed-seed patterns in tests/utils.
 */
#ifndef BONSAI_CRYPTO_RAND_H
#define BONSAI_CRYPTO_RAND_H

#include <stddef.h>
#include <stdint.h>
#include "common/error.h"

/* Fill `buf` with `len` cryptographically random bytes (or the injected source
 * when one is installed). TS: crypto.randomBytes(len). BNS_OK / BNS_ECRYPTO. */
int rand_bytes(uint8_t *buf, size_t len);

/* Like rand_bytes but ALWAYS the OpenSSL CSPRNG — never the rand_set_source
 * override. Use for long-term KEY material (e.g. private-key generation) so a
 * stray test override can never make generated keys predictable. */
int rand_bytes_secure(uint8_t *buf, size_t len);

/* Injectable RNG function-pointer type. Must fill buf[0..len) and return BNS_OK
 * on success (any non-zero is treated as failure). `ctx` is the opaque user
 * pointer passed to rand_set_source. */
typedef int (*rand_source_fn)(void *ctx, uint8_t *buf, size_t len);

/* Install a deterministic/override RNG for testing. Pass fn==NULL to restore
 * the default OpenSSL RAND_bytes source. `ctx` is forwarded to `fn`.
 * TS: dependency-injected RNG seam. Not thread-safe — set before use. */
void rand_set_source(rand_source_fn fn, void *ctx);

#endif /* BONSAI_CRYPTO_RAND_H */
