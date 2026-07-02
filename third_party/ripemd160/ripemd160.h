/*
 * ripemd160.h — standalone RIPEMD-160 (public-domain reference algorithm).
 *
 * Vendored so hash160 (Bitcoin address derivation, P2PKH) does not depend on the
 * OpenSSL 3 legacy provider. Verified against the canonical test vectors:
 *   RIPEMD160("")    = 9c1185a5c5e9fc54612808977ee8f548b2258d31
 *   RIPEMD160("abc") = 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
 */
#ifndef BONSAI_RIPEMD160_H
#define BONSAI_RIPEMD160_H

#include <stddef.h>
#include <stdint.h>

#define RIPEMD160_DIGEST_LENGTH 20
#define RIPEMD160_BLOCK_LENGTH  64

typedef struct {
    uint32_t state[5];      /* MD buffer (h0..h4)              */
    uint64_t length;        /* total message length in bytes   */
    uint8_t  buffer[RIPEMD160_BLOCK_LENGTH];
    size_t   buflen;        /* bytes currently in buffer        */
} ripemd160_ctx;

void ripemd160_init(ripemd160_ctx *ctx);
void ripemd160_update(ripemd160_ctx *ctx, const uint8_t *data, size_t len);
void ripemd160_final(ripemd160_ctx *ctx, uint8_t out[RIPEMD160_DIGEST_LENGTH]);

/* One-shot convenience: out = RIPEMD160(data[0..len)). */
void ripemd160(const uint8_t *data, size_t len, uint8_t out[RIPEMD160_DIGEST_LENGTH]);

#endif /* BONSAI_RIPEMD160_H */
