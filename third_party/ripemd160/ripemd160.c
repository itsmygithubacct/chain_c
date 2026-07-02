/*
 * ripemd160.c — standalone RIPEMD-160 implementation (public domain).
 *
 * Reference: H. Dobbertin, A. Bosselaers, B. Preneel, "RIPEMD-160: A
 * Strengthened Version of RIPEMD" (1996). This is a from-scratch, self-contained
 * implementation following that specification; verified against the canonical
 * test vectors at build/test time.
 */
#include "ripemd160.h"
#include <string.h>

/* --- rotate left --- */
static inline uint32_t rol(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

/* Boolean functions f1..f5 */
#define F1(x, y, z) ((x) ^ (y) ^ (z))
#define F2(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define F3(x, y, z) (((x) | ~(y)) ^ (z))
#define F4(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define F5(x, y, z) ((x) ^ ((y) | ~(z)))

static void ripemd160_compress(uint32_t state[5], const uint8_t block[64]) {
    uint32_t X[16];
    for (int i = 0; i < 16; i++) {
        X[i] = (uint32_t)block[i * 4] |
               ((uint32_t)block[i * 4 + 1] << 8) |
               ((uint32_t)block[i * 4 + 2] << 16) |
               ((uint32_t)block[i * 4 + 3] << 24);
    }

    /* message word selection order */
    static const int rl[80] = {
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
        7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
        3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
        1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
        4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13
    };
    static const int rr[80] = {
        5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
        6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
        15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
        8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
        12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11
    };
    /* rotate amounts */
    static const int sl[80] = {
        11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
        7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
        11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
        11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
        9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6
    };
    static const int sr[80] = {
        8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
        9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
        9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
        15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
        8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11
    };
    /* added constants (left line) */
    static const uint32_t kl[5] = {
        0x00000000u, 0x5a827999u, 0x6ed9eba1u, 0x8f1bbcdcu, 0xa953fd4eu
    };
    /* added constants (right line) */
    static const uint32_t kr[5] = {
        0x50a28be6u, 0x5c4dd124u, 0x6d703ef3u, 0x7a6d76e9u, 0x00000000u
    };

    uint32_t al = state[0], bl = state[1], cl = state[2], dl = state[3], el = state[4];
    uint32_t ar = state[0], br = state[1], cr = state[2], dr = state[3], er = state[4];

    for (int j = 0; j < 80; j++) {
        int round = j / 16;
        uint32_t t;

        /* left line */
        uint32_t fl;
        switch (round) {
            case 0: fl = F1(bl, cl, dl); break;
            case 1: fl = F2(bl, cl, dl); break;
            case 2: fl = F3(bl, cl, dl); break;
            case 3: fl = F4(bl, cl, dl); break;
            default: fl = F5(bl, cl, dl); break;
        }
        t = rol(al + fl + X[rl[j]] + kl[round], sl[j]) + el;
        al = el; el = dl; dl = rol(cl, 10); cl = bl; bl = t;

        /* right line */
        uint32_t fr;
        switch (round) {
            case 0: fr = F5(br, cr, dr); break;
            case 1: fr = F4(br, cr, dr); break;
            case 2: fr = F3(br, cr, dr); break;
            case 3: fr = F2(br, cr, dr); break;
            default: fr = F1(br, cr, dr); break;
        }
        t = rol(ar + fr + X[rr[j]] + kr[round], sr[j]) + er;
        ar = er; er = dr; dr = rol(cr, 10); cr = br; br = t;
    }

    uint32_t tmp = state[1] + cl + dr;
    state[1] = state[2] + dl + er;
    state[2] = state[3] + el + ar;
    state[3] = state[4] + al + br;
    state[4] = state[0] + bl + cr;
    state[0] = tmp;
}

void ripemd160_init(ripemd160_ctx *ctx) {
    ctx->state[0] = 0x67452301u;
    ctx->state[1] = 0xefcdab89u;
    ctx->state[2] = 0x98badcfeu;
    ctx->state[3] = 0x10325476u;
    ctx->state[4] = 0xc3d2e1f0u;
    ctx->length = 0;
    ctx->buflen = 0;
}

void ripemd160_update(ripemd160_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->length += len;
    while (len > 0) {
        size_t take = RIPEMD160_BLOCK_LENGTH - ctx->buflen;
        if (take > len) take = len;
        memcpy(ctx->buffer + ctx->buflen, data, take);
        ctx->buflen += take;
        data += take;
        len -= take;
        if (ctx->buflen == RIPEMD160_BLOCK_LENGTH) {
            ripemd160_compress(ctx->state, ctx->buffer);
            ctx->buflen = 0;
        }
    }
}

void ripemd160_final(ripemd160_ctx *ctx, uint8_t out[RIPEMD160_DIGEST_LENGTH]) {
    uint64_t bitlen = ctx->length * 8;
    uint8_t pad = 0x80;
    ripemd160_update(ctx, &pad, 1);
    uint8_t zero = 0x00;
    while (ctx->buflen != 56) {
        ripemd160_update(ctx, &zero, 1);
    }
    uint8_t lenbytes[8];
    for (int i = 0; i < 8; i++) {
        lenbytes[i] = (uint8_t)(bitlen >> (8 * i));
    }
    ripemd160_update(ctx, lenbytes, 8);
    /* buffer is now flushed; emit state little-endian */
    for (int i = 0; i < 5; i++) {
        out[i * 4]     = (uint8_t)(ctx->state[i]);
        out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 8);
        out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4 + 3] = (uint8_t)(ctx->state[i] >> 24);
    }
}

void ripemd160(const uint8_t *data, size_t len, uint8_t out[RIPEMD160_DIGEST_LENGTH]) {
    ripemd160_ctx ctx;
    ripemd160_init(&ctx);
    ripemd160_update(&ctx, data, len);
    ripemd160_final(&ctx, out);
}
