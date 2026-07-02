/*
 * rabin.c — byte-exact port of `rabinsig` (scrypt-sv/rabin) + scrypt-ts-lib
 * RabinVerifier, SECURITY_LEVEL = 6.
 *
 * Faithful to chain/node_modules/rabinsig/dist/{rabin,utils}.js:
 *   bin2hash(b)      = SHA256(SHA256(b)[0:16]) || SHA256(SHA256(b)[16:32])  (64B)
 *   rabinHashBytes   = bin2hash(in); 5x: r ||= bin2hash(r); 384B; toBigIntLE
 *   root(data,p,q,n) = loop x = H(data) % n;
 *                      s = ( powerMod(p,q-2,q)*p*powerMod(x,(q+1)/4,q)
 *                          + powerMod(q,p-2,p)*q*powerMod(x,(p+1)/4,p) ) % n;
 *                      if s*s%n==x break; else append one 0x00 byte, pad++.
 *   verify(d,sig,n)  = append paddingByteCount 0x00 bytes; (H % n) == (s^2 % n).
 *   privKeyToPubKey  = p*q.
 *   generatePrivKey  = seed=randomBytes(2048);
 *                      p=getPrimeNumber(H(seed) % 2^1536);
 *                      q=getPrimeNumber(H(seed||00) % 2^1536).
 *
 * Pubkey wire = DECIMAL (bn_to_dec); signature s wire = LOWERCASE HEX no pad
 * (bn_to_hex) — handled by the bignum layer, not here.
 */
#include "crypto/rabin.h"
#include "crypto/bignum.h"
#include "crypto/hash.h"
#include "crypto/rand.h"
#include "common/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>   /* OPENSSL_cleanse for scrubbing secret seeds */

/* Constant-time modular exponentiation for SECRET exponents, defined in
 * bignum.c (deliberately not in the frozen crypto/bignum.h public header).
 * Used on the signing / key-gen square-root path so the secret exponent bits do
 * not leak via timing; the result is byte-identical to bn_mod_exp, so signature
 * and pubkey wire bytes are unchanged. */
int bn_mod_exp_secret(const bn_t *base, const bn_t *exp, const bn_t *m,
                      bn_t **out);

/* ---- small bn helpers --------------------------------------------------- */

/* Build a bn_t from a small unsigned long via decimal parse (no extra deps). */
static int bn_from_ul(unsigned long v, bn_t **out) {
    char buf[32];
    snprintf(buf, sizeof buf, "%lu", v);
    return bn_parse_dec(buf, out);
}

/* *out = a / d for a small divisor `d` (the bignum.h contract has no division).
 * Big-endian long division: works for any non-negative `a`. Used here only for
 * (p+1)/4 and (q+1)/4, which are exact since p,q ≡ 3 (mod 4). */
static int bn_div_small(const bn_t *a, unsigned int d, bn_t **out) {
    byte_buf_t be;
    byte_buf_init(&be);
    int rc;
    if ((rc = bn_to_be_bytes(a, &be)) != BNS_OK) { byte_buf_free(&be); return rc; }

    /* In-place long division of the big-endian byte string by d. */
    unsigned int rem = 0;
    for (size_t i = 0; i < be.len; i++) {
        unsigned int cur = (rem << 8) | be.data[i];
        be.data[i] = (uint8_t)(cur / d);
        rem = cur % d;
    }
    /* Interpret the quotient bytes as a big-endian integer (leading zeros ok). */
    rc = bn_parse_be(be.len ? be.data : (const uint8_t *)"", be.len, out);
    byte_buf_free(&be);
    return rc;
}

/* ---- bin2hash / rabinHashBytes ------------------------------------------ */

/* bin2hash: append the 64-byte doubled hash of (data[0..len)) to `out`.
 *   h  = SHA256(data)            (32 bytes)
 *   hl = SHA256(h[0:16])         (32 bytes)
 *   hr = SHA256(h[16:32])        (32 bytes)
 *   result = hl || hr            (64 bytes)
 * Split index is 16 (BONSAI_RABIN_BIN2HASH_SPLIT), half of the 32-byte digest. */
static int rabin_bin2hash(const uint8_t *data, size_t len, byte_buf_t *out) {
    uint8_t h[BONSAI_SHA256_LEN];
    uint8_t hl[BONSAI_SHA256_LEN];
    uint8_t hr[BONSAI_SHA256_LEN];
    int rc;

    sha256(data, len, h);
    sha256(h, BONSAI_RABIN_BIN2HASH_SPLIT, hl);
    sha256(h + BONSAI_RABIN_BIN2HASH_SPLIT,
           BONSAI_SHA256_LEN - BONSAI_RABIN_BIN2HASH_SPLIT, hr);

    if ((rc = byte_buf_append(out, hl, sizeof hl)) != BNS_OK) return rc;
    if ((rc = byte_buf_append(out, hr, sizeof hr)) != BNS_OK) return rc;
    return BNS_OK;
}

int rabin_hash(const uint8_t *data, size_t len, bn_t **out) {
    if (!out) return BNS_EINVAL;
    *out = NULL;

    byte_buf_t acc;
    byte_buf_init(&acc);
    int rc;

    /* result = bin2hash(data) */
    if ((rc = rabin_bin2hash(data, len, &acc)) != BNS_OK) goto done;

    /* repeat (SECURITY_LEVEL - 1) times: result ||= bin2hash(result) */
    for (int i = 0; i < BONSAI_RABIN_SECURITY_LEVEL - 1; i++) {
        /* bin2hash reads the CURRENT accumulated result, then appends to it.
         * Snapshot the current bytes first (acc grows during append). */
        size_t cur_len = acc.len;
        uint8_t *snapshot = malloc(cur_len ? cur_len : 1);
        if (!snapshot) { rc = BNS_ENOMEM; goto done; }
        memcpy(snapshot, acc.data, cur_len);
        rc = rabin_bin2hash(snapshot, cur_len, &acc);
        free(snapshot);
        if (rc != BNS_OK) goto done;
    }

    /* toBigIntLE over the full (64 * SECURITY_LEVEL = 384) byte buffer. */
    rc = bn_parse_le(acc.data, acc.len, out);

done:
    byte_buf_free(&acc);
    return rc;
}

/* ---- lifecycle ---------------------------------------------------------- */

void rabin_key_free(rabin_key_t *key) {
    if (!key) return;
    /* p and q are the SECRET Rabin primes — scrub on release. */
    bn_clear_free(key->p);
    bn_clear_free(key->q);
    key->p = NULL;
    key->q = NULL;
}

void rabin_sig_free(rabin_sig_t *sig) {
    if (!sig) return;
    bn_free(sig->s);
    sig->s = NULL;
}

/* ---- keygen (non-deterministic) ----------------------------------------- */

/* greatestCommonDivisor wrapper using OpenSSL via the bn layer is not exposed;
 * implement the rabinsig Euclid loop on bn_t directly (used by keygen only). */
static int bn_gcd_euclid(const bn_t *a_in, const bn_t *b_in, bn_t **out) {
    /* a,b are non-negative here (hashes / small product). */
    bn_t *a = NULL, *b = NULL;
    int rc;
    if ((rc = bn_dup(a_in, &a)) != BNS_OK) return rc;
    if ((rc = bn_dup(b_in, &b)) != BNS_OK) { bn_free(a); return rc; }

    /* if (b > a) swap */
    if (bn_cmp(b, a) > 0) { bn_t *t = a; a = b; b = t; }

    while (!bn_is_zero(b)) {
        bn_t *r = NULL;
        if ((rc = bn_mod(a, b, &r)) != BNS_OK) { bn_free(a); bn_free(b); return rc; }
        bn_free(a);
        a = b;
        b = r;
    }
    *out = a;
    bn_free(b);
    return BNS_OK;
}

/* calculateNextPrime, recursive in JS; implemented as a loop in C. */
static int rabin_calc_next_prime(bn_t **pp) {
    /* smallPrimesProduct = 3*5*7*11*13*17*19*23*29 = 3234846615 */
    bn_t *spp = NULL, *four = NULL, *one = NULL;
    bn_t *e2 = NULL, *e3 = NULL, *e5 = NULL, *e17 = NULL;
    int rc;

    if ((rc = bn_from_ul(3234846615UL, &spp)) != BNS_OK) return rc;
    if ((rc = bn_from_ul(4, &four)) != BNS_OK) { bn_free(spp); return rc; }
    if ((rc = bn_from_ul(1, &one)) != BNS_OK) { bn_free(spp); bn_free(four); return rc; }
    if ((rc = bn_from_ul(2, &e2)) != BNS_OK) goto err_consts;
    if ((rc = bn_from_ul(3, &e3)) != BNS_OK) { bn_free(e2); goto err_consts; }
    if ((rc = bn_from_ul(5, &e5)) != BNS_OK) { bn_free(e2); bn_free(e3); goto err_consts; }
    if ((rc = bn_from_ul(17, &e17)) != BNS_OK) { bn_free(e2); bn_free(e3); bn_free(e5); goto err_consts; }

    for (;;) {
        bn_t *p = *pp;

        /* while gcd(p, smallPrimesProduct) != 1: p += 4 */
        for (;;) {
            bn_t *g = NULL;
            if ((rc = bn_gcd_euclid(p, spp, &g)) != BNS_OK) goto err_all;
            int isone = (bn_cmp(g, one) == 0);
            bn_free(g);
            if (isone) break;
            bn_t *np = NULL;
            if ((rc = bn_add(p, four, &np)) != BNS_OK) goto err_all;
            bn_free(p);
            p = np;
            *pp = p;
        }

        /* Fermat tests bases 2,3,5,17: a^(p-1) mod p must be 1 for each. */
        bn_t *pm1 = NULL;
        if ((rc = bn_sub(p, one, &pm1)) != BNS_OK) goto err_all;

        const bn_t *bases[4] = { e2, e3, e5, e17 };
        int fail = 0;
        for (int i = 0; i < 4; i++) {
            bn_t *r = NULL;
            /* Exponent pm1 = p-1 reveals the secret candidate prime p; use the
             * constant-time path (byte-identical result). */
            if ((rc = bn_mod_exp_secret(bases[i], pm1, p, &r)) != BNS_OK) {
                bn_free(pm1); goto err_all;
            }
            int eqone = (bn_cmp(r, one) == 0);
            bn_free(r);
            if (!eqone) { fail = 1; break; }
        }
        bn_free(pm1);

        if (!fail) {
            /* p is the next prime. */
            rc = BNS_OK;
            break;
        }

        /* recurse calculateNextPrime(p + 4) -> loop with p += 4 */
        bn_t *np = NULL;
        if ((rc = bn_add(p, four, &np)) != BNS_OK) goto err_all;
        bn_free(p);
        *pp = np;
    }

    bn_free(spp); bn_free(four); bn_free(one);
    bn_free(e2); bn_free(e3); bn_free(e5); bn_free(e17);
    return rc;

err_all:
    bn_free(e2); bn_free(e3); bn_free(e5); bn_free(e17);
err_consts:
    bn_free(spp); bn_free(four); bn_free(one);
    return rc;
}

/* getPrimeNumber(p): while p%4 != 3: p++; then calculateNextPrime(p).
 * Consumes *pp (replaces it with the prime). */
static int rabin_get_prime_number(bn_t **pp) {
    bn_t *four = NULL, *three = NULL, *one = NULL;
    int rc;
    if ((rc = bn_from_ul(4, &four)) != BNS_OK) return rc;
    if ((rc = bn_from_ul(3, &three)) != BNS_OK) { bn_free(four); return rc; }
    if ((rc = bn_from_ul(1, &one)) != BNS_OK) { bn_free(four); bn_free(three); return rc; }

    for (;;) {
        bn_t *r = NULL;
        if ((rc = bn_mod(*pp, four, &r)) != BNS_OK) goto done;
        int eq3 = (bn_cmp(r, three) == 0);
        bn_free(r);
        if (eq3) break;
        bn_t *np = NULL;
        if ((rc = bn_add(*pp, one, &np)) != BNS_OK) goto done;
        bn_free(*pp);
        *pp = np;
    }
    rc = rabin_calc_next_prime(pp);

done:
    bn_free(four); bn_free(three); bn_free(one);
    return rc;
}

/* range = 2^(256*SECURITY_LEVEL) = 2^1536. Returns a fresh bn_t. */
static int rabin_range(bn_t **out) {
    /* 2^1536 = 1 followed by 1536 zero bits = a 193-byte big-endian value:
     * byte 0 = 0x01, then 192 zero bytes. */
    uint8_t be[193];
    memset(be, 0, sizeof be);
    be[0] = 0x01;
    return bn_parse_be(be, sizeof be, out);
}

/* generatePrivKeyFromSeed(seed): the deterministic core of keygen. */
static int rabin_keygen_from_seed(const uint8_t *seed, size_t seed_len,
                                  rabin_key_t *out) {
    bn_t *range = NULL, *hp = NULL, *hq = NULL;
    bn_t *p = NULL, *q = NULL;
    uint8_t *seed0 = NULL;
    int rc;

    if ((rc = rabin_range(&range)) != BNS_OK) return rc;

    /* p = getPrimeNumber(rabinHashBytes(seed) % range) */
    if ((rc = rabin_hash(seed, seed_len, &hp)) != BNS_OK) goto done;
    if ((rc = bn_mod(hp, range, &p)) != BNS_OK) goto done;
    if ((rc = rabin_get_prime_number(&p)) != BNS_OK) goto done;

    /* q = getPrimeNumber(rabinHashBytes(seed || 0x00) % range) */
    seed0 = malloc(seed_len + 1);
    if (!seed0) { rc = BNS_ENOMEM; goto done; }
    memcpy(seed0, seed, seed_len);
    seed0[seed_len] = 0x00;
    if ((rc = rabin_hash(seed0, seed_len + 1, &hq)) != BNS_OK) goto done;
    if ((rc = bn_mod(hq, range, &q)) != BNS_OK) goto done;
    if ((rc = rabin_get_prime_number(&q)) != BNS_OK) goto done;

    out->p = p; p = NULL;
    out->q = q; q = NULL;
    rc = BNS_OK;

done:
    /* seed0 = seed || 0x00 is SECRET key-derivation input — scrub before free.
     * hp/hq (hashes of the seed) and any not-yet-handed-off p/q are likewise
     * secret-derived; release them with the zeroizing free. range (2^1536) is
     * a public constant. */
    if (seed0) OPENSSL_cleanse(seed0, seed_len + 1);
    free(seed0);
    bn_free(range);
    bn_clear_free(hp);
    bn_clear_free(hq);
    bn_clear_free(p);
    bn_clear_free(q);
    return rc;
}

int rabin_keygen(rabin_key_t *out) {
    if (!out) return BNS_EINVAL;
    out->p = NULL;
    out->q = NULL;

    uint8_t seed[2048];
    int rc = rand_bytes_secure(seed, sizeof seed);   /* long-term Rabin key: bypass the test RNG override (review-2 #7) */
    if (rc != BNS_OK) return BNS_ECRYPTO;

    rc = rabin_keygen_from_seed(seed, sizeof seed, out);
    /* seed is SECRET key material — scrub it off the stack before returning. */
    OPENSSL_cleanse(seed, sizeof seed);
    if (rc != BNS_OK && rc != BNS_ENOMEM) rc = BNS_ECRYPTO;
    return rc;
}

int rabin_pubkey(const rabin_key_t *key, bn_t **out) {
    if (!key || !key->p || !key->q || !out) return BNS_EINVAL;
    return bn_mul(key->p, key->q, out);
}

/* ---- sign --------------------------------------------------------------- */

/* One CRT square-root attempt: given x (already reduced mod n), p, q, n,
 * compute s = ( powerMod(q,p-2,p)*q*powerMod(x,(p+1)/4,p)
 *             + powerMod(p,q-2,q)*p*powerMod(x,(q+1)/4,q) ) % n.
 * Note rabinsig computes the q-term first then the p-term; addition is
 * commutative so the assembled value is identical. */
static int rabin_crt_root(const bn_t *x, const bn_t *p, const bn_t *q,
                          const bn_t *n, bn_t **out_s) {
    bn_t *one = NULL, *two = NULL, *four = NULL;
    bn_t *pm2 = NULL, *qm2 = NULL, *pp1 = NULL, *qp1 = NULL;
    bn_t *exp_p = NULL, *exp_q = NULL;
    bn_t *inv_q_p = NULL, *inv_p_q = NULL;
    bn_t *xsp = NULL, *xsq = NULL;
    bn_t *tp = NULL, *tq = NULL;
    bn_t *termp = NULL, *termq = NULL, *sum = NULL, *s = NULL;
    int rc;

    if ((rc = bn_from_ul(1, &one)) != BNS_OK) return rc;
    if ((rc = bn_from_ul(2, &two)) != BNS_OK) goto done;
    if ((rc = bn_from_ul(4, &four)) != BNS_OK) goto done;

    /* exponents */
    if ((rc = bn_sub(p, two, &pm2)) != BNS_OK) goto done;     /* p-2 */
    if ((rc = bn_sub(q, two, &qm2)) != BNS_OK) goto done;     /* q-2 */
    if ((rc = bn_add(p, one, &pp1)) != BNS_OK) goto done;     /* p+1 (then /4) */
    if ((rc = bn_add(q, one, &qp1)) != BNS_OK) goto done;     /* q+1 (then /4) */

    /* (p+1)/4 and (q+1)/4: exact since p,q ≡ 3 (mod 4) (Blum integers). */
    if ((rc = bn_div_small(pp1, 4, &exp_p)) != BNS_OK) goto done; /* (p+1)/4 */
    if ((rc = bn_div_small(qp1, 4, &exp_q)) != BNS_OK) goto done; /* (q+1)/4 */

    /* inv_q_p = powerMod(q, p-2, p)  (== q^{-1} mod p by Fermat)
     * inv_p_q = powerMod(p, q-2, q)  (== p^{-1} mod q)
     * Exponents p-2, q-2 are SECRET; const-time path (byte-identical result). */
    if ((rc = bn_mod_exp_secret(q, pm2, p, &inv_q_p)) != BNS_OK) goto done;
    if ((rc = bn_mod_exp_secret(p, qm2, q, &inv_p_q)) != BNS_OK) goto done;

    /* x^{(p+1)/4} mod p, x^{(q+1)/4} mod q — exponents (p+1)/4, (q+1)/4 are
     * SECRET; const-time path (byte-identical result). */
    if ((rc = bn_mod_exp_secret(x, exp_p, p, &xsp)) != BNS_OK) goto done;
    if ((rc = bn_mod_exp_secret(x, exp_q, q, &xsq)) != BNS_OK) goto done;

    /* termp = inv_q_p * q * xsp   (full-precision multiply, no mod — match JS) */
    if ((rc = bn_mul(inv_q_p, q, &tp)) != BNS_OK) goto done;
    if ((rc = bn_mul(tp, xsp, &termp)) != BNS_OK) goto done;

    /* termq = inv_p_q * p * xsq */
    if ((rc = bn_mul(inv_p_q, p, &tq)) != BNS_OK) goto done;
    if ((rc = bn_mul(tq, xsq, &termq)) != BNS_OK) goto done;

    /* s = (termp + termq) % n */
    if ((rc = bn_add(termp, termq, &sum)) != BNS_OK) goto done;
    if ((rc = bn_mod(sum, n, &s)) != BNS_OK) goto done;

    *out_s = s; s = NULL;
    rc = BNS_OK;

done:
    /* one/two/four are public constants. Everything else is derived from the
     * SECRET primes p, q (p±, (p+1)/4, the modular inverses) or is a CRT
     * square-root intermediate — scrub these on release. */
    bn_free(one); bn_free(two); bn_free(four);
    bn_clear_free(pm2); bn_clear_free(qm2); bn_clear_free(pp1); bn_clear_free(qp1);
    bn_clear_free(exp_p); bn_clear_free(exp_q);
    bn_clear_free(inv_q_p); bn_clear_free(inv_p_q);
    bn_clear_free(xsp); bn_clear_free(xsq);
    bn_clear_free(tp); bn_clear_free(tq);
    bn_clear_free(termp); bn_clear_free(termq); bn_clear_free(sum); bn_clear_free(s);
    return rc;
}

int rabin_sign(const uint8_t *msg, size_t msg_len,
               const rabin_key_t *key, rabin_sig_t *out_sig) {
    if (!key || !key->p || !key->q || !out_sig) return BNS_EINVAL;
    out_sig->s = NULL;
    out_sig->padding_byte_count = 0;

    bn_t *n = NULL;
    byte_buf_t data;
    byte_buf_init(&data);
    int rc;

    if ((rc = bn_mul(key->p, key->q, &n)) != BNS_OK) goto done;
    if ((rc = byte_buf_append(&data, msg, msg_len)) != BNS_OK) goto done;

    size_t padding = 0;
    for (;;) {
        /* x = rabinHashBytes(data) % n */
        bn_t *h = NULL, *x = NULL, *s = NULL, *s2 = NULL;
        if ((rc = rabin_hash(data.data, data.len, &h)) != BNS_OK) goto done;
        rc = bn_mod(h, n, &x);
        bn_free(h);
        if (rc != BNS_OK) goto done;

        rc = rabin_crt_root(x, key->p, key->q, n, &s);
        if (rc != BNS_OK) { bn_free(x); goto done; }

        /* if (s*s % n) == x: accept */
        rc = bn_mod_sqr(s, n, &s2);
        if (rc != BNS_OK) { bn_free(x); bn_free(s); goto done; }

        int match = (bn_cmp(s2, x) == 0);
        bn_free(x);
        bn_free(s2);

        if (match) {
            out_sig->s = s;
            out_sig->padding_byte_count = padding;
            rc = BNS_OK;
            goto done;
        }
        bn_free(s);

        /* not a QR for this branch: append one 0x00 pad byte and retry. */
        if ((rc = byte_buf_append_byte(&data, 0x00)) != BNS_OK) goto done;
        padding++;
    }

done:
    byte_buf_free(&data);
    bn_free(n);
    if (rc != BNS_OK && rc != BNS_ENOMEM && rc != BNS_EINVAL) rc = BNS_ECRYPTO;
    return rc;
}

/* ---- verify ------------------------------------------------------------- */

bool rabin_verify(const uint8_t *msg, size_t msg_len,
                  const rabin_sig_t *sig, const bn_t *n) {
    if (!sig || !sig->s || !n) return false;
    /* Defensive bound at the single choke point: reject an absurd padding count
     * before it can grow `data` by that many bytes (memory-exhaustion DoS). */
    if (sig->padding_byte_count > RABIN_MAX_PADDING_BYTES) return false;

    byte_buf_t data;
    byte_buf_init(&data);
    bn_t *h = NULL, *hmod = NULL, *s2 = NULL;
    bool ok = false;

    if (byte_buf_append(&data, msg, msg_len) != BNS_OK) goto done;
    for (size_t i = 0; i < sig->padding_byte_count; i++) {
        if (byte_buf_append_byte(&data, 0x00) != BNS_OK) goto done;
    }

    if (rabin_hash(data.data, data.len, &h) != BNS_OK) goto done;
    if (bn_mod(h, n, &hmod) != BNS_OK) goto done;
    if (bn_mod_sqr(sig->s, n, &s2) != BNS_OK) goto done;

    ok = (bn_cmp(hmod, s2) == 0);

done:
    byte_buf_free(&data);
    bn_free(h);
    bn_free(hmod);
    bn_free(s2);
    return ok;
}
