/*
 * bignum.c — opaque arbitrary-precision integer (bn_t) over OpenSSL BIGNUM.
 *
 * Implements include/crypto/bignum.h. Faithful to TS semantics:
 *   - bn_to_dec  : BN_bn2dec (RabinPubKey canonical DECIMAL wire form).
 *   - bn_to_hex  : JS BigInt.toString(16) — lowercase, no leading zeros, no
 *                  "0x", leading '-' for negatives, "0" for zero. (OpenSSL
 *                  BN_bn2hex uppercases + zero-pads to even nibble width, so we
 *                  post-process.)
 *   - bn_parse_le / bn_to_le_bytes : little-endian (Rabin rabinHashBytes, num2bin
 *                  fixed-width LE substrate). Unsigned.
 *   - bn_parse_be / bn_to_be_bytes : big-endian (BN.fromBuffer / toBuffer).
 *   - bn_mod*    : non-negative modular results via BN_mod_* (Rabin verify, zk).
 *
 * A fresh BN_CTX is created per fallible operation that needs scratch space and
 * freed before return. This keeps the type free of shared mutable state (safe
 * across threads) at a small allocation cost; results are fully deterministic.
 */
#include "crypto/bignum.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>

struct bn_s {
    BIGNUM *bn;
};

/* ---- internal helpers --------------------------------------------------- */

/* Allocate a bn_t whose BIGNUM is freshly created (zero). NULL on OOM. */
static bn_t *bn_alloc(void)
{
    bn_t *r = (bn_t *)malloc(sizeof(*r));
    if (!r) return NULL;
    r->bn = BN_new();
    if (!r->bn) {
        free(r);
        return NULL;
    }
    BN_zero(r->bn);
    return r;
}

/* ---- lifecycle ---------------------------------------------------------- */

bn_t *bn_new(void)
{
    return bn_alloc();
}

void bn_free(bn_t *bn)
{
    if (!bn) return;
    if (bn->bn) BN_free(bn->bn);
    free(bn);
}

/* Like bn_free but scrubs the BIGNUM's contents (BN_clear_free) before release.
 * For SECRET values — Rabin primes p/q and the CRT square-root intermediates —
 * so cleartext key material is not left lingering in freed heap. NULL-safe. */
void bn_clear_free(bn_t *bn)
{
    if (!bn) return;
    if (bn->bn) BN_clear_free(bn->bn);
    free(bn);
}

int bn_dup(const bn_t *src, bn_t **out)
{
    if (!src || !out) return BNS_EINVAL;
    bn_t *r = (bn_t *)malloc(sizeof(*r));
    if (!r) return BNS_ENOMEM;
    r->bn = BN_dup(src->bn);
    if (!r->bn) {
        free(r);
        return BNS_ENOMEM;
    }
    *out = r;
    return BNS_OK;
}

/* ---- parse (string / bytes -> bn) --------------------------------------- */

int bn_parse_dec(const char *dec, bn_t **out)
{
    if (!dec || !out) return BNS_EINVAL;
    bn_t *r = bn_alloc();
    if (!r) return BNS_ENOMEM;
    /* BN_dec2bn returns the number of chars consumed; must consume the whole
     * string (and at least one char) for a clean parse. Accepts leading '-'. */
    int used = BN_dec2bn(&r->bn, dec);
    if (used == 0 || dec[used] != '\0' || used != (int)strlen(dec)) {
        bn_free(r);
        return BNS_EPARSE;
    }
    *out = r;
    return BNS_OK;
}

int bn_parse_hex(const char *hex, bn_t **out)
{
    if (!hex || !out) return BNS_EINVAL;

    /* Permit optional sign and optional "0x"/"0X" prefix (TS BigInt("0x..")). */
    const char *p = hex;
    int negative = 0;
    if (*p == '-') { negative = 1; p++; }
    else if (*p == '+') { p++; }
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;

    if (*p == '\0') { return BNS_EPARSE; }

    bn_t *r = bn_alloc();
    if (!r) return BNS_ENOMEM;

    int used = BN_hex2bn(&r->bn, p);
    if (used == 0 || p[used] != '\0' || used != (int)strlen(p)) {
        bn_free(r);
        return BNS_EPARSE;
    }
    if (negative) BN_set_negative(r->bn, 1);
    *out = r;
    return BNS_OK;
}

int bn_parse_le(const uint8_t *data, size_t len, bn_t **out)
{
    if (!out || (len && !data)) return BNS_EINVAL;
    bn_t *r = (bn_t *)malloc(sizeof(*r));
    if (!r) return BNS_ENOMEM;
    r->bn = BN_lebin2bn(data, (int)len, NULL);
    if (!r->bn) {
        free(r);
        return BNS_ENOMEM;
    }
    *out = r;
    return BNS_OK;
}

int bn_parse_be(const uint8_t *data, size_t len, bn_t **out)
{
    if (!out || (len && !data)) return BNS_EINVAL;
    bn_t *r = (bn_t *)malloc(sizeof(*r));
    if (!r) return BNS_ENOMEM;
    r->bn = BN_bin2bn(data, (int)len, NULL);
    if (!r->bn) {
        free(r);
        return BNS_ENOMEM;
    }
    *out = r;
    return BNS_OK;
}

/* ---- serialize (bn -> string / bytes) ----------------------------------- */

int bn_to_dec(const bn_t *bn, char **out)
{
    if (!bn || !out) return BNS_EINVAL;
    char *s = BN_bn2dec(bn->bn);   /* OpenSSL-allocated */
    if (!s) return BNS_ENOMEM;
    /* Hand back a malloc'd copy so the caller frees with free() consistently. */
    char *copy = strdup(s);
    OPENSSL_free(s);
    if (!copy) return BNS_ENOMEM;
    *out = copy;
    return BNS_OK;
}

int bn_to_hex(const bn_t *bn, char **out)
{
    if (!bn || !out) return BNS_EINVAL;

    char *s = BN_bn2hex(bn->bn);   /* UPPERCASE, zero-padded to even nibbles */
    if (!s) return BNS_ENOMEM;

    const char *p = s;
    int negative = 0;
    if (*p == '-') { negative = 1; p++; }

    /* Strip leading zeros (BN_bn2hex pads). Keep one digit if value is zero. */
    while (p[0] == '0' && p[1] != '\0') p++;

    size_t digits = strlen(p);
    /* zero stays "0", and a zero value is never negative -> drop sign. */
    if (digits == 1 && p[0] == '0') negative = 0;

    char *res = (char *)malloc((negative ? 1 : 0) + digits + 1);
    if (!res) { OPENSSL_free(s); return BNS_ENOMEM; }

    char *w = res;
    if (negative) *w++ = '-';
    for (size_t i = 0; i < digits; i++) {
        char c = p[i];
        if (c >= 'A' && c <= 'F') c = (char)(c - 'A' + 'a');
        *w++ = c;
    }
    *w = '\0';

    OPENSSL_free(s);
    *out = res;
    return BNS_OK;
}

int bn_to_le_bytes(const bn_t *bn, size_t width, byte_buf_t *out)
{
    if (!bn || !out) return BNS_EINVAL;
    /* Width refers to the unsigned magnitude; negatives are unsupported here
     * (this is the fixed-width LE substrate for unsigned values). */
    if (BN_is_negative(bn->bn)) return BNS_ERANGE;

    int need = BN_num_bytes(bn->bn);
    if (need > (int)width) return BNS_ERANGE;

    uint8_t *tmp = (uint8_t *)malloc(width ? width : 1);
    if (!tmp) return BNS_ENOMEM;

    if (BN_bn2lebinpad(bn->bn, tmp, (int)width) < 0) {
        free(tmp);
        return BNS_ERANGE;
    }
    int rc = byte_buf_append(out, tmp, width);
    free(tmp);
    return rc; /* BNS_OK / BNS_ENOMEM */
}

int bn_to_be_bytes(const bn_t *bn, byte_buf_t *out)
{
    if (!bn || !out) return BNS_EINVAL;
    /* BN_num_bytes/BN_bn2bin use the magnitude only; a negative bn would be silently
     * encoded as its absolute value, violating the documented "unsigned BIG-ENDIAN"
     * contract. Reject it, matching bn_to_le_bytes. */
    if (BN_is_negative(bn->bn)) return BNS_ERANGE;

    int n = BN_num_bytes(bn->bn);
    if (n == 0) return BNS_OK; /* minimal-width BE of 0 is empty */

    uint8_t *tmp = (uint8_t *)malloc((size_t)n);
    if (!tmp) return BNS_ENOMEM;

    int wrote = BN_bn2bin(bn->bn, tmp);
    if (wrote < 0) {
        free(tmp);
        return BNS_ENOMEM;
    }
    int rc = byte_buf_append(out, tmp, (size_t)wrote);
    free(tmp);
    return rc;
}

/* ---- modular arithmetic ------------------------------------------------- */

int bn_mod(const bn_t *a, const bn_t *m, bn_t **out)
{
    if (!a || !m || !out) return BNS_EINVAL;
    if (BN_is_zero(m->bn)) return BNS_EINVAL;

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return BNS_ENOMEM;
    bn_t *r = bn_alloc();
    if (!r) { BN_CTX_free(ctx); return BNS_ENOMEM; }

    /* BN_nnmod yields a non-negative residue (TS Euclidean %, matched). */
    int ok = BN_nnmod(r->bn, a->bn, m->bn, ctx);
    BN_CTX_free(ctx);
    if (!ok) { bn_free(r); return BNS_ENOMEM; }
    *out = r;
    return BNS_OK;
}

int bn_mod_mul(const bn_t *a, const bn_t *b, const bn_t *m, bn_t **out)
{
    if (!a || !b || !m || !out) return BNS_EINVAL;
    if (BN_is_zero(m->bn)) return BNS_EINVAL;

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return BNS_ENOMEM;
    bn_t *r = bn_alloc();
    if (!r) { BN_CTX_free(ctx); return BNS_ENOMEM; }

    int ok = BN_mod_mul(r->bn, a->bn, b->bn, m->bn, ctx);
    BN_CTX_free(ctx);
    if (!ok) { bn_free(r); return BNS_ENOMEM; }
    *out = r;
    return BNS_OK;
}

int bn_mod_sqr(const bn_t *a, const bn_t *m, bn_t **out)
{
    if (!a || !m || !out) return BNS_EINVAL;
    if (BN_is_zero(m->bn)) return BNS_EINVAL;

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return BNS_ENOMEM;
    bn_t *r = bn_alloc();
    if (!r) { BN_CTX_free(ctx); return BNS_ENOMEM; }

    int ok = BN_mod_sqr(r->bn, a->bn, m->bn, ctx);
    BN_CTX_free(ctx);
    if (!ok) { bn_free(r); return BNS_ENOMEM; }
    *out = r;
    return BNS_OK;
}

int bn_mod_exp(const bn_t *base, const bn_t *exp, const bn_t *m, bn_t **out)
{
    if (!base || !exp || !m || !out) return BNS_EINVAL;
    if (BN_is_zero(m->bn)) return BNS_EINVAL;

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return BNS_ENOMEM;
    bn_t *r = bn_alloc();
    if (!r) { BN_CTX_free(ctx); return BNS_ENOMEM; }

    int ok = BN_mod_exp(r->bn, base->bn, exp->bn, m->bn, ctx);
    BN_CTX_free(ctx);
    if (!ok) { bn_free(r); return BNS_ENOMEM; }
    *out = r;
    return BNS_OK;
}

/* Constant-time variant of bn_mod_exp for SECRET exponents (Rabin signing /
 * key-gen square-root path: p-2, q-2, (p+1)/4, (q+1)/4, and the Fermat p-1).
 * Setting BN_FLG_CONSTTIME on the exponent makes OpenSSL dispatch to
 * BN_mod_exp_mont_consttime (Rabin moduli p, q are odd primes), removing the
 * exponent-dependent timing side channel. The mathematical result is identical
 * to BN_mod_exp, so on-chain output bytes are unchanged; only timing differs.
 * Public verification never calls this (it uses bn_mod_sqr). Declared, not in
 * the frozen bignum.h header, and reached by an explicit forward declaration in
 * the Rabin secret-key path. */
int bn_mod_exp_secret(const bn_t *base, const bn_t *exp, const bn_t *m,
                      bn_t **out);

int bn_mod_exp_secret(const bn_t *base, const bn_t *exp, const bn_t *m,
                      bn_t **out)
{
    if (!base || !exp || !m || !out) return BNS_EINVAL;
    if (BN_is_zero(m->bn)) return BNS_EINVAL;

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return BNS_ENOMEM;
    bn_t *r = bn_alloc();
    if (!r) { BN_CTX_free(ctx); return BNS_ENOMEM; }

    /* Flag a private copy of the exponent so the caller's bn_t is untouched and
     * the const-time scope is confined to this operation; scrub it on free. */
    BIGNUM *e = BN_dup(exp->bn);
    if (!e) { bn_free(r); BN_CTX_free(ctx); return BNS_ENOMEM; }
    BN_set_flags(e, BN_FLG_CONSTTIME);

    int ok = BN_mod_exp(r->bn, base->bn, e, m->bn, ctx);
    BN_clear_free(e);
    BN_CTX_free(ctx);
    if (!ok) { bn_free(r); return BNS_ENOMEM; }
    *out = r;
    return BNS_OK;
}

int bn_mod_inverse(const bn_t *a, const bn_t *m, bn_t **out)
{
    if (!a || !m || !out) return BNS_EINVAL;
    if (BN_is_zero(m->bn)) return BNS_EINVAL;

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return BNS_ENOMEM;
    bn_t *r = bn_alloc();
    if (!r) { BN_CTX_free(ctx); return BNS_ENOMEM; }

    /* Returns NULL when no inverse exists (a, m not coprime). */
    BIGNUM *res = BN_mod_inverse(r->bn, a->bn, m->bn, ctx);
    BN_CTX_free(ctx);
    if (!res) { bn_free(r); return BNS_EINVAL; }
    *out = r;
    return BNS_OK;
}

/* ---- plain arithmetic --------------------------------------------------- */

int bn_add(const bn_t *a, const bn_t *b, bn_t **out)
{
    if (!a || !b || !out) return BNS_EINVAL;
    bn_t *r = bn_alloc();
    if (!r) return BNS_ENOMEM;
    if (!BN_add(r->bn, a->bn, b->bn)) { bn_free(r); return BNS_ENOMEM; }
    *out = r;
    return BNS_OK;
}

int bn_sub(const bn_t *a, const bn_t *b, bn_t **out)
{
    if (!a || !b || !out) return BNS_EINVAL;
    bn_t *r = bn_alloc();
    if (!r) return BNS_ENOMEM;
    if (!BN_sub(r->bn, a->bn, b->bn)) { bn_free(r); return BNS_ENOMEM; }
    *out = r;
    return BNS_OK;
}

int bn_mul(const bn_t *a, const bn_t *b, bn_t **out)
{
    if (!a || !b || !out) return BNS_EINVAL;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return BNS_ENOMEM;
    bn_t *r = bn_alloc();
    if (!r) { BN_CTX_free(ctx); return BNS_ENOMEM; }
    int ok = BN_mul(r->bn, a->bn, b->bn, ctx);
    BN_CTX_free(ctx);
    if (!ok) { bn_free(r); return BNS_ENOMEM; }
    *out = r;
    return BNS_OK;
}

/* ---- comparison / predicates -------------------------------------------- */

int bn_cmp(const bn_t *a, const bn_t *b)
{
    /* NULL guard (siblings reject NULL handles). Order a missing handle as
     * less-than a present one and equal only if both are missing — never
     * spuriously report equality between NULL and a real value, which would
     * weaken the == comparisons callers rely on. */
    if (!a || !b) return (a == b) ? 0 : (a ? 1 : -1);
    return BN_cmp(a->bn, b->bn);
}

bool bn_is_zero(const bn_t *bn)
{
    if (!bn) return false; /* NULL guard, consistent with the other bn fns */
    return BN_is_zero(bn->bn) ? true : false;
}
