/*
 * num2bin.c — the TWO scrypt-ts integer->bytes encoders.
 *
 *   int2bytestring_sized(n, width)  : num2bin two-arg. Fixed-width LE,
 *       sign-magnitude with the sign BIT in the top byte. BNS_ERANGE if the
 *       value (incl. the reserved sign bit) does not fit in `width` bytes.
 *
 *   int2bytestring_minimal(n)       : num2bin one-arg / BN.toSM. Minimal-width
 *       sign-magnitude LE; appends a 0x00 (positive) / 0x80 (negative) sign
 *       byte only when the top magnitude byte's high bit is set, otherwise ORs
 *       the sign into that top byte. Zero -> empty.
 *
 * Sign/magnitude are derived through the frozen bignum.h API (which exposes no
 * sign accessor): compare against a zero handle, and obtain |n| via 0 - n.
 *
 * TS origin: scrypt-ts int2ByteString (both arities), bsv BN.toSM / num2bin.
 */
#include "bsv/num2bin.h"

#include "crypto/bignum.h"

/* Compute sign of `n` (-1/0/+1) and an owned magnitude handle |n| in *mag.
 * Returns BNS_OK / BNS_ENOMEM. On success *mag is set (caller frees). */
static int split_sign_mag(const bn_t *n, int *sign, bn_t **mag)
{
    bn_t *zero = bn_new();
    if (zero == NULL) {
        return BNS_ENOMEM;
    }

    int c = bn_cmp(n, zero); /* <0, 0, >0 */
    int rc;
    if (c < 0) {
        *sign = -1;
        rc = bn_sub(zero, n, mag); /* |n| = 0 - n */
    } else {
        *sign = (c > 0) ? 1 : 0;
        rc = bn_dup(n, mag);
    }
    bn_free(zero);
    return rc;
}

int int2bytestring_sized(const bn_t *n, size_t width, byte_buf_t *out)
{
    if (n == NULL || out == NULL) {
        return BNS_EINVAL;
    }

    int sign;
    bn_t *mag = NULL;
    int rc = split_sign_mag(n, &sign, &mag);
    if (rc != BNS_OK) {
        return rc;
    }

    /* Append the magnitude as exactly `width` LE bytes onto a fresh scratch
     * buffer first, so a width-overflow (BNS_ERANGE) leaves `out` untouched. */
    byte_buf_t tmp;
    byte_buf_init(&tmp);
    rc = bn_to_le_bytes(mag, width, &tmp); /* BNS_ERANGE if |n| wider than width */
    bn_free(mag);
    if (rc != BNS_OK) {
        byte_buf_free(&tmp);
        return rc;
    }

    if (width > 0) {
        /* The top (most-significant) byte is the last in little-endian order.
         * Its high bit is reserved for the sign; if magnitude already set it,
         * the signed value does not fit in `width` bytes (matches num2bin). */
        if (tmp.data[width - 1] & 0x80) {
            byte_buf_free(&tmp);
            return BNS_ERANGE;
        }
        if (sign < 0) {
            tmp.data[width - 1] |= 0x80;
        }
    } else if (sign != 0) {
        /* width 0 cannot hold a non-zero magnitude (bn_to_le_bytes would have
         * already failed, but guard the sign-only case defensively). */
        byte_buf_free(&tmp);
        return BNS_ERANGE;
    }

    rc = byte_buf_append_buf(out, &tmp);
    byte_buf_free(&tmp);
    return rc;
}

int int2bytestring_minimal(const bn_t *n, byte_buf_t *out)
{
    if (n == NULL || out == NULL) {
        return BNS_EINVAL;
    }

    /* Zero -> empty (TS '' / 0n). */
    if (bn_is_zero(n)) {
        return BNS_OK;
    }

    int sign;
    bn_t *mag = NULL;
    int rc = split_sign_mag(n, &sign, &mag);
    if (rc != BNS_OK) {
        return rc;
    }

    /* Minimal-width BIG-ENDIAN magnitude, then reverse into LE. */
    byte_buf_t be;
    byte_buf_init(&be);
    rc = bn_to_be_bytes(mag, &be);
    bn_free(mag);
    if (rc != BNS_OK) {
        byte_buf_free(&be);
        return rc;
    }

    byte_buf_t le;
    byte_buf_init(&le);
    rc = byte_buf_reserve(&le, be.len + 1);
    if (rc != BNS_OK) {
        byte_buf_free(&be);
        byte_buf_free(&le);
        return rc;
    }
    for (size_t i = 0; i < be.len; i++) {
        /* reverse */
        (void)byte_buf_append_byte(&le, be.data[be.len - 1 - i]); /* reserved above */
    }
    byte_buf_free(&be);

    /* le now holds the minimal-width LE magnitude (non-empty: n != 0). The
     * most-significant byte is the last element. */
    size_t top = le.len - 1;
    if (le.data[top] & 0x80) {
        /* High bit occupied by magnitude: append a dedicated sign byte. */
        rc = byte_buf_append_byte(&le, sign < 0 ? 0x80 : 0x00); /* reserved above */
    } else if (sign < 0) {
        le.data[top] |= 0x80;
        rc = BNS_OK;
    } else {
        rc = BNS_OK;
    }
    if (rc != BNS_OK) {
        byte_buf_free(&le);
        return rc;
    }

    rc = byte_buf_append_buf(out, &le);
    byte_buf_free(&le);
    return rc;
}
