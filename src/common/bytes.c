/*
 * bytes.c — byte_buf_t growable owned-bytes buffer.
 *
 * Pure C over libc only. Geometric growth on reserve; constant-time compare
 * via a volatile accumulator so digest/secret comparisons do not leak timing.
 */
#include "common/bytes.h"
#include "common/error.h"

#include <stdlib.h>
#include <string.h>

/* Smallest non-zero capacity we bother allocating. */
#define BYTE_BUF_MIN_CAP 16u

void byte_buf_init(byte_buf_t *b)
{
    b->data = NULL;
    b->len  = 0;
    b->cap  = 0;
}

int byte_buf_init_cap(byte_buf_t *b, size_t cap)
{
    b->data = NULL;
    b->len  = 0;
    b->cap  = 0;
    if (cap == 0) {
        return BNS_OK;
    }
    b->data = (uint8_t *)malloc(cap);
    if (b->data == NULL) {
        return BNS_ENOMEM;
    }
    b->cap = cap;
    return BNS_OK;
}

void byte_buf_free(byte_buf_t *b)
{
    if (b == NULL) {
        return;
    }
    free(b->data);
    b->data = NULL;
    b->len  = 0;
    b->cap  = 0;
}

int byte_buf_reserve(byte_buf_t *b, size_t need)
{
    size_t new_cap;
    uint8_t *p;

    if (need <= b->cap) {
        return BNS_OK;
    }

    /* Geometric growth: double until >= need, starting from a sane minimum. */
    new_cap = (b->cap < BYTE_BUF_MIN_CAP) ? BYTE_BUF_MIN_CAP : b->cap;
    while (new_cap < need) {
        size_t doubled = new_cap << 1;
        if (doubled < new_cap) {
            /* size_t overflow on doubling: fall back to the exact need. */
            new_cap = need;
            break;
        }
        new_cap = doubled;
    }

    p = (uint8_t *)realloc(b->data, new_cap);
    if (p == NULL) {
        return BNS_ENOMEM;
    }
    b->data = p;
    b->cap  = new_cap;
    return BNS_OK;
}

int byte_buf_append(byte_buf_t *b, const void *data, size_t len)
{
    int rc;

    if (len == 0) {
        return BNS_OK;
    }
    /* Guard against size_t overflow of len + existing length. */
    if (len > (size_t)-1 - b->len) {
        return BNS_ENOMEM;
    }
    rc = byte_buf_reserve(b, b->len + len);
    if (rc != BNS_OK) {
        return rc;
    }
    memcpy(b->data + b->len, data, len);
    b->len += len;
    return BNS_OK;
}

int byte_buf_append_byte(byte_buf_t *b, uint8_t byte)
{
    int rc = byte_buf_reserve(b, b->len + 1);
    if (rc != BNS_OK) {
        return rc;
    }
    b->data[b->len] = byte;
    b->len += 1;
    return BNS_OK;
}

int byte_buf_append_buf(byte_buf_t *b, const byte_buf_t *src)
{
    if (src == NULL || src->len == 0) {
        return BNS_OK;
    }
    return byte_buf_append(b, src->data, src->len);
}

void byte_buf_clear(byte_buf_t *b)
{
    b->len = 0;
}

int byte_buf_from(byte_buf_t *b, const void *data, size_t len)
{
    int rc;

    byte_buf_init(b);
    if (len == 0) {
        return BNS_OK;
    }
    rc = byte_buf_reserve(b, len);
    if (rc != BNS_OK) {
        return rc;
    }
    memcpy(b->data, data, len);
    b->len = len;
    return BNS_OK;
}

bool byte_buf_eq(const byte_buf_t *a, const byte_buf_t *b)
{
    if (a == b) {
        return true;
    }
    if (a == NULL || b == NULL) {
        return false;
    }
    if (a->len != b->len) {
        return false;
    }
    if (a->len == 0) {
        return true;
    }
    return memcmp(a->data, b->data, a->len) == 0;
}

bool byte_buf_eq_ct(const byte_buf_t *a, const byte_buf_t *b)
{
    size_t i;
    volatile uint8_t acc = 0;

    if (a == NULL || b == NULL) {
        return a == b;
    }
    /* Length mismatch is not secret; bail without a content compare. */
    if (a->len != b->len) {
        return false;
    }
    for (i = 0; i < a->len; i++) {
        acc |= (uint8_t)(a->data[i] ^ b->data[i]);
    }
    return acc == 0;
}
