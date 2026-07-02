/*
 * bytes.h — byte_buf_t, the single owned-bytes type used everywhere.
 *
 * This is the C representation of a scrypt-ts `ByteString` payload (the raw
 * decoded bytes) and of every preimage / script / serialized tx / hash digest.
 * It is a growable, owned buffer; `hex.h` converts to/from the lowercase-hex
 * string form that the TS layer passes around as `ByteString`.
 *
 * Ownership: the buffer owns `data`. byte_buf_free() releases it. Functions that
 * "return" a buffer initialise a caller-provided byte_buf_t (out-param) or take
 * an already-init'd buffer to append into. There is no implicit aliasing.
 */
#ifndef BONSAI_COMMON_BYTES_H
#define BONSAI_COMMON_BYTES_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint8_t *data;   /* owned; may be NULL when cap == 0 */
    size_t   len;    /* used bytes                       */
    size_t   cap;    /* allocated bytes                  */
} byte_buf_t;

/* Initialise an empty buffer (no allocation). */
void byte_buf_init(byte_buf_t *b);

/* Initialise with reserved capacity. Returns BNS_OK / BNS_ENOMEM. */
int byte_buf_init_cap(byte_buf_t *b, size_t cap);

/* Release owned memory and reset to empty. Safe on a zeroed/empty buffer. */
void byte_buf_free(byte_buf_t *b);

/* Ensure cap >= need (grows geometrically). Returns BNS_OK / BNS_ENOMEM. */
int byte_buf_reserve(byte_buf_t *b, size_t need);

/* Append raw bytes. Returns BNS_OK / BNS_ENOMEM. */
int byte_buf_append(byte_buf_t *b, const void *data, size_t len);

/* Append a single byte. */
int byte_buf_append_byte(byte_buf_t *b, uint8_t byte);

/* Append the contents of another buffer. */
int byte_buf_append_buf(byte_buf_t *b, const byte_buf_t *src);

/* Reset length to 0 but keep the allocation. */
void byte_buf_clear(byte_buf_t *b);

/* Take ownership of a heap copy of `data`/`len` (e.g. for returning). */
int byte_buf_from(byte_buf_t *b, const void *data, size_t len);

/* Byte-exact equality (length + content). */
bool byte_buf_eq(const byte_buf_t *a, const byte_buf_t *b);

/* Constant-time equality (for secret/digest comparison). */
bool byte_buf_eq_ct(const byte_buf_t *a, const byte_buf_t *b);

#endif /* BONSAI_COMMON_BYTES_H */
