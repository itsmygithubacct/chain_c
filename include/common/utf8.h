/*
 * utf8.h — UTF-8 byte helpers.
 *
 * The TS uses Buffer.from(s, 'utf8') in a few preimages (e.g. provenance
 * length-prefixed fields). Source strings in this port are already UTF-8 byte
 * sequences (C char*), so "UTF-8 encoding" is the identity on the bytes; these
 * helpers exist to make that explicit and to give a byte-length count that
 * matches JavaScript's Buffer.byteLength(s, 'utf8').
 */
#ifndef BONSAI_COMMON_UTF8_H
#define BONSAI_COMMON_UTF8_H

#include <stddef.h>
#include <stdbool.h>

/* Number of bytes in the UTF-8 encoding of NUL-terminated `s` (== strlen for a
 * valid UTF-8 C string). */
size_t utf8_byte_len(const char *s);

/* Validate that `s` is well-formed UTF-8. */
bool utf8_is_valid(const char *s, size_t len);

#endif /* BONSAI_COMMON_UTF8_H */
