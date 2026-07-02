/*
 * utf8.c — UTF-8 byte helpers.
 *
 * Pure C over libc only. Source strings in this port are already UTF-8 byte
 * sequences, so byte length == strlen and "UTF-8 encoding" is the identity on
 * the bytes. utf8_is_valid does a strict well-formedness check (RFC 3629:
 * shortest form, no surrogates, U+0000..U+10FFFF) matching what a JS string
 * round-trips through Buffer.from(s, 'utf8').
 */
#include "common/utf8.h"

#include <string.h>
#include <stdint.h>

size_t utf8_byte_len(const char *s)
{
    if (s == NULL) {
        return 0;
    }
    return strlen(s);
}

bool utf8_is_valid(const char *s, size_t len)
{
    size_t i = 0;
    const uint8_t *p;

    if (s == NULL) {
        return len == 0;
    }
    p = (const uint8_t *)s;

    while (i < len) {
        uint8_t c = p[i];

        if (c <= 0x7f) {
            /* ASCII. */
            i += 1;
        } else if ((c & 0xe0u) == 0xc0u) {
            /* 2-byte: U+0080..U+07FF. Reject overlong (C0, C1). */
            if (c < 0xc2u) {
                return false;
            }
            if (i + 1 >= len) {
                return false;
            }
            if ((p[i + 1] & 0xc0u) != 0x80u) {
                return false;
            }
            i += 2;
        } else if ((c & 0xf0u) == 0xe0u) {
            /* 3-byte: U+0800..U+FFFF, excluding surrogates U+D800..U+DFFF. */
            uint8_t c1, c2;
            if (i + 2 >= len) {
                return false;
            }
            c1 = p[i + 1];
            c2 = p[i + 2];
            if ((c1 & 0xc0u) != 0x80u || (c2 & 0xc0u) != 0x80u) {
                return false;
            }
            /* Overlong: E0 requires second byte >= A0. */
            if (c == 0xe0u && c1 < 0xa0u) {
                return false;
            }
            /* Surrogate range: ED requires second byte < A0. */
            if (c == 0xedu && c1 >= 0xa0u) {
                return false;
            }
            i += 3;
        } else if ((c & 0xf8u) == 0xf0u) {
            /* 4-byte: U+10000..U+10FFFF. */
            uint8_t c1, c2, c3;
            if (c > 0xf4u) {
                return false; /* > U+10FFFF */
            }
            if (i + 3 >= len) {
                return false;
            }
            c1 = p[i + 1];
            c2 = p[i + 2];
            c3 = p[i + 3];
            if ((c1 & 0xc0u) != 0x80u || (c2 & 0xc0u) != 0x80u ||
                (c3 & 0xc0u) != 0x80u) {
                return false;
            }
            /* Overlong: F0 requires second byte >= 90. */
            if (c == 0xf0u && c1 < 0x90u) {
                return false;
            }
            /* Cap: F4 requires second byte < 90 (so <= U+10FFFF). */
            if (c == 0xf4u && c1 >= 0x90u) {
                return false;
            }
            i += 4;
        } else {
            /* Lone continuation byte or invalid lead (F5..FF, 80..BF). */
            return false;
        }
    }
    return true;
}
