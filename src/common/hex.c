/*
 * hex.c — lowercase-hex <-> bytes (the ByteString string form) + validators.
 *
 * Pure C over libc only. Encode is ALWAYS lowercase (load-bearing for every
 * hash/commitment); decode accepts either case. Validators mirror the TS
 * regexes: is_sha256_hex == 64 hex chars, is_pubkey_hex == 66 hex chars
 * starting 02 or 03 (compressed SEC).
 */
#include "common/hex.h"
#include "common/error.h"

#include <stdlib.h>
#include <string.h>

static const char HEX_LC[16] = {
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'
};

/* Return the nibble value of an ASCII hex digit, or -1 if not a hex digit. */
static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_encode_to(const uint8_t *data, size_t len, char *out, size_t out_sz)
{
    size_t i;

    if (out == NULL) {
        return BNS_EINVAL;
    }
    /* Need 2*len chars + 1 NUL; guard the multiply against overflow. */
    if (len > ((size_t)-1 - 1) / 2) {
        return BNS_EINVAL;
    }
    if (out_sz < 2 * len + 1) {
        return BNS_EINVAL;
    }
    for (i = 0; i < len; i++) {
        out[2 * i]     = HEX_LC[(data[i] >> 4) & 0x0f];
        out[2 * i + 1] = HEX_LC[data[i] & 0x0f];
    }
    out[2 * len] = '\0';
    return BNS_OK;
}

char *hex_encode(const uint8_t *data, size_t len)
{
    char *out;

    if (len > ((size_t)-1 - 1) / 2) {
        return NULL;
    }
    out = (char *)malloc(2 * len + 1);
    if (out == NULL) {
        return NULL;
    }
    if (hex_encode_to(data, len, out, 2 * len + 1) != BNS_OK) {
        free(out);
        return NULL;
    }
    return out;
}

char *hex_encode_buf(const byte_buf_t *b)
{
    if (b == NULL) {
        return NULL;
    }
    return hex_encode(b->data, b->len);
}

int hex_decode(const char *hex, byte_buf_t *out)
{
    size_t slen, nbytes, i;
    int rc;

    if (out == NULL) return BNS_EINVAL;   /* byte_buf_init derefs out; guard first (sibling decoders do) */
    byte_buf_init(out);
    if (hex == NULL) {
        return BNS_EPARSE;
    }
    slen = strlen(hex);
    if ((slen & 1u) != 0) {
        return BNS_EPARSE;
    }
    nbytes = slen / 2;
    if (nbytes == 0) {
        return BNS_OK; /* empty string -> empty buffer */
    }
    rc = byte_buf_reserve(out, nbytes);
    if (rc != BNS_OK) {
        return rc; /* BNS_ENOMEM */
    }
    for (i = 0; i < nbytes; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            byte_buf_free(out);
            return BNS_EPARSE;
        }
        out->data[i] = (uint8_t)((hi << 4) | lo);
    }
    out->len = nbytes;
    return BNS_OK;
}

int hex_decode_fixed(const char *hex, uint8_t *buf, size_t nbytes)
{
    size_t i;

    if (hex == NULL || (buf == NULL && nbytes > 0)) {
        return BNS_EPARSE;
    }
    if (strlen(hex) != 2 * nbytes) {
        return BNS_EPARSE;
    }
    for (i = 0; i < nbytes; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return BNS_EPARSE;
        }
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    return BNS_OK;
}

bool is_hex(const char *s)
{
    size_t i, slen;

    if (s == NULL) {
        return false;
    }
    slen = strlen(s);
    if (slen == 0 || (slen & 1u) != 0) {
        return false;
    }
    for (i = 0; i < slen; i++) {
        if (hex_nibble(s[i]) < 0) {
            return false;
        }
    }
    return true;
}

bool is_hex_len(const char *s, size_t nbytes)
{
    size_t i;

    if (s == NULL) {
        return false;
    }
    if (strlen(s) != 2 * nbytes) {
        return false;
    }
    for (i = 0; i < 2 * nbytes; i++) {
        if (hex_nibble(s[i]) < 0) {
            return false;
        }
    }
    return true;
}

bool is_sha256_hex(const char *s)
{
    return is_hex_len(s, 32); /* 64 hex chars */
}

bool is_pubkey_hex(const char *s)
{
    if (!is_hex_len(s, 33)) { /* 66 hex chars */
        return false;
    }
    /* Compressed SEC prefix: 02 or 03. */
    return s[0] == '0' && (s[1] == '2' || s[1] == '3');
}

char *hex_to_lower(const char *s)
{
    size_t slen, i;
    char *out;

    if (s == NULL) {
        return NULL;
    }
    slen = strlen(s);
    out = (char *)malloc(slen + 1);
    if (out == NULL) {
        return NULL;
    }
    for (i = 0; i < slen; i++) {
        char c = s[i];
        if (c >= 'A' && c <= 'F') {
            c = (char)(c - 'A' + 'a');
        }
        out[i] = c;
    }
    out[slen] = '\0';
    return out;
}
