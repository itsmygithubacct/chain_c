/*
 * rabin_attestor.c — Rabin-signature attestation toolkit (verifier-side adapter
 * over the frozen crypto/rabin primitives).
 *
 * TS origin: src/verifier/rabinAttestor.ts. See rabin_attestor.h for the wire
 * and byte-layout pins. The 54-byte attestation message is
 *   ATTEST_DOMAIN_HEX (ASCII "ARP1_ATTEST_V1", 14 bytes)
 *   || seq as 8-byte LITTLE-ENDIAN
 *   || digest (32 bytes, lowercased)
 * Golden: attestationMsg(seq=7, digest=ef*32) =
 *   415250315f4154544553545f5631 0700000000000000 ef*32.
 */
#include "verifier/rabin_attestor.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "common/hex.h"
#include "common/bytes.h"

/* Raw domain-tag bytes ("ARP1_ATTEST_V1", 14 bytes). */
static const uint8_t ATTEST_DOMAIN_BYTES[] = {
    0x41, 0x52, 0x50, 0x31, 0x5f, 0x41, 0x54, 0x54,
    0x45, 0x53, 0x54, 0x5f, 0x56, 0x31
};
#define ATTEST_DOMAIN_LEN 14u
#define ATTEST_SEQ_LEN    8u
#define ATTEST_DIGEST_LEN 32u
#define ATTEST_MSG_LEN    (ATTEST_DOMAIN_LEN + ATTEST_SEQ_LEN + ATTEST_DIGEST_LEN) /* 54 */

/* TS regex /^[0-9a-f]{64}$/i : exactly 64 chars, each hex (either case). */
static bool is_valid_digest_hex(const char *digest_hex)
{
    if (!digest_hex) return false;
    size_t i = 0;
    for (; i < 64; i++) {
        char c = digest_hex[i];
        if (c == '\0') return false;
        bool ok = (c >= '0' && c <= '9') ||
                  (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F');
        if (!ok) return false;
    }
    return digest_hex[64] == '\0';
}

/* Build the raw 54-byte attestation message into `out[ATTEST_MSG_LEN]`.
 * Returns BNS_OK / BNS_EINVAL (bad seq/digest). seq must be < 2^63. */
static int build_msg_bytes(uint64_t seq, const char *digest_hex,
                           uint8_t out[ATTEST_MSG_LEN])
{
    /* TS: seq < 0n || seq >= 1n << 63n. seq is uint64_t so >=0 always; the
     * upper guard is the high bit (mirrors BigInt < 2^63). */
    if (seq >= (UINT64_C(1) << 63)) return BNS_EINVAL;
    if (!is_valid_digest_hex(digest_hex)) return BNS_EINVAL;

    memcpy(out, ATTEST_DOMAIN_BYTES, ATTEST_DOMAIN_LEN);

    /* 8-byte little-endian seq: low byte first. */
    uint64_t v = seq;
    for (size_t i = 0; i < ATTEST_SEQ_LEN; i++) {
        out[ATTEST_DOMAIN_LEN + i] = (uint8_t)(v & 0xffu);
        v >>= 8;
    }

    /* digest bytes (lowercase normalization happens implicitly: hex_decode_fixed
     * accepts either case; the byte values are identical). */
    int rc = hex_decode_fixed(digest_hex, out + ATTEST_DOMAIN_LEN + ATTEST_SEQ_LEN,
                              ATTEST_DIGEST_LEN);
    if (rc != BNS_OK) return BNS_EINVAL;
    return BNS_OK;
}

/* ---- keygen / pubkey ---------------------------------------------------- */

int generate_attestor_key(rabin_attestor_key_t *out)
{
    if (!out) return BNS_EINVAL;
    return rabin_keygen(out);
}

int attestor_pub_key(const rabin_attestor_key_t *key, char **out)
{
    if (!key || !out) return BNS_EINVAL;
    *out = NULL;

    bn_t *n = NULL;
    int rc = rabin_pubkey(key, &n);
    if (rc != BNS_OK) return rc;

    rc = bn_to_dec(n, out);   /* base-10 decimal string */
    bn_free(n);
    return rc;
}

/* ---- message construction ----------------------------------------------- */

int attestation_msg_hex(uint64_t seq, const char *digest_hex, char **out)
{
    if (!out) return BNS_EINVAL;
    *out = NULL;

    uint8_t msg[ATTEST_MSG_LEN];
    int rc = build_msg_bytes(seq, digest_hex, msg);
    if (rc != BNS_OK) return rc;

    char *hex = hex_encode(msg, ATTEST_MSG_LEN);  /* lowercase, 108 chars */
    if (!hex) return BNS_ENOMEM;
    *out = hex;
    return BNS_OK;
}

/* ---- signer ------------------------------------------------------------- */

int rabin_attestor_sign_digest(const rabin_attestor_key_t *key,
                               const char *digest_hex, uint64_t seq,
                               char **out)
{
    if (!key || !out) return BNS_EINVAL;
    *out = NULL;

    uint8_t msg[ATTEST_MSG_LEN];
    int rc = build_msg_bytes(seq, digest_hex, msg);
    if (rc != BNS_OK) return rc;

    rabin_sig_t sig = { 0 };
    rc = rabin_sign(msg, ATTEST_MSG_LEN, key, &sig);
    if (rc != BNS_OK) return rc;

    /* s as lowercase hex, no 0x, no zero padding (JS BigInt.toString(16)). */
    char *s_hex = NULL;
    rc = bn_to_hex(sig.s, &s_hex);
    if (rc != BNS_OK) {
        rabin_sig_free(&sig);
        return rc;
    }

    /* "<seq decimal>:<s hex>:<paddingByteCount decimal>" */
    int needed = snprintf(NULL, 0, "%llu:%s:%zu",
                          (unsigned long long)seq, s_hex,
                          sig.padding_byte_count);
    if (needed < 0) {
        free(s_hex);
        rabin_sig_free(&sig);
        return BNS_ENOMEM;
    }
    char *wire = malloc((size_t)needed + 1);
    if (!wire) {
        free(s_hex);
        rabin_sig_free(&sig);
        return BNS_ENOMEM;
    }
    snprintf(wire, (size_t)needed + 1, "%llu:%s:%zu",
             (unsigned long long)seq, s_hex, sig.padding_byte_count);

    free(s_hex);
    rabin_sig_free(&sig);
    *out = wire;
    return BNS_OK;
}

/* ---- wire parsing ------------------------------------------------------- */

/* Parse a non-negative decimal string into *out (uint64_t).
 * Returns false on empty, non-digit, leading sign, or overflow. */
static bool parse_u64_dec(const char *s, size_t len, uint64_t *out)
{
    if (len == 0) return false;
    uint64_t v = 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c < '0' || c > '9') return false;
        /* overflow guard: v*10 + d must fit in uint64_t */
        if (v > (UINT64_MAX - (uint64_t)(c - '0')) / 10) return false;
        v = v * 10 + (uint64_t)(c - '0');
    }
    *out = v;
    return true;
}

void parsed_attestation_free(parsed_attestation_t *p)
{
    if (!p) return;
    if (p->s) {
        bn_free(p->s);
        p->s = NULL;
    }
}

int parse_attestation(const char *signature, parsed_attestation_t *out,
                      bool *out_ok)
{
    if (!out_ok) return BNS_EINVAL;
    *out_ok = false;
    if (!signature || !out) return BNS_OK;

    out->seq = 0;
    out->s = NULL;
    out->padding_byte_count = 0;

    /* Split on ':' requiring EXACTLY 3 parts. */
    const char *c0 = signature;
    const char *colon1 = strchr(c0, ':');
    if (!colon1) return BNS_OK;                 /* < 3 parts */
    const char *c1 = colon1 + 1;
    const char *colon2 = strchr(c1, ':');
    if (!colon2) return BNS_OK;                 /* < 3 parts */
    const char *c2 = colon2 + 1;
    if (strchr(c2, ':') != NULL) return BNS_OK; /* > 3 parts */

    size_t len0 = (size_t)(colon1 - c0);
    size_t len1 = (size_t)(colon2 - c1);
    /* c2 runs to end-of-string */

    /* seq = BigInt(parts[0]) decimal; reject negative / non-numeric.
     * BigInt("") throws => null. Our parser rejects empty. */
    uint64_t seq = 0;
    if (!parse_u64_dec(c0, len0, &seq)) return BNS_OK;

    /* paddingByteCount = Number(parts[2]); reject non-integer / negative.
     * TS: Number.isInteger && >= 0. Match a strict non-negative decimal. */
    uint64_t pad = 0;
    if (!parse_u64_dec(c2, strlen(c2), &pad)) return BNS_OK;
    /* Reject an absurd padding count from this untrusted attestation string early
     * (a tiny retry count is legitimate; ~2^63 is a memory-exhaustion DoS). */
    if (pad > RABIN_MAX_PADDING_BYTES) return BNS_OK;   /* malformed => null */

    /* s = BigInt('0x' + parts[1]); hex of the signature value. Empty hex part
     * => BigInt('0x') throws => null. Validate it's pure hex first. */
    if (len1 == 0) return BNS_OK;
    /* Bound the untrusted signature hex: a legitimate Rabin s is ~384 hex chars (n is ~1536-bit);
     * reject a wildly oversized value before bn_parse_hex builds a giant bignum that rabin_verify
     * would then square (CPU/memory spike per verification). 1024 hex = 4096-bit, well above any
     * real modulus. (review-2 #11) */
    if (len1 > 1024) return BNS_OK;   /* malformed => null */
    for (size_t i = 0; i < len1; i++) {
        char ch = c1[i];
        bool hexok = (ch >= '0' && ch <= '9') ||
                     (ch >= 'a' && ch <= 'f') ||
                     (ch >= 'A' && ch <= 'F');
        if (!hexok) return BNS_OK;
    }

    /* bn_parse_hex needs a NUL-terminated string; copy the middle part. */
    char *hexbuf = malloc(len1 + 1);
    if (!hexbuf) return BNS_ENOMEM;
    memcpy(hexbuf, c1, len1);
    hexbuf[len1] = '\0';

    bn_t *s = NULL;
    int rc = bn_parse_hex(hexbuf, &s);
    free(hexbuf);
    if (rc == BNS_ENOMEM) return BNS_ENOMEM;
    if (rc != BNS_OK) return BNS_OK;   /* malformed => null */

    out->seq = seq;
    out->s = s;
    out->padding_byte_count = (size_t)pad;
    *out_ok = true;
    return BNS_OK;
}

/* ---- verifier ----------------------------------------------------------- */

int rabin_attestation_verify(const char *attestor_pubkey,
                             const char *digest_hex, const char *signature,
                             bool *out_ok)
{
    if (!out_ok) return BNS_EINVAL;
    *out_ok = false;   /* fail-closed default */

    if (!attestor_pubkey || !digest_hex || !signature) return BNS_OK;

    /* n = BigInt(attestorPubkey) decimal; bad pubkey => false. */
    bn_t *n = NULL;
    int rc = bn_parse_dec(attestor_pubkey, &n);
    if (rc != BNS_OK) return BNS_OK;

    /* Parse the wire signature; null/malformed => false. */
    parsed_attestation_t att;
    bool parsed = false;
    rc = parse_attestation(signature, &att, &parsed);
    if (rc != BNS_OK || !parsed) {
        bn_free(n);
        if (parsed) parsed_attestation_free(&att);
        return BNS_OK;
    }

    /* Reconstruct the message at the embedded seq over the given digest.
     * A bad seq/digest here means the message can't be built => false. */
    uint8_t msg[ATTEST_MSG_LEN];
    rc = build_msg_bytes(att.seq, digest_hex, msg);
    if (rc != BNS_OK) {
        bn_free(n);
        parsed_attestation_free(&att);
        return BNS_OK;
    }

    rabin_sig_t sig = { .s = att.s, .padding_byte_count = att.padding_byte_count };
    bool verified = rabin_verify(msg, ATTEST_MSG_LEN, &sig, n);

    bn_free(n);
    parsed_attestation_free(&att);

    *out_ok = verified;
    return BNS_OK;
}

/* ---- AttestationVerifier vtable adapter ---------------------------------- */

static int rabin_attestation_verify_vfn(void *ctx, const char *attestor_pubkey,
                                        const char *digest_hex,
                                        const char *signature, bool *out_ok)
{
    (void)ctx;
    return rabin_attestation_verify(attestor_pubkey, digest_hex, signature, out_ok);
}

int rabin_attestation_verifier_vtable(attestation_verifier_t *out_vtable)
{
    if (!out_vtable) return BNS_EINVAL;
    out_vtable->ctx = NULL;
    out_vtable->verify = rabin_attestation_verify_vfn;
    return BNS_OK;
}
