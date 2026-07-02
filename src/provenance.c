/*
 * provenance.c — on-chain provenance commitment + length-prefixed preimage.
 *
 * TS origin: src/provenance.ts (ProvenanceRecord, ZERO_PROVENANCE,
 * provenancePreimage, computeProvenanceHash).
 *
 * Byte-exactness pins (provenance.h):
 *  (1) length prefix is the UTF-8 BYTE count (== strlen for UTF-8 C strings).
 *  (2) field > 255 bytes => BNS_ERANGE (TS throws).
 *  (3) computeProvenanceHash hashes the DECODED preimage bytes.
 *  (4) order is fixed: datasetId, modelId, version, licenceTag.
 *  (5) lp(f) = [1-byte len][raw UTF-8 bytes].
 */
#include "provenance.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <openssl/sha.h>

#include "common/hex.h"
#include "common/utf8.h"

/* lp(s): append [1-byte UTF-8 length][raw bytes]. NULL => empty string.
 * TS: lp(s) — Buffer.from(s,'utf8'); if (>255) throw; lenHex || bytesHex. */
static int provenance_lp(const char *s, byte_buf_t *out)
{
    if (s == NULL) {
        s = "";
    }

    size_t n = utf8_byte_len(s);
    if (n > 255) {
        /* TS: throw new Error(`provenance field too long (>255 bytes): ...`) */
        return BNS_ERANGE;
    }

    int rc = byte_buf_append_byte(out, (uint8_t)n);
    if (rc != BNS_OK) {
        return rc;
    }
    return byte_buf_append(out, s, n);
}

int provenance_preimage(const provenance_record_t *p, byte_buf_t *out)
{
    if (p == NULL || out == NULL) {
        return BNS_EINVAL;
    }

    int rc;
    /* Fixed order: datasetId, modelId, version, licenceTag. */
    if ((rc = provenance_lp(p->dataset_id, out)) != BNS_OK) return rc;
    if ((rc = provenance_lp(p->model_id, out)) != BNS_OK) return rc;
    if ((rc = provenance_lp(p->version, out)) != BNS_OK) return rc;
    if ((rc = provenance_lp(p->licence_tag, out)) != BNS_OK) return rc;

    return BNS_OK;
}

int compute_provenance_hash(const provenance_record_t *p, char **out_hex)
{
    if (p == NULL || out_hex == NULL) {
        return BNS_EINVAL;
    }
    *out_hex = NULL;

    byte_buf_t preimage;
    byte_buf_init(&preimage);

    int rc = provenance_preimage(p, &preimage);
    if (rc != BNS_OK) {
        byte_buf_free(&preimage);
        return rc;
    }

    /* sha256 over the DECODED preimage bytes. */
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(preimage.data, preimage.len, digest);
    byte_buf_free(&preimage);

    char *hex = hex_encode(digest, sizeof(digest));
    if (hex == NULL) {
        return BNS_ENOMEM;
    }

    *out_hex = hex;
    return BNS_OK;
}
