/*
 * provenance.h — the on-chain provenance commitment (datasetId/modelId/version/
 * licenceTag) and its byte-exact length-prefixed preimage.
 *
 * Computes the provenanceHash that commits to the dataset/model/version/licence
 * behind an agent action WITHOUT publishing the details (the structured record
 * lives in a crypto-shreddable off-chain enclave). The canonical preimage lets
 * an auditor recompute the same hash; ZERO_PROVENANCE is the sentinel for an
 * action declaring no provenance.
 *
 * TS origin: src/provenance.ts (ProvenanceRecord, ZERO_PROVENANCE,
 * provenancePreimage, computeProvenanceHash).
 *
 * DETERMINISM PINS (src/provenance.ts notes — a wrong byte changes the hash):
 *  (1) The length prefix is the UTF-8 BYTE count of the field, NOT the codepoint
 *      count — multibyte chars count as their bytes (see common/utf8.h).
 *  (2) A field whose UTF-8 byte length exceeds 255 MUST hard-error (BNS_ERANGE)
 *      exactly as the TS throws — never silently truncate or widen the prefix.
 *  (3) computeProvenanceHash hashes the DECODED bytes of the preimage, i.e.
 *      sha256(provenance_preimage bytes), not the ASCII hex text.
 *  (4) Field concatenation order is FIXED: datasetId, modelId, version, licenceTag.
 *  (5) lp(field) = [1-byte UTF-8 length][raw UTF-8 bytes].
 */
#ifndef BONSAI_PROVENANCE_H
#define BONSAI_PROVENANCE_H

#include <stddef.h>
#include "common/error.h"
#include "common/bytes.h"

/* The 'no provenance declared' sentinel as a 64-char all-zero lowercase hex
 * Sha256 string ('0000...00', NUL-terminated). TS: provenance.ts::ZERO_PROVENANCE
 * = Sha256(toByteString('00'.repeat(32))). */
#define BONSAI_ZERO_PROVENANCE \
    "0000000000000000000000000000000000000000000000000000000000000000"

/* Off-chain provenance record: four UTF-8 string fields. The strings are
 * borrowed, NUL-terminated UTF-8 (NULL is treated as the empty string by the
 * preimage builder). TS: src/provenance.ts::ProvenanceRecord. */
typedef struct {
    const char *dataset_id;   /* datasetId  */
    const char *model_id;     /* modelId    */
    const char *version;      /* version    */
    const char *licence_tag;  /* licenceTag */
} provenance_record_t;

/* Build the canonical preimage bytes appended to `out` (init'd):
 *   lp(datasetId) || lp(modelId) || lp(version) || lp(licenceTag)
 * where lp(f) = [1-byte UTF-8 byte length of f][raw UTF-8 bytes of f].
 * Any field longer than 255 UTF-8 bytes => BNS_ERANGE (matches the TS throw).
 * TS: src/provenance.ts::provenancePreimage. BNS_OK / BNS_ERANGE / BNS_ENOMEM. */
int provenance_preimage(const provenance_record_t *p, byte_buf_t *out);

/* Compute the provenance hash: sha256(provenance_preimage(p)) as a freshly
 * malloc'd 64-char lowercase hex Sha256 string (*out_hex; caller frees).
 * TS: src/provenance.ts::computeProvenanceHash.
 * BNS_OK / BNS_ERANGE (field too long) / BNS_ENOMEM. */
int compute_provenance_hash(const provenance_record_t *p, char **out_hex);

#endif /* BONSAI_PROVENANCE_H */
