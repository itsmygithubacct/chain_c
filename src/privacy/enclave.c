/*
 * enclave.c — PrivateEnclave: per-identity AES-256-GCM-encrypted off-chain store
 * for action payloads / PII. The chain holds only H(action); the plaintext lives
 * here encrypted under a per-identity KeyVault key. 'Erasure' (crypto-shredding)
 * destroys the key while the on-chain receipt commitment stands. Also derives
 * the keyed actionHash and the shred-marker.
 *
 * TS origin: src/privacy/enclave.ts (PrivateEnclave, SealedRecord, ShreddedError,
 * IntegrityError) over crypto/aes_gcm.h + crypto/hash.h.
 */
#include "privacy/enclave.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/crypto.h> /* OPENSSL_cleanse */

#include "crypto/aes_gcm.h"
#include "crypto/hash.h"
#include "crypto/rand.h"
#include "common/hex.h"

struct private_enclave_s {
    const key_vault_t *vault;       /* borrowed; must outlive the enclave */
    enclave_clock_fn   clock;       /* NULL => wall-clock seconds         */
    void              *clock_user;
};

/* now(): injected clock if provided, else Math.floor(Date.now()/1000). */
static int64_t enc_now(const private_enclave_t *enc)
{
    if (enc->clock) return enc->clock(enc->clock_user);
    return (int64_t)time(NULL);
}

/* ---- lifecycle ---------------------------------------------------------- */

int private_enclave_new(const key_vault_t *vault,
                        enclave_clock_fn clock, void *clock_user,
                        private_enclave_t **out)
{
    if (!vault || !out) return BNS_EINVAL;
    private_enclave_t *enc = calloc(1, sizeof(*enc));
    if (!enc) return BNS_ENOMEM;
    enc->vault      = vault;
    enc->clock      = clock;
    enc->clock_user = clock_user;
    *out = enc;
    return BNS_OK;
}

void private_enclave_free(private_enclave_t *enc)
{
    free(enc);
}

/* Provenance strings in a sealed_record are OWNED deep copies (the source pointers
 * are borrowed and may be freed by the caller while the sealed record lives on). */
static char *dup_or_null(const char *s) { return s ? strdup(s) : NULL; }

static void provenance_free_owned(provenance_record_t *p)
{
    free((char *)p->dataset_id);
    free((char *)p->model_id);
    free((char *)p->version);
    free((char *)p->licence_tag);
    p->dataset_id = p->model_id = p->version = p->licence_tag = NULL;
}

static int provenance_deep_copy(provenance_record_t *dst, const provenance_record_t *src)
{
    dst->dataset_id  = dup_or_null(src->dataset_id);
    dst->model_id    = dup_or_null(src->model_id);
    dst->version     = dup_or_null(src->version);
    dst->licence_tag = dup_or_null(src->licence_tag);
    if ((src->dataset_id  && !dst->dataset_id) ||
        (src->model_id    && !dst->model_id)   ||
        (src->version     && !dst->version)    ||
        (src->licence_tag && !dst->licence_tag)) {
        provenance_free_owned(dst);   /* free partial copies, fail closed */
        return BNS_ENOMEM;
    }
    return BNS_OK;
}

void sealed_record_free(sealed_record_t *rec)
{
    if (!rec) return;
    free(rec->identity_id);
    free(rec->ciphertext);
    free(rec->iv);
    free(rec->auth_tag);
    if (rec->has_provenance) provenance_free_owned(&rec->provenance);
    memset(rec, 0, sizeof(*rec));
}

/* ---- keyed commitments -------------------------------------------------- */

/* actionCommitment = SHA256("PRISCILLA_ACTION_V1" || raw 32-byte key || payload).
 * Single sha256 over the three chunks, NO separators. Lowercase hex (caller
 * frees). TS: PrivateEnclave.actionCommitment. */
static int action_commitment(const uint8_t key[BONSAI_KEY_VAULT_KEY_LEN],
                             const uint8_t *payload, size_t payload_len,
                             char **out_hex)
{
    byte_buf_t pre;
    byte_buf_init(&pre);
    int rc;
    if ((rc = byte_buf_append(&pre, BONSAI_PRISCILLA_ACTION_DOMAIN,
                              strlen(BONSAI_PRISCILLA_ACTION_DOMAIN))) != BNS_OK)
        goto done;
    if ((rc = byte_buf_append(&pre, key, BONSAI_KEY_VAULT_KEY_LEN)) != BNS_OK)
        goto done;
    if (payload_len > 0 &&
        (rc = byte_buf_append(&pre, payload, payload_len)) != BNS_OK)
        goto done;

    uint8_t digest[BONSAI_SHA256_LEN];
    sha256(pre.data, pre.len, digest);
    char *hex = hex_encode(digest, BONSAI_SHA256_LEN);
    if (!hex) {
        rc = BNS_ENOMEM;
        goto done;
    }
    *out_hex = hex;
    rc = BNS_OK;
done:
    byte_buf_free(&pre);
    return rc;
}

/* ---- seal / open -------------------------------------------------------- */

int private_enclave_seal(private_enclave_t *enc, const char *identity_id,
                         const uint8_t *plaintext, size_t plaintext_len,
                         sealed_record_t *out)
{
    if (!enc || !identity_id || !out || (plaintext_len > 0 && !plaintext))
        return BNS_EINVAL;

    memset(out, 0, sizeof(*out));

    uint8_t key[BONSAI_KEY_VAULT_KEY_LEN];
    int rc = enc->vault->ensure_key(enc->vault->ctx, identity_id, key);
    if (rc != BNS_OK) return rc;

    uint8_t iv[BONSAI_AES_GCM_IV_LEN];
    rc = rand_bytes(iv, BONSAI_AES_GCM_IV_LEN);
    if (rc != BNS_OK) goto fail_key;

    byte_buf_t ct;
    byte_buf_init(&ct);
    uint8_t tag[BONSAI_AES_GCM_TAG_LEN];
    /* AAD = UTF-8 bytes of identityId — binds identity into the tag. */
    rc = aes256gcm_seal(key, iv, plaintext, plaintext_len,
                        (const uint8_t *)identity_id, strlen(identity_id),
                        &ct, tag);
    if (rc != BNS_OK) {
        byte_buf_free(&ct);
        goto fail_key;
    }

    char *id_copy   = NULL;
    char *ct_hex    = NULL;
    char *iv_hex    = NULL;
    char *tag_hex   = NULL;
    size_t idlen    = strlen(identity_id);

    id_copy = malloc(idlen + 1);
    ct_hex  = hex_encode(ct.data, ct.len);
    iv_hex  = hex_encode(iv, BONSAI_AES_GCM_IV_LEN);
    tag_hex = hex_encode(tag, BONSAI_AES_GCM_TAG_LEN);
    byte_buf_free(&ct);

    if (!id_copy || !ct_hex || !iv_hex || !tag_hex) {
        free(id_copy);
        free(ct_hex);
        free(iv_hex);
        free(tag_hex);
        rc = BNS_ENOMEM;
        goto fail_key;
    }
    memcpy(id_copy, identity_id, idlen + 1);

    out->identity_id   = id_copy;
    out->ciphertext    = ct_hex;
    out->iv            = iv_hex;
    out->auth_tag      = tag_hex;
    out->sealed_at     = enc_now(enc);
    out->has_provenance = false;

    OPENSSL_cleanse(key, sizeof(key));
    return BNS_OK;

fail_key:
    OPENSSL_cleanse(key, sizeof(key));
    return rc;
}

int private_enclave_seal_action(private_enclave_t *enc, const char *identity_id,
                                const uint8_t *payload, size_t payload_len,
                                const provenance_record_t *provenance,
                                sealed_record_t *out_sealed,
                                char **out_action_hash,
                                char **out_provenance_hash)
{
    if (!enc || !identity_id || !out_sealed || !out_action_hash ||
        !out_provenance_hash || (payload_len > 0 && !payload))
        return BNS_EINVAL;

    *out_action_hash     = NULL;
    *out_provenance_hash = NULL;
    memset(out_sealed, 0, sizeof(*out_sealed));

    /* actionHash = keyed commitment over ensureKey(identityId). */
    uint8_t key[BONSAI_KEY_VAULT_KEY_LEN];
    int rc = enc->vault->ensure_key(enc->vault->ctx, identity_id, key);
    if (rc != BNS_OK) return rc;

    char *action_hash = NULL;
    rc = action_commitment(key, payload, payload_len, &action_hash);
    OPENSSL_cleanse(key, sizeof(key));
    if (rc != BNS_OK) return rc;

    /* seal() (ensureKey is idempotent — same key). */
    rc = private_enclave_seal(enc, identity_id, payload, payload_len, out_sealed);
    if (rc != BNS_OK) {
        free(action_hash);
        return rc;
    }

    /* provenanceHash: compute when declared, else ZERO_PROVENANCE. */
    char *prov_hash = NULL;
    if (provenance) {
        rc = compute_provenance_hash(provenance, &prov_hash);
        if (rc != BNS_OK) {
            free(action_hash);
            sealed_record_free(out_sealed);
            return rc;
        }
        /* Attach the plaintext provenance to the record as OWNED deep copies: the
         * sealed record outlives this call, so a shallow pointer copy would dangle
         * once the caller frees/reuses its borrowed provenance string storage. */
        rc = provenance_deep_copy(&out_sealed->provenance, provenance);
        if (rc != BNS_OK) {
            free(prov_hash);
            free(action_hash);
            sealed_record_free(out_sealed);
            return rc;
        }
        out_sealed->has_provenance = true;
    } else {
        size_t n = strlen(BONSAI_ZERO_PROVENANCE);
        prov_hash = malloc(n + 1);
        if (!prov_hash) {
            free(action_hash);
            sealed_record_free(out_sealed);
            return BNS_ENOMEM;
        }
        memcpy(prov_hash, BONSAI_ZERO_PROVENANCE, n + 1);
    }

    *out_action_hash     = action_hash;
    *out_provenance_hash = prov_hash;
    return BNS_OK;
}

int private_enclave_recompute_action_hash(private_enclave_t *enc,
                                          const char *identity_id,
                                          const uint8_t *payload,
                                          size_t payload_len,
                                          char **out_hex, bool *out_found)
{
    if (!enc || !identity_id || !out_hex || !out_found ||
        (payload_len > 0 && !payload))
        return BNS_EINVAL;

    *out_hex = NULL;

    uint8_t key[BONSAI_KEY_VAULT_KEY_LEN];
    bool found = false;
    int rc = enc->vault->get_key(enc->vault->ctx, identity_id, key, &found);
    if (rc != BNS_OK) return rc;
    if (!found) {
        /* Key shredded => unverifiable. The erasure property, not an error. */
        *out_found = false;
        return BNS_OK;
    }

    rc = action_commitment(key, payload, payload_len, out_hex);
    OPENSSL_cleanse(key, sizeof(key));
    if (rc != BNS_OK) return rc;

    *out_found = true;
    return BNS_OK;
}

int private_enclave_open(private_enclave_t *enc, const sealed_record_t *record,
                         byte_buf_t *out)
{
    if (!enc || !record || !out || !record->identity_id || !record->iv ||
        !record->auth_tag || !record->ciphertext)
        return BNS_EINVAL;

    uint8_t key[BONSAI_KEY_VAULT_KEY_LEN];
    bool found = false;
    int rc = enc->vault->get_key(enc->vault->ctx, record->identity_id, key,
                                 &found);
    if (rc != BNS_OK) return rc;
    if (!found) return BNS_ESHREDDED; /* ShreddedError */

    uint8_t iv[BONSAI_AES_GCM_IV_LEN];
    uint8_t tag[BONSAI_AES_GCM_TAG_LEN];
    byte_buf_t ct;
    byte_buf_init(&ct);

    rc = hex_decode_fixed(record->iv, iv, BONSAI_AES_GCM_IV_LEN);
    if (rc != BNS_OK) { rc = BNS_EINTEGRITY; goto done; }
    rc = hex_decode_fixed(record->auth_tag, tag, BONSAI_AES_GCM_TAG_LEN);
    if (rc != BNS_OK) { rc = BNS_EINTEGRITY; goto done; }
    rc = hex_decode(record->ciphertext, &ct);
    if (rc != BNS_OK) { rc = BNS_EINTEGRITY; goto done; }

    /* AAD = UTF-8(identityId); a relabelled record fails authentication. */
    rc = aes256gcm_open(key, iv, ct.data, ct.len,
                        (const uint8_t *)record->identity_id,
                        strlen(record->identity_id), tag, out);
    if (rc != BNS_OK) rc = BNS_EINTEGRITY; /* IntegrityError */

done:
    OPENSSL_cleanse(key, sizeof(key));
    byte_buf_free(&ct);
    return rc;
}

/* ---- shred / marker ----------------------------------------------------- */

int private_enclave_shred(private_enclave_t *enc, const char *identity_id,
                          bool *out_shredded, char **out_marker)
{
    if (!enc || !identity_id || !out_shredded || !out_marker)
        return BNS_EINVAL;

    *out_marker = NULL;

    bool had = false;
    int rc = enc->vault->shred(enc->vault->ctx, identity_id, &had);
    if (rc != BNS_OK) return rc;

    rc = private_enclave_shred_marker(identity_id, out_marker);
    if (rc != BNS_OK) return rc;

    *out_shredded = had;
    return BNS_OK;
}

int private_enclave_shred_marker(const char *identity_id, char **out)
{
    if (!identity_id || !out) return BNS_EINVAL;
    *out = NULL;

    /* SHA256("SHRED_V1" || UTF-8 identityId). */
    byte_buf_t pre;
    byte_buf_init(&pre);
    int rc;
    if ((rc = byte_buf_append(&pre, BONSAI_SHRED_MARKER_DOMAIN,
                              strlen(BONSAI_SHRED_MARKER_DOMAIN))) != BNS_OK)
        goto done;
    if ((rc = byte_buf_append(&pre, identity_id, strlen(identity_id))) != BNS_OK)
        goto done;

    uint8_t digest[BONSAI_SHA256_LEN];
    sha256(pre.data, pre.len, digest);
    char *hex = hex_encode(digest, BONSAI_SHA256_LEN);
    if (!hex) { rc = BNS_ENOMEM; goto done; }
    *out = hex;
    rc = BNS_OK;
done:
    byte_buf_free(&pre);
    return rc;
}
