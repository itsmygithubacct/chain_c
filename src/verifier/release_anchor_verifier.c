/*
 * release_anchor_verifier.c — Pillar A consumer/Brain gate.
 *
 * Faithful port of src/verifier/releaseAnchorVerifier.ts. Pure policy over
 * injected SpvClient / AttestationVerifier / RevocationOracle vtables; also
 * implements computeActivateDigest, the canonical digest both signer and
 * verifier must agree on.
 *
 * Byte-exactness pins (see header): the digest domain tag is the 16 ASCII bytes
 * "ARP1_ACTIVATE_V1" with NO separator, then for each of the 6 release fields a
 * 4-byte BIG-ENDIAN length prefix followed by the UTF-8 field bytes. Verify
 * check ORDER and the asymmetric boundary operators (depth `<`, staleness `>`,
 * activate `depth<1`) are load-bearing.
 */
#include "verifier/release_anchor_verifier.h"

#include <stdlib.h>
#include <string.h>

#include "common/bytes.h"
#include "crypto/hash.h"

/* ---- deny reason wire strings ------------------------------------------- */

const char *deny_reason_str(deny_reason_t reason) {
    switch (reason) {
        case DENY_NONE:                   return "";
        case DENY_UNKNOWN_PUBLISHER:      return "unknown-publisher";
        case DENY_SCOPE_NOT_IN_NAMESPACE: return "scope-not-in-namespace";
        case DENY_ANNOUNCE_UNCONFIRMED:   return "announce-unconfirmed";
        case DENY_INSUFFICIENT_DEPTH:     return "insufficient-depth";
        case DENY_ANNOUNCE_NO_MERKLE_PROOF: return "announce-no-merkle-proof";
        case DENY_ACTIVATE_UNCONFIRMED:   return "activate-unconfirmed";
        case DENY_ACTIVATE_NO_MERKLE_PROOF: return "activate-no-merkle-proof";
        case DENY_STALE_CHAIN:            return "stale-chain";
        case DENY_BUNDLE_HASH_MISMATCH:   return "bundle-hash-mismatch";
        case DENY_FILESET_ROOT_MISMATCH:  return "fileset-root-mismatch";
        case DENY_DIGEST_MISMATCH:        return "digest-mismatch";
        case DENY_INSUFFICIENT_QUORUM:    return "insufficient-quorum";
        case DENY_DUPLICATE_ATTESTOR:     return "duplicate-attestor";
        case DENY_ATTESTOR_NOT_IN_SET:    return "attestor-not-in-set";
        case DENY_BAD_ATTESTATION:        return "bad-attestation";
        case DENY_RELEASE_REVOKED:        return "release-revoked";
    }
    return "";
}

/* ---- canonical digest --------------------------------------------------- */

int compute_activate_digest(const char *genesis_outpoint, const char *scope,
                            const char *version, const char *bundle_hash,
                            const char *file_set_root, const char *announce_txid,
                            char **out) {
    if (!out) return BNS_EINVAL;
    *out = NULL;
    if (!genesis_outpoint || !scope || !version || !bundle_hash ||
        !file_set_root || !announce_txid) {
        return BNS_EINVAL;
    }

    const char *fields[6] = {
        genesis_outpoint, scope, version,
        bundle_hash, file_set_root, announce_txid,
    };

    /* Build the exact preimage, then a single SHA256 over it (mirrors the TS
     * incremental createHash('sha256') updates). */
    byte_buf_t pre;
    byte_buf_init(&pre);
    int rc = BNS_OK;

    /* Domain tag: 16 ASCII bytes, no separator, no NUL. */
    rc = byte_buf_append(&pre, BONSAI_ACTIVATE_DOMAIN,
                         sizeof(BONSAI_ACTIVATE_DOMAIN) - 1);

    for (size_t i = 0; i < 6 && rc == BNS_OK; i++) {
        size_t len = strlen(fields[i]);
        /* writeUInt32BE — 4-byte big-endian length prefix. */
        uint32_t n = (uint32_t)len;
        uint8_t lp[4] = {
            (uint8_t)((n >> 24) & 0xff),
            (uint8_t)((n >> 16) & 0xff),
            (uint8_t)((n >> 8) & 0xff),
            (uint8_t)(n & 0xff),
        };
        rc = byte_buf_append(&pre, lp, 4);
        if (rc == BNS_OK) rc = byte_buf_append(&pre, fields[i], len);
    }
    if (rc != BNS_OK) {
        byte_buf_free(&pre);
        return rc;
    }

    uint8_t digest[BONSAI_SHA256_LEN];
    sha256(pre.data, pre.len, digest);
    byte_buf_free(&pre);

    char *hex = malloc(BONSAI_SHA256_LEN * 2 + 1);
    if (!hex) return BNS_ENOMEM;
    static const char hexc[] = "0123456789abcdef";
    for (int i = 0; i < BONSAI_SHA256_LEN; i++) {
        hex[i * 2]     = hexc[(digest[i] >> 4) & 0xf];
        hex[i * 2 + 1] = hexc[digest[i] & 0xf];
    }
    hex[BONSAI_SHA256_LEN * 2] = '\0';
    *out = hex;
    return BNS_OK;
}

/* ---- verifier ----------------------------------------------------------- */

struct release_anchor_verifier_s {
    const spv_client_t                 *spv;
    const attestation_verifier_t       *attestor;
    const release_revocation_oracle_t  *revocation;
};

int release_anchor_verifier_new(const spv_client_t *spv,
                                const attestation_verifier_t *attestor,
                                const release_revocation_oracle_t *revocation,
                                release_anchor_verifier_t **out) {
    if (!out) return BNS_EINVAL;
    *out = NULL;
    if (!spv || !attestor || !revocation) return BNS_EINVAL;

    release_anchor_verifier_t *v = calloc(1, sizeof(*v));
    if (!v) return BNS_ENOMEM;
    v->spv = spv;
    v->attestor = attestor;
    v->revocation = revocation;
    *out = v;
    return BNS_OK;
}

void release_anchor_verifier_free(release_anchor_verifier_t *v) {
    free(v);
}

/* constEq — length-checked, then constant-time-ish XOR equality. Mirrors the TS
 * helper (charCodeAt XOR accumulation over equal-length inputs). */
static bool const_eq(const char *a, const char *b) {
    if (!a || !b) return false;
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return false;
    int diff = 0;
    for (size_t i = 0; i < la; i++) {
        diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
    }
    return diff == 0;
}

/* scopeInNamespace: ns ends with '*' && scope startsWith(ns minus '*'), OR
 * scope === ns. Single trailing '*', prefix-only. */
static bool scope_in_namespace(const char *scope,
                               const char *const *namespace_scopes,
                               size_t num) {
    for (size_t i = 0; i < num; i++) {
        const char *ns = namespace_scopes[i];
        if (!ns) continue;
        size_t nl = strlen(ns);
        if (nl > 0 && ns[nl - 1] == '*') {
            size_t prefix = nl - 1;
            if (strncmp(scope, ns, prefix) == 0) return true;
        } else {
            if (strcmp(scope, ns) == 0) return true;
        }
    }
    return false;
}

static void deny(verify_result_t *r, deny_reason_t reason, const char *detail) {
    r->ok = false;
    r->reason = reason;
    r->detail = detail;
}

int release_anchor_verifier_verify(release_anchor_verifier_t *v,
                                   const publish_ref_t *ref,
                                   const local_artifact_t *local,
                                   const trusted_publisher_t *publisher,
                                   const verify_opts_t *opts,
                                   verify_result_t *out_result) {
    if (!v || !ref || !local || !out_result) return BNS_EINVAL;

    out_result->ok = false;
    out_result->reason = DENY_NONE;
    out_result->detail = NULL;

    bool fail_closed = true;
    if (opts && opts->has_fail_closed) fail_closed = opts->fail_closed;

    /* 1. Publisher must be in the trust set, by genesis outpoint. */
    if (!publisher ||
        strcmp(publisher->genesis_outpoint, ref->genesis_outpoint) != 0) {
        deny(out_result, DENY_UNKNOWN_PUBLISHER,
             "no trusted publisher for genesisOutpoint");
        return BNS_OK;
    }

    /* 2. Scope must fall within the publisher's namespace. */
    if (!scope_in_namespace(ref->scope, publisher->namespace_scopes,
                            publisher->num_namespace_scopes)) {
        deny(out_result, DENY_SCOPE_NOT_IN_NAMESPACE,
             "scope not in namespace");
        return BNS_OK;
    }

    /* 3. Artifact identity: the bytes we hold must equal what was announced. */
    if (!const_eq(local->bundle_hash, ref->bundle_hash)) {
        deny(out_result, DENY_BUNDLE_HASH_MISMATCH, NULL);
        return BNS_OK;
    }
    if (!const_eq(local->file_set_root, ref->file_set_root)) {
        deny(out_result, DENY_FILESET_ROOT_MISMATCH, NULL);
        return BNS_OK;
    }

    /* 3b. Digest binding: the digest the attestors signed must be the canonical
     *     commitment to THIS release's fields. */
    {
        char *computed = NULL;
        int rc = compute_activate_digest(ref->genesis_outpoint, ref->scope,
                                         ref->version, ref->bundle_hash,
                                         ref->file_set_root, ref->announce_txid,
                                         &computed);
        if (rc != BNS_OK) return rc;
        bool eq = const_eq(ref->activate_digest, computed);
        free(computed);
        if (!eq) {
            deny(out_result, DENY_DIGEST_MISMATCH,
                 "activateDigest does not commit to this release");
            return BNS_OK;
        }
    }

    /* 4. Publication delay: ANNOUNCE confirmed at depth >= minDepth with a real
     *    Merkle inclusion proof. A failed/unknown lookup is ALWAYS a deny — no
     *    fail-open mode for the publication event. */
    spv_lookup_t announce;
    {
        bool found = false;
        int rc = v->spv->lookup(v->spv->ctx, ref->announce_txid,
                                &announce, &found);
        /* .catch(() => null): any error folds to null => deny. */
        if (rc != BNS_OK || !found) {
            deny(out_result, DENY_ANNOUNCE_UNCONFIRMED, NULL);
            return BNS_OK;
        }
    }
    if (!announce.merkle_verified) {
        deny(out_result, DENY_ANNOUNCE_NO_MERKLE_PROOF, NULL);
        return BNS_OK;
    }
    if (announce.depth < publisher->min_depth) {
        deny(out_result, DENY_INSUFFICIENT_DEPTH, "depth < required");
        return BNS_OK;
    }

    /* 4b. The ACTIVATE must itself be a mined, Merkle-proven event.
     *
     * KNOWN LIMITATION (review finding #13): this proves only that `activate_txid`
     * names SOME mined, Merkle-proven tx — it does NOT prove that tx's CONTENT commits
     * `activate_digest`. compute_activate_digest() omits activate_txid (and the SPV
     * lookup returns only depth/merkle_verified, never the tx payload), so a caller
     * holding a valid announce + quorum can point activate_txid at any confirmed
     * mainnet tx and this step passes. Closing it requires binding the activate tx's
     * OUTPUT to activate_digest (option b): extend spv_lookup_t to carry the tx's
     * OP_RETURN and assert it == activate_digest here. That is deliberately deferred —
     * folding activate_txid into compute_activate_digest() would diverge from the TS
     * producer's shared digest format (it "mirrors the TS createHash updates") and
     * break C<->TS parity; the real fix is an SPV-interface change, out of scope here. */
    spv_lookup_t activate;
    {
        bool found = false;
        int rc = v->spv->lookup(v->spv->ctx, ref->activate_txid,
                                &activate, &found);
        if (rc != BNS_OK || !found || activate.depth < 1) {
            deny(out_result, DENY_ACTIVATE_UNCONFIRMED, NULL);
            return BNS_OK;
        }
    }
    if (!activate.merkle_verified) {
        deny(out_result, DENY_ACTIVATE_NO_MERKLE_PROOF, NULL);
        return BNS_OK;
    }

    /* 5. Freshness: the chain view must not be stale. */
    int64_t tip;
    {
        int rc = v->spv->tip_height(v->spv->ctx, &tip);
        if (rc != BNS_OK) {
            if (fail_closed) {
                deny(out_result, DENY_STALE_CHAIN,
                     "tip height unavailable (fail-closed)");
                return BNS_OK;
            }
            tip = announce.block_height + announce.depth;
        }
    }
    int64_t staleness = tip - (announce.block_height + announce.depth);
    if (staleness > publisher->max_staleness) {
        deny(out_result, DENY_STALE_CHAIN, "staleness > maxStaleness");
        return BNS_OK;
    }

    /* 6. Threshold attestation: M-of-N over the activate digest, counted ONLY
     *    from the publisher's charter attestor set. ANY invalid/out-of-set/
     *    duplicate attestation rejects the WHOLE release (does not skip). */
    {
        int64_t valid = 0;
        for (size_t i = 0; i < ref->num_attestations; i++) {
            const release_attestation_t *att = &ref->attestations[i];

            /* duplicate check: seen set over prior attestor pubkeys. */
            for (size_t j = 0; j < i; j++) {
                if (strcmp(ref->attestations[j].attestor_pubkey,
                           att->attestor_pubkey) == 0) {
                    deny(out_result, DENY_DUPLICATE_ATTESTOR,
                         att->attestor_pubkey);
                    return BNS_OK;
                }
            }

            /* membership in the charter attestor set. */
            bool in_set = false;
            for (size_t k = 0; k < publisher->num_attestor_pubkeys; k++) {
                if (strcmp(publisher->attestor_pubkeys[k],
                           att->attestor_pubkey) == 0) {
                    in_set = true;
                    break;
                }
            }
            if (!in_set) {
                deny(out_result, DENY_ATTESTOR_NOT_IN_SET,
                     att->attestor_pubkey);
                return BNS_OK;
            }

            bool ok = false;
            int rc = v->attestor->verify(v->attestor->ctx,
                                         att->attestor_pubkey,
                                         ref->activate_digest,
                                         att->signature, &ok);
            /* A non-BNS_OK return is treated as a failed attestation. */
            if (rc != BNS_OK || !ok) {
                deny(out_result, DENY_BAD_ATTESTATION, att->attestor_pubkey);
                return BNS_OK;
            }
            valid++;
        }
        if (valid < publisher->min_quorum) {
            deny(out_result, DENY_INSUFFICIENT_QUORUM, "valid < required");
            return BNS_OK;
        }
    }

    /* 7. Revocation / invalidation. */
    {
        bool revoked = false;
        int rc = v->revocation->is_release_revoked(v->revocation->ctx,
                                                   ref->genesis_outpoint,
                                                   ref->scope, ref->version,
                                                   &revoked);
        if (rc != BNS_OK) {
            if (fail_closed) {
                deny(out_result, DENY_RELEASE_REVOKED,
                     "revocation state unavailable (fail-closed)");
                return BNS_OK;
            }
            revoked = false;
        }
        if (revoked) {
            deny(out_result, DENY_RELEASE_REVOKED, NULL);
            return BNS_OK;
        }
    }

    out_result->ok = true;
    out_result->reason = DENY_NONE;
    out_result->detail = NULL;
    return BNS_OK;
}
