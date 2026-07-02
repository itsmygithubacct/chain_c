/*
 * release_anchor_verifier.h — the Pillar A consumer/Brain gate: install requires
 * an SPV-verified, aged (depth>=minDepth), threshold-attested (M-of-N over the
 * charter attestor set), un-revoked release anchor or it fails closed. Pure
 * policy over injected SpvClient / AttestationVerifier / RevocationOracle
 * vtables; also defines computeActivateDigest, the canonical digest both signer
 * and verifier must agree on.
 *
 * TS origin: src/verifier/releaseAnchorVerifier.ts (TrustedPublisher, SpvLookup,
 * SpvClient, AttestationVerifier, RevocationOracle, PublishRef, LocalArtifact,
 * DenyReason, VerifyResult, VerifyOpts, ReleaseAnchorVerifier,
 * computeActivateDigest).
 *
 * BYTE-EXACTNESS PINS (module notes — load-bearing):
 *  - computeActivateDigest: SHA256 ctx; update(ASCII "ARP1_ACTIVATE_V1") [16
 *    bytes domain tag, NO separators]; then for each field IN ORDER
 *    [genesisOutpoint, scope, version, bundleHash, fileSetRoot, announceTxid]:
 *    write a 4-byte BIG-ENDIAN length prefix (UInt32BE of UTF-8 byte length),
 *    then the UTF-8 field bytes. Return lowercase hex. ONLY these 6 fields are
 *    committed (NOT activateTxid, NOT attestations).
 *  - VERIFY check ORDER is load-bearing (tests assert the exact DenyReason for a
 *    given malformed ref) — see the ordered list in the verify() doc-comment.
 *  - ASYMMETRIC bounds: announce requires depth >= minDepth (insufficient-depth
 *    uses '<'); activate requires depth >= 1 (any confirmation); staleness =
 *    tip - (announce.blockHeight + announce.depth) and staleness > maxStaleness
 *    (uses '>') => stale-chain.
 *  - FAIL-CLOSED: spv.lookup errors are ALWAYS a deny (no fail-open for the
 *    publication event); only tipHeight and isReleaseRevoked honor
 *    failClosed=false. failClosed defaults TRUE.
 *  - ATTESTATION quorum: ANY duplicate / out-of-set / bad attestation rejects
 *    the WHOLE release (does not skip); after the loop valid<minQuorum =>
 *    insufficient-quorum.
 *  - scopeInNamespace: ns ends with '*' && scope startsWith(ns minus '*'), OR
 *    scope === ns. Prefix-only single trailing '*'.
 *  - constEq: length-checked then constant-time-ish XOR equality.
 */
#ifndef BONSAI_VERIFIER_RELEASE_ANCHOR_VERIFIER_H
#define BONSAI_VERIFIER_RELEASE_ANCHOR_VERIFIER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"

/* Canonical digest domain tag (16 bytes ASCII, no separator). TS constant. */
#define BONSAI_ACTIVATE_DOMAIN "ARP1_ACTIVATE_V1"

/* ---- policy / data types ------------------------------------------------ */

/* One trusted-publisher policy row. `namespace_scopes`/`attestor_pubkeys` are
 * borrowed arrays of borrowed strings owned by the caller for the verify() call.
 * TS: releaseAnchorVerifier.ts::TrustedPublisher. */
typedef struct {
    const char        *label;
    const char        *genesis_outpoint;
    const char *const *namespace_scopes;  size_t num_namespace_scopes;
    int64_t            min_depth;
    int64_t            min_quorum;
    const char *const *attestor_pubkeys;  size_t num_attestor_pubkeys;
    int64_t            max_staleness;
} trusted_publisher_t;

/* SPV result for a txid. TS: releaseAnchorVerifier.ts::SpvLookup. */
typedef struct {
    int64_t depth;          /* confirmation depth (0 = mempool) */
    int64_t block_height;   /* mining block height              */
    bool    merkle_verified;/* whether a Merkle proof was checked */
} spv_lookup_t;

/* Injected SPV provider vtable. TS: releaseAnchorVerifier.ts::SpvClient. */
typedef struct spv_client_s spv_client_t;
struct spv_client_s {
    void *ctx;

    /* lookup(txid): sets *out_found=false to mirror TS null (unknown txid). On a
     * found tx fills *out. The TS wraps this in .catch(()=>null): the IMPL of
     * the verifier treats ANY non-BNS_OK return here as null => deny. So callers
     * may return non-BNS_OK to signal an error; it is folded into a deny.
     * TS: SpvClient.lookup. */
    int (*lookup)(void *ctx, const char *txid, spv_lookup_t *out, bool *out_found);

    /* tipHeight(): current best-chain tip height into *out_tip. A non-BNS_OK
     * return is the "throw" path honoring VerifyOpts.failClosed.
     * TS: SpvClient.tipHeight. */
    int (*tip_height)(void *ctx, int64_t *out_tip);
};

/* Pluggable single-signature verifier over the activate digest (Rabin impl in
 * rabin_attestor.h). Pure predicate; returns the verify result via *out_ok.
 * A non-BNS_OK return is treated as a failed attestation (fail-closed).
 * TS: releaseAnchorVerifier.ts::AttestationVerifier. */
typedef struct attestation_verifier_s attestation_verifier_t;
struct attestation_verifier_s {
    void *ctx;
    /* verify(attestorPubkey, digestHex, signature) -> *out_ok.
     * TS: AttestationVerifier.verify. */
    int (*verify)(void *ctx, const char *attestor_pubkey,
                  const char *digest_hex, const char *signature, bool *out_ok);
};

/* Indexer-backed revocation/invalidation check for an exact release. A non-
 * BNS_OK return is the "throw" path honoring VerifyOpts.failClosed.
 * TS: releaseAnchorVerifier.ts::RevocationOracle (isReleaseRevoked). */
typedef struct release_revocation_oracle_s release_revocation_oracle_t;
struct release_revocation_oracle_s {
    void *ctx;
    /* isReleaseRevoked(genesisOutpoint, scope, version) -> *out_revoked. */
    int (*is_release_revoked)(void *ctx, const char *genesis_outpoint,
                              const char *scope, const char *version,
                              bool *out_revoked);
};

/* One attestation in a PublishRef. TS: PublishRef.attestations[] element. */
typedef struct {
    const char *attestor_pubkey;
    const char *signature;
} release_attestation_t;

/* The release anchor presented by the installer. All strings borrowed for the
 * verify() call. TS: releaseAnchorVerifier.ts::PublishRef. */
typedef struct {
    const char                  *genesis_outpoint;
    const char                  *scope;
    const char                  *version;
    const char                  *bundle_hash;
    const char                  *file_set_root;
    const char                  *announce_txid;
    const char                  *activate_txid;
    const char                  *activate_digest;
    const release_attestation_t *attestations;  size_t num_attestations;
} publish_ref_t;

/* What the installer locally computed about the bytes it holds.
 * TS: releaseAnchorVerifier.ts::LocalArtifact. */
typedef struct {
    const char *bundle_hash;
    const char *file_set_root;
} local_artifact_t;

/* The closed set of fail-fast deny reasons. TS: releaseAnchorVerifier.ts::
 * DenyReason (string union -> C enum). DENY_NONE is the ok=true sentinel. */
typedef enum {
    DENY_NONE = 0,
    DENY_UNKNOWN_PUBLISHER,        /* 'unknown-publisher'        */
    DENY_SCOPE_NOT_IN_NAMESPACE,   /* 'scope-not-in-namespace'   */
    DENY_ANNOUNCE_UNCONFIRMED,     /* 'announce-unconfirmed'     */
    DENY_INSUFFICIENT_DEPTH,       /* 'insufficient-depth'       */
    DENY_ANNOUNCE_NO_MERKLE_PROOF, /* 'announce-no-merkle-proof' */
    DENY_ACTIVATE_UNCONFIRMED,     /* 'activate-unconfirmed'     */
    DENY_ACTIVATE_NO_MERKLE_PROOF, /* 'activate-no-merkle-proof' */
    DENY_STALE_CHAIN,              /* 'stale-chain'              */
    DENY_BUNDLE_HASH_MISMATCH,     /* 'bundle-hash-mismatch'     */
    DENY_FILESET_ROOT_MISMATCH,    /* 'fileset-root-mismatch'    */
    DENY_DIGEST_MISMATCH,          /* 'digest-mismatch'          */
    DENY_INSUFFICIENT_QUORUM,      /* 'insufficient-quorum'      */
    DENY_DUPLICATE_ATTESTOR,       /* 'duplicate-attestor'       */
    DENY_ATTESTOR_NOT_IN_SET,      /* 'attestor-not-in-set'      */
    DENY_BAD_ATTESTATION,          /* 'bad-attestation'          */
    DENY_RELEASE_REVOKED           /* 'release-revoked'          */
} deny_reason_t;

/* Stable lowercase wire string for a deny reason (the TS union member text).
 * Returns "" for DENY_NONE. */
const char *deny_reason_str(deny_reason_t reason);

/* Verification outcome; reason != DENY_NONE only when ok=false. `detail` is an
 * optional extra (borrowed static or empty). TS: releaseAnchorVerifier.ts::
 * VerifyResult. */
typedef struct {
    bool          ok;
    deny_reason_t reason;
    const char   *detail;   /* NULL/"" when none */
} verify_result_t;

/* Verify options. fail_closed defaults TRUE (has_fail_closed=false => treat as
 * true). TS: releaseAnchorVerifier.ts::VerifyOpts. */
typedef struct {
    bool fail_closed; bool has_fail_closed;
} verify_opts_t;

/* Opaque verifier handle binding the three injected vtables.
 * TS: releaseAnchorVerifier.ts::ReleaseAnchorVerifier. */
typedef struct release_anchor_verifier_s release_anchor_verifier_t;

/* ---- canonical digest --------------------------------------------------- */

/* computeActivateDigest: domain tag + 6 length-prefixed fields (see header
 * note). Writes a freshly malloc'd lowercase-hex SHA256 string to *out (caller
 * frees). All six field pointers must be non-NULL.
 * TS: releaseAnchorVerifier.ts::computeActivateDigest. BNS_OK / BNS_ENOMEM. */
int compute_activate_digest(const char *genesis_outpoint, const char *scope,
                            const char *version, const char *bundle_hash,
                            const char *file_set_root, const char *announce_txid,
                            char **out);

/* ---- verifier ----------------------------------------------------------- */

/* Construct a verifier over the three borrowed vtables (must outlive it). *out
 * freed via release_anchor_verifier_free.
 * TS: new ReleaseAnchorVerifier(spv, attestor, revocation).
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int release_anchor_verifier_new(const spv_client_t *spv,
                                const attestation_verifier_t *attestor,
                                const release_revocation_oracle_t *revocation,
                                release_anchor_verifier_t **out);

/* Release a verifier (NULL-safe; does not free the injected vtables). */
void release_anchor_verifier_free(release_anchor_verifier_t *v);

/* Run the ordered fail-fast/fail-closed pipeline and return the FIRST failure or
 * {ok:true}. `publisher` may be NULL (=> unknown-publisher). `opts` may be NULL
 * (fail_closed defaults true). Writes the outcome to *out_result.
 *
 * ORDER (load-bearing): 1) publisher non-NULL && genesisOutpoint match else
 * unknown-publisher. 2) scopeInNamespace else scope-not-in-namespace.
 * 3) constEq(local.bundleHash, ref.bundleHash) else bundle-hash-mismatch;
 *    constEq(local.fileSetRoot, ref.fileSetRoot) else fileset-root-mismatch.
 * 3b) constEq(ref.activateDigest, computeActivateDigest(ref)) else
 *    digest-mismatch. 4) announce = spv.lookup(announceTxid) (err->null):
 *    null => announce-unconfirmed; !merkleVerified => announce-no-merkle-proof;
 *    depth<minDepth => insufficient-depth. 4b) activate = spv.lookup(activateTxid):
 *    (!found || depth<1) => activate-unconfirmed; !merkleVerified =>
 *    activate-no-merkle-proof. 5) tip = spv.tipHeight() (err: failClosed =>
 *    stale-chain else tip = announce.blockHeight+announce.depth); staleness =
 *    tip - (announce.blockHeight+announce.depth); staleness>maxStaleness =>
 *    stale-chain. 6) attestation quorum loop. 7) revoked =
 *    isReleaseRevoked(...) (err: failClosed => release-revoked else false);
 *    revoked => release-revoked. Else {ok:true}.
 *
 * This call itself returns BNS_OK in the normal case (all branches fold into a
 * verify_result_t); BNS_ENOMEM only on an internal digest-build allocation
 * failure. TS: ReleaseAnchorVerifier.verify. */
int release_anchor_verifier_verify(release_anchor_verifier_t *v,
                                   const publish_ref_t *ref,
                                   const local_artifact_t *local,
                                   const trusted_publisher_t *publisher,
                                   const verify_opts_t *opts,
                                   verify_result_t *out_result);

#endif /* BONSAI_VERIFIER_RELEASE_ANCHOR_VERIFIER_H */
