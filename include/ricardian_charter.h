/*
 * ricardian_charter.h — the single source of truth for an identity's policy
 * parameters and the byte-exact Ricardian contract (prose ‖ canonical binding).
 *
 * Parses the delimited key=value policy block out of the human-readable charter
 * prose, defines the canonical byte layout that IS the Ricardian contract,
 * computes ricardianHash over it, and signs/verifies that exact byte string with
 * the issuer's (Elder's) ECDSA key — closing the Grigg {Prose, Parameters, Code,
 * Signatures} loop so the thing hashed == the thing signed == the thing read.
 *
 * TS origin: src/ricardianCharter.ts (CharterParams, parseCharterParams,
 * DeploymentBinding, canonicalJSON, canonicalContractBytes, computeRicardianHash,
 * CharterSignature, signCharter, verifyCharterSignature, assertParamsMatchProse).
 *
 * ===========================  BYTE-FRAGILE PREIMAGE  ========================
 * canonicalContractBytes(prose, binding) is the EXACT preimage (src/ricardian-
 * Charter.ts notes — any drift breaks ricardianHash AND the signature):
 *   canonicalContractBytes = prose
 *                          + "\n\n--- DEPLOYMENT BINDING (canonical) ---\n"
 *                          + canonicalJSON(binding)
 *                          + "\n"
 *  (1) The separator string and the trailing newline are EXACT preimage bytes —
 *      reproduce them verbatim, including the two leading newlines and the
 *      literal "--- DEPLOYMENT BINDING (canonical) ---".
 *  (2) `prose` is hashed VERBATIM: no CRLF->LF, trailing-whitespace, or BOM
 *      normalization — read the prose file as raw bytes.
 *  (3) canonicalJSON sorts keys ASCENDING BY BYTE VALUE (JS Array.sort is
 *      lexicographic UTF-16 == byte order for these ASCII keys), joins
 *      jsonStr(k)+':'+jsonStr(v) with ',' inside '{' '}', NO spaces, with full
 *      ECMA-262 JSON string escaping on every key and value (see json.h).
 *  (4) Binding values are STRINGIFIED BEFORE hashing: pubkeys/Sha256 are
 *      LOWERCASE HEX strings; Rabin pubkeys and bigint slashing numbers are
 *      DECIMAL strings (RabinPubKey is a bigint => DECIMAL, NOT hex — getting
 *      this wrong silently changes the canonical JSON and the hash).
 *  (5) ECDSA signs the ALREADY-SHA256'd 32-byte digest DIRECTLY (single hash,
 *      NOT Bitcoin double-SHA256), low-S DER (see crypto/ecdsa.h). Do NOT
 *      double-hash the charter.
 *  (6) ricardianHash is compared case-insensitively in verify; emit LOWERCASE.
 *  (7) The .sig sidecar JSON is JSON.stringify(sig, null, 2) + '\n' (insertion
 *      order, see json.h json_print_pretty2_nl) — not the canonical serializer.
 *  (8) BigInt params/targets are arbitrary precision — modeled as bn_t, never int64.
 * ============================================================================
 */
#ifndef BONSAI_RICARDIAN_CHARTER_H
#define BONSAI_RICARDIAN_CHARTER_H

#include <stddef.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/bignum.h"
#include "crypto/ecdsa.h"

/* The fixed canonical-binding separator inserted between prose and the JSON.
 * EXACT preimage bytes — note the two leading '\n'. TS: ricardianCharter.ts. */
#define BONSAI_CHARTER_BINDING_SEPARATOR \
    "\n\n--- DEPLOYMENT BINDING (canonical) ---\n"

/* The signature algorithm tag carried in the .sig sidecar. TS: 'ECDSA-SHA256'. */
#define BONSAI_CHARTER_ALGO "ECDSA-SHA256"

/* The five machine-parsable policy terms, all positive arbitrary-precision
 * integers parsed from the prose. Owns its bn_t handles; charter_params_free
 * releases them. TS: src/ricardianCharter.ts::CharterParams. */
typedef struct {
    bn_t *per_tx_limit;          /* perTxLimit          */
    bn_t *daily_limit;           /* dailyLimit          */
    bn_t *window_duration;       /* windowDuration      */
    bn_t *graduation_threshold;  /* graduationThreshold */
    bn_t *validator_threshold;   /* validatorThreshold  */
} charter_params_t;

/* The six binding fields, each already STRINGIFIED to its canonical text form
 * (hex for pubkeys/Sha256, DECIMAL for Rabin/bigint) — these exact strings are
 * what canonicalJSON serializes. Strings are owned; deployment_binding_free
 * releases them. TS: src/ricardianCharter.ts::DeploymentBinding. */
typedef struct {
    char *agent_pubkey;                 /* agentPubKey (66-hex)                  */
    char *designated_validator_pubkey;  /* designatedValidatorPubKey (DECIMAL n) */
    char *validator_rabin_pubkey;       /* validatorRabinPubKey (DECIMAL n)      */
    char *max_slashing_target;          /* maxSlashingTarget (DECIMAL)           */
    char *min_slash_confirmations;      /* minSlashConfirmations (DECIMAL)       */
    char *initial_slash_checkpoint_hash;/* initialSlashCheckpointHash (64-hex)   */
} deployment_binding_t;

/* Self-contained issuer-signature sidecar. All strings owned;
 * charter_signature_free releases them (including the nested binding).
 * TS: src/ricardianCharter.ts::CharterSignature. */
typedef struct {
    char                 *algo;          /* 'ECDSA-SHA256'                        */
    char                 *issuer_pubkey; /* issuer compressed-pubkey hex (66)     */
    char                 *signature;     /* DER ECDSA signature, lowercase hex    */
    char                 *ricardian_hash;/* the ricardianHash, lowercase 64-hex   */
    deployment_binding_t  binding;       /* the binding (owned copy)              */
} charter_signature_t;

/* Result of verifyCharterSignature: ok + optional reason string. `reason` is a
 * borrowed pointer to a static string constant (NULL when ok). TS:
 * { ok: boolean; reason?: string }. */
typedef struct {
    bool        ok;
    const char *reason; /* NULL on success; static reason text on failure */
} charter_verify_result_t;

/* ---- lifecycle ---------------------------------------------------------- */

/* Release the five bn_t members and zero the struct (NULL-safe). */
void charter_params_free(charter_params_t *p);

/* Release the six owned strings and zero the struct (NULL-safe). */
void deployment_binding_free(deployment_binding_t *b);

/* Release all owned members incl. the nested binding (NULL-safe). */
void charter_signature_free(charter_signature_t *s);

/* ---- parse -------------------------------------------------------------- */

/* Extract the begin/end-delimited policy block from `prose_text`, parse its
 * key=value integer lines, and fill *out (caller frees via charter_params_free).
 * Throws loudly (BNS_EPARSE, with a verbatim message in `ctx`) on a malformed
 * block, unparseable line, duplicate key, missing key, non-positive value, or
 * unknown key — matching the TS error strings.
 * TS: src/ricardianCharter.ts::parseCharterParams.
 * BNS_OK / BNS_EPARSE / BNS_ENOMEM. */
int parse_charter_params(const char *prose_text, charter_params_t *out,
                         bonsai_err_ctx *ctx);

/* Single-source-of-truth guard: error if any of the five params differ between
 * the parsed-from-prose values and the values about to be locked into the
 * contract constructor. TS: src/ricardianCharter.ts::assertParamsMatchProse.
 * BNS_OK / BNS_EBINDING (mismatch, message in ctx). */
int assert_params_match_prose(const charter_params_t *parsed,
                              const charter_params_t *constructed,
                              bonsai_err_ctx *ctx);

/* ---- canonical serialization -------------------------------------------- */

/* Serialize the binding as canonicalJSON (sorted keys, escaped, no spaces) into
 * a freshly malloc'd NUL-terminated string (*out; caller frees). Delegates to
 * json.h canonical_json over the six already-stringified fields.
 * TS: src/ricardianCharter.ts::canonicalJSON(binding).
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int charter_canonical_json(const deployment_binding_t *binding, char **out);

/* Build the EXACT Ricardian-contract preimage bytes appended to `out` (init'd):
 *   prose_text || BONSAI_CHARTER_BINDING_SEPARATOR || canonicalJSON(binding) || "\n"
 * `prose_text` is treated as raw bytes (NUL-terminated source; if the prose can
 * contain embedded NULs use the explicit-length builder in the .c). TS:
 * src/ricardianCharter.ts::canonicalContractBytes. BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int canonical_contract_bytes(const char *prose_text,
                             const deployment_binding_t *binding,
                             byte_buf_t *out);

/* sha256(canonical_contract_bytes(prose,binding)) as a freshly malloc'd 64-char
 * LOWERCASE hex Sha256 string (*out_hex; caller frees).
 * TS: src/ricardianCharter.ts::computeRicardianHash.
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int compute_ricardian_hash(const char *prose_text,
                           const deployment_binding_t *binding,
                           char **out_hex);

/* ---- sign / verify ------------------------------------------------------ */

/* SHA256 the canonical_contract_bytes, sign that 32-byte digest DIRECTLY (single
 * hash, low-S DER) with the issuer's ECDSA private key, and fill *out_sig with
 * algo='ECDSA-SHA256', issuer compressed-pubkey hex, DER-hex signature, the
 * lowercase ricardianHash, and a copy of the binding (caller frees via
 * charter_signature_free). TS: src/ricardianCharter.ts::signCharter.
 * BNS_OK / BNS_ECRYPTO / BNS_ENOMEM. */
int sign_charter(const char *prose_text, const deployment_binding_t *binding,
                 const ecdsa_key_t *issuer_priv, charter_signature_t *out_sig);

/* Recompute the hash from prose ‖ sig->binding, check it equals sig->ricardian_hash
 * (case-insensitive), then ECDSA-verify the DER signature over
 * SHA256(canonicalContractBytes) under sig->issuer_pubkey. Fills *out with
 * {ok, reason}. Never returns a fallible code for an ordinary verification
 * failure — the outcome is in *out (mirrors the TS { ok, reason } object); the
 * int return reports only allocation/parse faults. TS:
 * src/ricardianCharter.ts::verifyCharterSignature.
 * BNS_OK (result in *out) / BNS_ENOMEM. */
int verify_charter_signature(const char *prose_text,
                             const charter_signature_t *sig,
                             charter_verify_result_t *out);

#endif /* BONSAI_RICARDIAN_CHARTER_H */
