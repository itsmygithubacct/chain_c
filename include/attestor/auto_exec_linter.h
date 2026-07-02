/*
 * auto_exec_linter.h — ARP-1's first attestor class: a deterministic lint over a
 * release's total-file-set manifest for known auto-execution vectors (IDE/agent
 * config that runs on folder-open) plus package.json install-time script hooks.
 * The AutoExecLinterAttestor signs the self-computed activate digest under a
 * strictly-increasing Rabin sequence number ONLY if the lint is clean.
 *
 * TS origin: src/attestor/autoExecLinter.ts (ManifestEntry, LintViolation,
 * lintManifest, ReleaseFields, AttestResult, AutoExecLinterAttestor) over
 * verifier/rabin_attestor.h + verifier/release_anchor_verifier.h.
 *
 * BYTE-EXACTNESS PINS (module notes — load-bearing for security AND violation
 * output order):
 *  - normalizeSegments(path): (1) all '\\'->'/'; (2) strip a SINGLE leading
 *    './'; (3) lowercase WHOLE string; (4) split on '/'; (5) per segment strip
 *    trailing [. ]+ run. Order matters (lowercase before split; trailing strip
 *    per segment).
 *  - matchVector: suffix loop at ANY depth; per i join segments[i..] with '/';
 *    exact (FORBIDDEN_EXACT) checked BEFORE prefix (FORBIDDEN_PREFIXES); returns
 *    FIRST match. Lists are stored lowercase.
 *  - package.json hook check: last normalized segment == "package.json" AND
 *    content present; for each hook in PACKAGE_JSON_HOOKS (in this order:
 *    preinstall, install, postinstall, prepare, prepublish), key PRESENCE in
 *    scripts (the `in` operator — empty value still counts) => violation;
 *    JSON parse failure => 'unparseable-package-json' (fail-closed).
 *  - lintManifest order: input entry order; per entry the matchVector violation
 *    (if any) is pushed BEFORE the install-hook/unparseable violations.
 *  - attest(): seq consumed (incremented) ONLY on the clean/sign path; startSeq
 *    < 1 throws in the constructor; seq < 2^63.
 */
#ifndef BONSAI_ATTESTOR_AUTO_EXEC_LINTER_H
#define BONSAI_ATTESTOR_AUTO_EXEC_LINTER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "verifier/rabin_attestor.h"            /* rabin_attestor_key_t */
#include "verifier/release_anchor_verifier.h"   /* compute_activate_digest */

/* The package.json install-time hooks checked, IN ITERATION ORDER (affects
 * violation list order). TS: autoExecLinter.ts::PACKAGE_JSON_HOOKS. */
#define BONSAI_PACKAGE_JSON_HOOKS_COUNT 5
extern const char *const BONSAI_PACKAGE_JSON_HOOKS[BONSAI_PACKAGE_JSON_HOOKS_COUNT];

/* One file in the release manifest: repo-relative forward-slash path, optional
 * content (only used for package.json hook checks; NULL => absent). Strings
 * borrowed. TS: autoExecLinter.ts::ManifestEntry. */
typedef struct {
    const char *path;
    const char *content;   /* NULL => undefined (no hook check) */
} manifest_entry_t;

/* A detected known auto-exec vector. `rule`/`detail` are OWNED strings (the rule
 * id embeds the matched constant, e.g. "forbidden-file:.vscode/tasks.json").
 * TS: autoExecLinter.ts::LintViolation. */
typedef struct {
    char *path;    /* owned — the offending entry's path (as supplied) */
    char *rule;    /* owned rule id */
    char *detail;  /* owned human-readable detail */
} lint_violation_t;

/* lintManifest result: every violation in deterministic order + clean flag.
 * `violations` is an OWNED array (release via lint_result_free). TS: the
 * { clean, violations } object. */
typedef struct {
    bool              clean;       /* violations_count == 0 */
    lint_violation_t *violations;  /* owned array */
    size_t            violations_count;
} lint_result_t;

/* Release a lint_result_t's owned violations and zero it (NULL-safe). */
void lint_result_free(lint_result_t *r);

/* lintManifest(manifest): return EVERY violation across forbidden-file,
 * forbidden-prefix, install-hook, and unparseable-package-json rules in the
 * exact TS order. clean iff zero violations. Writes the result to *out (owned;
 * release via lint_result_free). TS: autoExecLinter.ts::lintManifest.
 * BNS_OK / BNS_ENOMEM. */
int lint_manifest(const manifest_entry_t *manifest, size_t count,
                  lint_result_t *out);

/* The six release fields the attestor verifies and commits into the activate
 * digest. Strings borrowed. TS: autoExecLinter.ts::ReleaseFields. */
typedef struct {
    const char *genesis_outpoint;
    const char *scope;
    const char *version;
    const char *bundle_hash;
    const char *file_set_root;
    const char *announce_txid;
} release_fields_t;

/* Discriminated attest outcome. On `attested`: the signed attestation (owned
 * strings + seq). On !attested: the violations (owned, release via
 * lint_result_free on `dirty`). TS: autoExecLinter.ts::AttestResult. */
typedef struct {
    bool attested;
    /* attested == true: */
    char        *attestor_pubkey;  /* owned decimal Rabin pubkey */
    char        *signature;        /* owned wire-format attestation */
    char        *digest;           /* owned lowercase-hex activate digest */
    uint64_t     seq;              /* the consumed sequence number */
    /* attested == false: */
    lint_result_t dirty;           /* owned violations */
} attest_result_t;

/* Release the owned members of an attest_result_t and zero it (NULL-safe). */
void attest_result_free(attest_result_t *r);

/* Opaque attestor handle: holds the Rabin signer key and the strictly-increasing
 * seq. TS: autoExecLinter.ts::AutoExecLinterAttestor. */
typedef struct auto_exec_linter_attestor_s auto_exec_linter_attestor_t;

/* Construct over a borrowed Rabin attestor key (must outlive it) and a starting
 * sequence (start_seq < 1 => BNS_EINVAL, the constructor throw). Use
 * start_seq=1 for the TS default. *out freed via auto_exec_linter_attestor_free.
 * TS: new AutoExecLinterAttestor(signer, startSeq=1n).
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int auto_exec_linter_attestor_new(const rabin_attestor_key_t *key,
                                  uint64_t start_seq,
                                  auto_exec_linter_attestor_t **out);

/* Release the attestor (NULL-safe; does not free the borrowed key). */
void auto_exec_linter_attestor_free(auto_exec_linter_attestor_t *a);

/* The next sequence number that would be consumed. TS: get nextSeq. */
uint64_t auto_exec_linter_attestor_next_seq(const auto_exec_linter_attestor_t *a);

/* The attestor's Rabin public key (borrowed; valid for the attestor's lifetime).
 * TS: get pubKey. */
const char *auto_exec_linter_attestor_pub_key(auto_exec_linter_attestor_t *a);

/* attest(release, manifest): lint; if dirty -> *out = {attested:false,
 * violations}. Else compute the activate digest, Rabin-sign it at the current
 * seq, increment seq (consumed ONLY here), and -> *out = {attested:true,...}.
 * Writes the result to *out (owned; release via attest_result_free).
 * TS: AutoExecLinterAttestor.attest. BNS_OK / BNS_ECRYPTO / BNS_ENOMEM. */
int auto_exec_linter_attestor_attest(auto_exec_linter_attestor_t *a,
                                     const release_fields_t *release,
                                     const manifest_entry_t *manifest,
                                     size_t manifest_count,
                                     attest_result_t *out);

#endif /* BONSAI_ATTESTOR_AUTO_EXEC_LINTER_H */
