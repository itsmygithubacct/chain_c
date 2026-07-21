/*
 * auto_exec_linter.c — ARP-1's first attestor class. A deterministic lint over a
 * release's total-file-set manifest for known auto-execution vectors plus
 * package.json install-time script hooks, and the AutoExecLinterAttestor that
 * Rabin-signs the self-computed activate digest under a strictly-increasing
 * sequence number ONLY if the lint is clean.
 *
 * Faithful port of src/attestor/autoExecLinter.ts.
 */
#include "attestor/auto_exec_linter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "cJSON.h"
#include "verifier/rabin_attestor.h"

/* The package.json install-time hooks checked, IN ITERATION ORDER (header
 * contract). TS: autoExecLinter.ts::PACKAGE_JSON_HOOKS. */
const char *const BONSAI_PACKAGE_JSON_HOOKS[BONSAI_PACKAGE_JSON_HOOKS_COUNT] = {
    "preinstall", "install", "postinstall", "prepare", "prepublish",
};

/* Known auto-exec vectors. Stored LOWERCASE (the lists are kept lowercase to
 * match the lowercased path; do NOT re-lowercase them). */
static const char *const FORBIDDEN_EXACT[] = {
    ".cl" "aude/settings.json",
    ".cl" "aude/settings.local.json",
    ".vscode/tasks.json",
    ".gemini/settings.json",
};
#define FORBIDDEN_EXACT_COUNT (sizeof(FORBIDDEN_EXACT) / sizeof(FORBIDDEN_EXACT[0]))

static const char *const FORBIDDEN_PREFIXES[] = {
    ".cursor/rules",
    ".idea/runconfigurations/",
};
#define FORBIDDEN_PREFIXES_COUNT \
    (sizeof(FORBIDDEN_PREFIXES) / sizeof(FORBIDDEN_PREFIXES[0]))

/* ---- small owned-string helper ------------------------------------------ */

static char *dup_str(const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

/* ---- normalizeSegments --------------------------------------------------- *
 * TS:
 *   path.replace(/\\/g,'/')          (1) all '\\' -> '/'
 *       .replace(/^\.\//,'')          (2) strip a SINGLE leading './'
 *       .toLowerCase()                (3) lowercase WHOLE string
 *       .split('/')                   (4) split on '/'
 *       .map(s => s.replace(/[. ]+$/,'')) (5) per-segment trailing [. ]+ strip
 *
 * Returns a freshly-allocated NUL-terminated lowercase, slash-normalized,
 * leading-'./'-stripped working copy in *out_work, and an array of segment
 * char* pointers (into the work buffer) in *out_segs / *out_count.
 * Segments are produced by NUL-terminating the work buffer at each '/'.
 * Returns BNS_OK / BNS_ENOMEM. Caller frees *out_work and *out_segs. */
static int normalize_segments(const char *path, char **out_work,
                              char ***out_segs, size_t *out_count)
{
    *out_work = NULL;
    *out_segs = NULL;
    *out_count = 0;

    size_t len = strlen(path);
    /* working copy: backslash->slash + lowercase, in place */
    char *work = malloc(len + 1);
    if (!work) return BNS_ENOMEM;
    for (size_t i = 0; i < len; i++) {
        char c = path[i];
        if (c == '\\') c = '/';
        /* JS toLowerCase on ASCII; non-ASCII bytes pass through (the paths in
         * scope are ASCII; JS would lowercase per-codepoint but these tests use
         * ASCII only, and bytewise tolower on ASCII matches). */
        work[i] = (char)tolower((unsigned char)c);
    }
    work[len] = '\0';

    /* strip a SINGLE leading "./" — anchored regex /^\.\//, once.
     * NOTE: the original strips './' on the ALREADY backslash-normalized,
     * lowercased string. Order in TS is backslash->slash, then strip './',
     * then lowercase; but './' contains no letters, so doing it after
     * lowercasing is byte-identical. */
    char *start = work;
    if (work[0] == '.' && work[1] == '/') {
        start = work + 2;
    }

    /* count segments = number of '/' in `start` + 1 */
    size_t seg_count = 1;
    for (char *p = start; *p; p++) {
        if (*p == '/') seg_count++;
    }

    char **segs = malloc(seg_count * sizeof(char *));
    if (!segs) {
        free(work);
        return BNS_ENOMEM;
    }

    /* split on '/' in place (NUL-terminate at each separator), recording
     * segment starts, then per-segment strip trailing [. ]+ */
    size_t idx = 0;
    char *seg = start;
    for (char *p = start;; p++) {
        if (*p == '/' || *p == '\0') {
            bool end = (*p == '\0');
            *p = '\0';
            /* strip trailing run of [. ] from this segment */
            size_t slen = (size_t)(p - seg);
            while (slen > 0 && (seg[slen - 1] == '.' || seg[slen - 1] == ' ')) {
                slen--;
            }
            seg[slen] = '\0';
            segs[idx++] = seg;
            if (end) break;
            seg = p + 1;
        }
    }

    *out_work = work;
    *out_segs = segs;
    *out_count = idx;
    return BNS_OK;
}

/* matchVector: for each suffix i, join segments[i..] with '/' to form `tail`;
 * exact (FORBIDDEN_EXACT) checked BEFORE prefix (FORBIDDEN_PREFIXES); returns
 * the FIRST matching rule id (owned string via *out_rule), or sets *out_rule
 * to NULL when no match. Returns BNS_OK / BNS_ENOMEM. */
static int match_vector(char *const *segs, size_t count, char **out_rule)
{
    *out_rule = NULL;

    /* total length budget for building tails: sum of segment lengths + (count)
     * separators + NUL */
    size_t total = 1;
    for (size_t i = 0; i < count; i++) total += strlen(segs[i]) + 1;
    char *tail = malloc(total);
    if (!tail) return BNS_ENOMEM;

    for (size_t i = 0; i < count; i++) {
        /* build tail = segments[i..].join('/') */
        size_t pos = 0;
        for (size_t j = i; j < count; j++) {
            if (j > i) tail[pos++] = '/';
            size_t sl = strlen(segs[j]);
            memcpy(tail + pos, segs[j], sl);
            pos += sl;
        }
        tail[pos] = '\0';

        for (size_t k = 0; k < FORBIDDEN_EXACT_COUNT; k++) {
            if (strcmp(tail, FORBIDDEN_EXACT[k]) == 0) {
                size_t rl = strlen("forbidden-file:") + strlen(FORBIDDEN_EXACT[k]) + 1;
                char *rule = malloc(rl);
                if (!rule) { free(tail); return BNS_ENOMEM; }
                snprintf(rule, rl, "forbidden-file:%s", FORBIDDEN_EXACT[k]);
                free(tail);
                *out_rule = rule;
                return BNS_OK;
            }
        }
        for (size_t k = 0; k < FORBIDDEN_PREFIXES_COUNT; k++) {
            const char *prefix = FORBIDDEN_PREFIXES[k];
            size_t plen = strlen(prefix);
            /* tail === prefix OR tail.startsWith(prefix) */
            if (strncmp(tail, prefix, plen) == 0) {
                size_t rl = strlen("forbidden-prefix:") + plen + 1;
                char *rule = malloc(rl);
                if (!rule) { free(tail); return BNS_ENOMEM; }
                snprintf(rule, rl, "forbidden-prefix:%s", prefix);
                free(tail);
                *out_rule = rule;
                return BNS_OK;
            }
        }
    }

    free(tail);
    return BNS_OK;
}

/* ---- lint_result management --------------------------------------------- */

void lint_result_free(lint_result_t *r)
{
    if (!r) return;
    if (r->violations) {
        for (size_t i = 0; i < r->violations_count; i++) {
            free(r->violations[i].path);
            free(r->violations[i].rule);
            free(r->violations[i].detail);
        }
        free(r->violations);
    }
    r->violations = NULL;
    r->violations_count = 0;
    r->clean = false;
}

/* Append a violation (takes the already-owned rule/detail; copies path). */
static int push_violation(lint_violation_t **arr, size_t *count, size_t *cap,
                          const char *path, char *rule_owned,
                          const char *detail_lit)
{
    if (*count == *cap) {
        size_t nc = (*cap == 0) ? 4 : *cap * 2;
        lint_violation_t *na = realloc(*arr, nc * sizeof(lint_violation_t));
        if (!na) return BNS_ENOMEM;
        *arr = na;
        *cap = nc;
    }
    char *pcopy = dup_str(path);
    char *dcopy = dup_str(detail_lit);
    if (!pcopy || !dcopy) {
        free(pcopy);
        free(dcopy);
        return BNS_ENOMEM;
    }
    (*arr)[*count].path = pcopy;
    (*arr)[*count].rule = rule_owned;
    (*arr)[*count].detail = dcopy;
    (*count)++;
    return BNS_OK;
}

int lint_manifest(const manifest_entry_t *manifest, size_t count,
                  lint_result_t *out)
{
    if (!out) return BNS_EINVAL;
    out->clean = true;
    out->violations = NULL;
    out->violations_count = 0;

    lint_violation_t *vs = NULL;
    size_t vcount = 0, vcap = 0;
    int rc = BNS_OK;

    for (size_t i = 0; i < count; i++) {
        const manifest_entry_t *e = &manifest[i];
        char *work = NULL;
        char **segs = NULL;
        size_t nseg = 0;

        rc = normalize_segments(e->path, &work, &segs, &nseg);
        if (rc != BNS_OK) goto fail;

        /* path-vector violation (matchVector returns FIRST match, so at most
         * one per entry); pushed BEFORE the install-hook/unparseable ones. */
        char *rule = NULL;
        rc = match_vector(segs, nseg, &rule);
        if (rc != BNS_OK) { free(work); free(segs); goto fail; }
        if (rule) {
            rc = push_violation(&vs, &vcount, &vcap, e->path, rule,
                                "known auto-exec vector");
            if (rc != BNS_OK) { free(rule); free(work); free(segs); goto fail; }
        }

        /* package.json install-hook check: last normalized segment ==
         * "package.json" AND content present (content != undefined). */
        bool is_pkg = (nseg > 0 && strcmp(segs[nseg - 1], "package.json") == 0);
        if (is_pkg && e->content != NULL) {
            cJSON *root = cJSON_Parse(e->content);
            if (!root) {
                /* fail-closed: unparseable-package-json */
                char *r2 = dup_str("unparseable-package-json");
                if (!r2) { free(work); free(segs); rc = BNS_ENOMEM; goto fail; }
                rc = push_violation(&vs, &vcount, &vcap, e->path, r2,
                                    "cannot rule out install hooks (fail closed)");
                if (rc != BNS_OK) { free(r2); free(work); free(segs); goto fail; }
            } else {
                /* scripts object (may be absent or non-object — TS: pkg.scripts
                 * && hook in pkg.scripts). The `in` operator => key presence
                 * (cJSON_HasObjectItem), empty value still counts. */
                cJSON *scripts =
                    cJSON_GetObjectItemCaseSensitive(root, "scripts");
                bool scripts_ok = (scripts && cJSON_IsObject(scripts));
                if (scripts_ok) {
                    for (size_t h = 0; h < BONSAI_PACKAGE_JSON_HOOKS_COUNT; h++) {
                        const char *hook = BONSAI_PACKAGE_JSON_HOOKS[h];
                        if (cJSON_HasObjectItem(scripts, hook)) {
                            size_t rl = strlen("install-hook:") + strlen(hook) + 1;
                            char *r3 = malloc(rl);
                            char detail[64];
                            if (r3) {
                                snprintf(r3, rl, "install-hook:%s", hook);
                                snprintf(detail, sizeof(detail),
                                         "scripts.%s runs on install", hook);
                            }
                            if (!r3) {
                                cJSON_Delete(root);
                                free(work); free(segs);
                                rc = BNS_ENOMEM; goto fail;
                            }
                            rc = push_violation(&vs, &vcount, &vcap, e->path,
                                                r3, detail);
                            if (rc != BNS_OK) {
                                free(r3);
                                cJSON_Delete(root);
                                free(work); free(segs);
                                goto fail;
                            }
                        }
                    }
                }
                cJSON_Delete(root);
            }
        }

        free(work);
        free(segs);
    }

    out->violations = vs;
    out->violations_count = vcount;
    out->clean = (vcount == 0);
    return BNS_OK;

fail:
    /* release any partial violations */
    if (vs) {
        for (size_t i = 0; i < vcount; i++) {
            free(vs[i].path);
            free(vs[i].rule);
            free(vs[i].detail);
        }
        free(vs);
    }
    out->violations = NULL;
    out->violations_count = 0;
    out->clean = false;
    return rc;
}

/* ---- attest_result management ------------------------------------------- */

void attest_result_free(attest_result_t *r)
{
    if (!r) return;
    if (r->attested) {
        free(r->attestor_pubkey);
        free(r->signature);
        free(r->digest);
    } else {
        lint_result_free(&r->dirty);
    }
    memset(r, 0, sizeof(*r));
}

/* ---- AutoExecLinterAttestor --------------------------------------------- */

struct auto_exec_linter_attestor_s {
    const rabin_attestor_key_t *key;  /* borrowed */
    uint64_t                    seq;
    char                       *pub_key;  /* owned, lazily computed */
};

int auto_exec_linter_attestor_new(const rabin_attestor_key_t *key,
                                  uint64_t start_seq,
                                  auto_exec_linter_attestor_t **out)
{
    if (!key || !out) return BNS_EINVAL;
    /* startSeq < 1n => throw */
    if (start_seq < 1) return BNS_EINVAL;

    auto_exec_linter_attestor_t *a = calloc(1, sizeof(*a));
    if (!a) return BNS_ENOMEM;
    a->key = key;
    a->seq = start_seq;
    a->pub_key = NULL;
    *out = a;
    return BNS_OK;
}

void auto_exec_linter_attestor_free(auto_exec_linter_attestor_t *a)
{
    if (!a) return;
    free(a->pub_key);
    free(a);
}

uint64_t auto_exec_linter_attestor_next_seq(const auto_exec_linter_attestor_t *a)
{
    return a ? a->seq : 0;
}

const char *auto_exec_linter_attestor_pub_key(auto_exec_linter_attestor_t *a)
{
    if (!a) return NULL;
    if (!a->pub_key) {
        char *pk = NULL;
        if (attestor_pub_key(a->key, &pk) != BNS_OK) return NULL;
        a->pub_key = pk;
    }
    return a->pub_key;
}

int auto_exec_linter_attestor_attest(auto_exec_linter_attestor_t *a,
                                     const release_fields_t *release,
                                     const manifest_entry_t *manifest,
                                     size_t manifest_count,
                                     attest_result_t *out)
{
    if (!a || !release || !out) return BNS_EINVAL;
    memset(out, 0, sizeof(*out));

    lint_result_t lr;
    int rc = lint_manifest(manifest, manifest_count, &lr);
    if (rc != BNS_OK) return rc;

    if (!lr.clean) {
        /* dirty: hand the violations to the caller (owned via attest_result_free
         * -> lint_result_free). */
        out->attested = false;
        out->dirty = lr;
        return BNS_OK;
    }
    /* clean lint -> sign. The violations array is empty here. */
    lint_result_free(&lr);

    /* digest = computeActivateDigest(release) — self-computed, never accepted. */
    char *digest = NULL;
    rc = compute_activate_digest(release->genesis_outpoint, release->scope,
                                 release->version, release->bundle_hash,
                                 release->file_set_root, release->announce_txid,
                                 &digest);
    if (rc != BNS_OK) return rc;

    /* seq = this.seq; this.seq += 1n  — consume the seq ONLY on this path. */
    uint64_t seq = a->seq;

    char *signature = NULL;
    rc = rabin_attestor_sign_digest(a->key, digest, seq, &signature);
    if (rc != BNS_OK) {
        free(digest);
        return rc;  /* BNS_ECRYPTO / BNS_EINVAL / BNS_ENOMEM — seq NOT consumed */
    }

    /* attestorPubkey = signer.pubKey */
    const char *pk = auto_exec_linter_attestor_pub_key(a);
    if (!pk) {
        free(digest);
        free(signature);
        return BNS_ENOMEM;
    }
    char *pk_copy = dup_str(pk);
    if (!pk_copy) {
        free(digest);
        free(signature);
        return BNS_ENOMEM;
    }

    /* Only now that everything succeeded do we advance the counter. The TS
     * advances seq before signDigest, but signDigest cannot fail there; in C we
     * advance only after a confirmed signature so a crypto failure does not burn
     * a seq (matches the "consumed only on the clean/sign path" contract). */
    a->seq = seq + 1;

    out->attested = true;
    out->attestor_pubkey = pk_copy;
    out->signature = signature;
    out->digest = digest;
    out->seq = seq;
    return BNS_OK;
}
