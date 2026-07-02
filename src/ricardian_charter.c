/*
 * ricardian_charter.c — faithful C port of src/ricardianCharter.ts.
 *
 * Parses the delimited key=value policy block out of the charter prose, defines
 * the canonical byte layout (prose ‖ separator ‖ canonicalJSON(binding) ‖ "\n")
 * that IS the Ricardian contract, computes ricardianHash over it, and
 * signs/verifies that exact byte string with the issuer's ECDSA key.
 *
 * Byte-fragile preimage rules — see ricardian_charter.h header notes.
 */

#include "ricardian_charter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "common/hex.h"
#include "crypto/hash.h"
#include "json/json.h"

/* The five machine-parsable policy terms, in REQUIRED-KEY order (TS). */
static const char *const REQUIRED_KEYS[] = {
    "perTxLimit",
    "dailyLimit",
    "windowDuration",
    "graduationThreshold",
    "validatorThreshold",
};
#define N_REQUIRED_KEYS 5

/* The begin/end delimiters of the policy block in the prose. TS BEGIN/END. */
#define CHARTER_BEGIN "<!-- ricardian:params:begin -->"
#define CHARTER_END   "<!-- ricardian:params:end -->"

/* ---- lifecycle ---------------------------------------------------------- */

void charter_params_free(charter_params_t *p)
{
    if (!p) return;
    bn_free(p->per_tx_limit);
    bn_free(p->daily_limit);
    bn_free(p->window_duration);
    bn_free(p->graduation_threshold);
    bn_free(p->validator_threshold);
    memset(p, 0, sizeof(*p));
}

void deployment_binding_free(deployment_binding_t *b)
{
    if (!b) return;
    free(b->agent_pubkey);
    free(b->designated_validator_pubkey);
    free(b->validator_rabin_pubkey);
    free(b->max_slashing_target);
    free(b->min_slash_confirmations);
    free(b->initial_slash_checkpoint_hash);
    memset(b, 0, sizeof(*b));
}

void charter_signature_free(charter_signature_t *s)
{
    if (!s) return;
    free(s->algo);
    free(s->issuer_pubkey);
    free(s->signature);
    free(s->ricardian_hash);
    deployment_binding_free(&s->binding);
    memset(s, 0, sizeof(*s));
}

/* ---- parse helpers ------------------------------------------------------ */

static bn_t *const *param_slot_const(const charter_params_t *p, const char *key)
{
    if (strcmp(key, "perTxLimit") == 0)          return &p->per_tx_limit;
    if (strcmp(key, "dailyLimit") == 0)          return &p->daily_limit;
    if (strcmp(key, "windowDuration") == 0)      return &p->window_duration;
    if (strcmp(key, "graduationThreshold") == 0) return &p->graduation_threshold;
    if (strcmp(key, "validatorThreshold") == 0)  return &p->validator_threshold;
    return NULL;
}

static bool is_ident_start(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}
static bool is_ident_char(char c)
{
    return is_ident_start(c) || (c >= '0' && c <= '9');
}
static bool is_js_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

/* True iff bn < 0. The bignum.h contract exposes bn_is_zero and bn_cmp; build a
 * zero handle and three-way compare to detect a negative value. */
static bool bn_is_neg(const bn_t *bn)
{
    bn_t *zero = bn_new();
    if (!zero) return false; /* OOM: treat as non-negative; caller OOM-paths win */
    int c = bn_cmp(bn, zero);
    bn_free(zero);
    return c < 0;
}

/*
 * Apply the TS line transform to one raw line:
 *   line = rawLine.replace(/```.*\/g, '').replace(/#.*\/g, '').trim()
 * `.*` is greedy and does NOT match newlines, so the first "```" deletes from
 * there to end of line, then the first '#' deletes from there to end of line,
 * then trim. Writes the cleaned token into `out` (size out_sz); returns its len.
 */
static size_t clean_line(const char *raw, size_t raw_len, char *out, size_t out_sz)
{
    size_t end = raw_len;

    /* replace(/```.*\/g, '') — cut from the first "```" run. */
    for (size_t i = 0; i + 2 < raw_len; i++) {
        if (raw[i] == '`' && raw[i + 1] == '`' && raw[i + 2] == '`') {
            end = i;
            break;
        }
    }
    /* replace(/#.*\/g, '') — cut from the first '#'. */
    for (size_t i = 0; i < end; i++) {
        if (raw[i] == '#') { end = i; break; }
    }
    /* trim() */
    size_t s = 0, e = end;
    while (s < e && is_js_ws(raw[s])) s++;
    while (e > s && is_js_ws(raw[e - 1])) e--;

    size_t n = e - s;
    if (n >= out_sz) n = out_sz - 1;
    memcpy(out, raw + s, n);
    out[n] = '\0';
    return n;
}

/* Trim a raw line (no fence/comment removal) for verbatim error messages. */
static size_t trim_raw(const char *raw, size_t raw_len, char *out, size_t out_sz)
{
    size_t s = 0, e = raw_len;
    while (s < e && is_js_ws(raw[s])) s++;
    while (e > s && is_js_ws(raw[e - 1])) e--;
    size_t n = e - s;
    if (n >= out_sz) n = out_sz - 1;
    memcpy(out, raw + s, n);
    out[n] = '\0';
    return n;
}

/*
 * Match the TS line regex: /^([A-Za-z][A-Za-z0-9]*)\s*=\s*(-?\d+)$/
 * On match copy the key and the (possibly signed) decimal digits and return
 * true. The line is already trimmed, so internal \s* around '=' is the only
 * relevant whitespace.
 */
static bool match_param_line(const char *line, char *key_out, size_t key_sz,
                             char *val_out, size_t val_sz)
{
    const char *p = line;
    if (!is_ident_start(*p)) return false;
    size_t ki = 0;
    while (is_ident_char(*p)) {
        if (ki + 1 >= key_sz) return false;
        key_out[ki++] = *p++;
    }
    key_out[ki] = '\0';
    while (is_js_ws(*p)) p++;
    if (*p != '=') return false;
    p++;
    while (is_js_ws(*p)) p++;
    size_t vi = 0;
    if (*p == '-') {
        if (vi + 1 >= val_sz) return false;
        val_out[vi++] = *p++;
    }
    if (!(*p >= '0' && *p <= '9')) return false;
    while (*p >= '0' && *p <= '9') {
        if (vi + 1 >= val_sz) return false;
        val_out[vi++] = *p++;
    }
    val_out[vi] = '\0';
    if (*p != '\0') return false; /* $ */
    return true;
}

/* Is `key` one of the five modelled required keys? Returns index or -1. */
static int required_index(const char *key)
{
    for (int i = 0; i < N_REQUIRED_KEYS; i++)
        if (strcmp(key, REQUIRED_KEYS[i]) == 0) return i;
    return -1;
}

/*
 * Scan the body up to (but not including) `before` for a parameter line whose
 * key == `key`. Used to detect a duplicate of an UNKNOWN key (which TS catches
 * during the parse loop, before the unknown-key sweep). Modelled (required)
 * keys track duplicates via found_flag, so this is only consulted for unknowns.
 */
static bool body_has_key_before(const char *body, const char *before,
                                const char *key)
{
    const char *ls = body;
    while (ls < before) {
        const char *nl = memchr(ls, '\n', (size_t)(before - ls));
        const char *le = nl ? nl : before;
        size_t rl = (size_t)(le - ls);
        char cl[512];
        size_t cln = clean_line(ls, rl, cl, sizeof(cl));
        if (cln != 0) {
            char k2[128], v2[256];
            if (match_param_line(cl, k2, sizeof(k2), v2, sizeof(v2)) &&
                strcmp(k2, key) == 0)
                return true;
        }
        if (!nl) break;
        ls = nl + 1;
    }
    return false;
}

/* ---- parse -------------------------------------------------------------- */

int parse_charter_params(const char *prose_text, charter_params_t *out,
                         bonsai_err_ctx *ctx)
{
    if (!prose_text || !out) return BNS_EINVAL;
    memset(out, 0, sizeof(*out));

    const char *begin_p = strstr(prose_text, CHARTER_BEGIN);
    const char *end_p = strstr(prose_text, CHARTER_END);
    if (!begin_p || !end_p || end_p < begin_p) {
        return bns_fail(ctx, BNS_EPARSE,
            "ricardian charter: missing or malformed parameter block "
            "(ricardian:params:begin/end)");
    }
    const char *body = begin_p + strlen(CHARTER_BEGIN);
    const char *body_end = end_p;

    bn_t *values[N_REQUIRED_KEYS] = {0};
    bool found_flag[N_REQUIRED_KEYS] = {0};
    /* First unknown key encountered (deferred to after the required sweep). */
    char unknown_key[128] = {0};
    bool have_unknown = false;
    int rc = BNS_OK;

    /* body.split('\n') */
    const char *line_start = body;
    while (line_start <= body_end) {
        const char *nl = memchr(line_start, '\n', (size_t)(body_end - line_start));
        const char *line_end = nl ? nl : body_end;
        size_t raw_len = (size_t)(line_end - line_start);

        char cleaned[512];
        size_t clen = clean_line(line_start, raw_len, cleaned, sizeof(cleaned));

        if (clen != 0) {
            char key[128], val[256];
            if (!match_param_line(cleaned, key, sizeof(key), val, sizeof(val))) {
                char trimmed[512];
                trim_raw(line_start, raw_len, trimmed, sizeof(trimmed));
                rc = bns_fail(ctx, BNS_EPARSE,
                    "ricardian charter: unparseable parameter line: \"%s\"", trimmed);
                goto fail;
            }

            int idx = required_index(key);
            if (idx < 0) {
                /* Unknown key. TS records ALL keys in `found`, so a duplicate
                 * (even of an unknown key) throws the duplicate error here,
                 * before the unknown-key sweep. */
                if (body_has_key_before(body, line_start, key)) {
                    rc = bns_fail(ctx, BNS_EPARSE,
                        "ricardian charter: duplicate parameter \"%s\"", key);
                    goto fail;
                }
                if (!have_unknown) {
                    snprintf(unknown_key, sizeof(unknown_key), "%s", key);
                    have_unknown = true;
                }
                goto next_line; /* keep parsing — required sweep takes precedence */
            }

            if (found_flag[idx]) {
                rc = bns_fail(ctx, BNS_EPARSE,
                    "ricardian charter: duplicate parameter \"%s\"", key);
                goto fail;
            }
            bn_t *bv = NULL;
            if (bn_parse_dec(val, &bv) != BNS_OK || !bv) {
                rc = BNS_EPARSE;
                bns_fail(ctx, BNS_EPARSE,
                    "ricardian charter: unparseable parameter line: \"%s\"", cleaned);
                goto fail;
            }
            values[idx] = bv;
            found_flag[idx] = true;
        }

    next_line:
        if (!nl) break;
        line_start = nl + 1;
    }

    /* Required-key sweep: missing? non-positive? (TS REQUIRED_KEYS order). */
    for (int i = 0; i < N_REQUIRED_KEYS; i++) {
        if (!found_flag[i]) {
            rc = bns_fail(ctx, BNS_EPARSE,
                "ricardian charter: prose is missing required parameter \"%s\"",
                REQUIRED_KEYS[i]);
            goto fail;
        }
        if (bn_is_zero(values[i]) || bn_is_neg(values[i])) {
            char *vs = NULL;
            (void)bn_to_dec(values[i], &vs);
            rc = bns_fail(ctx, BNS_EPARSE,
                "ricardian charter: parameter \"%s\" must be positive (got %s)",
                REQUIRED_KEYS[i], vs ? vs : "?");
            free(vs);
            goto fail;
        }
    }

    /* Only after the required sweep passes does an unknown key error fire. */
    if (have_unknown) {
        rc = bns_fail(ctx, BNS_EPARSE,
            "ricardian charter: prose declares unknown parameter \"%s\" "
            "with no contract field", unknown_key);
        goto fail;
    }

    /* All good. Transfer ownership into out in struct order. */
    out->per_tx_limit         = values[0];
    out->daily_limit          = values[1];
    out->window_duration      = values[2];
    out->graduation_threshold = values[3];
    out->validator_threshold  = values[4];
    return BNS_OK;

fail:
    for (int i = 0; i < N_REQUIRED_KEYS; i++) bn_free(values[i]);
    memset(out, 0, sizeof(*out));
    return rc;
}

int assert_params_match_prose(const charter_params_t *parsed,
                              const charter_params_t *constructed,
                              bonsai_err_ctx *ctx)
{
    if (!parsed || !constructed) return BNS_EINVAL;
    for (int i = 0; i < N_REQUIRED_KEYS; i++) {
        bn_t *const *ps = param_slot_const(parsed, REQUIRED_KEYS[i]);
        bn_t *const *cs = param_slot_const(constructed, REQUIRED_KEYS[i]);
        if (!ps || !cs || !*ps || !*cs) return BNS_EINVAL;
        if (bn_cmp(*ps, *cs) != 0) {
            char *cv = NULL, *pv = NULL;
            (void)bn_to_dec(*cs, &cv);
            (void)bn_to_dec(*ps, &pv);
            int rc = bns_fail(ctx, BNS_EBINDING,
                "ricardian charter: constructor %s=%s != prose %s=%s "
                "(single-source-of-truth violation)",
                REQUIRED_KEYS[i], cv ? cv : "?", REQUIRED_KEYS[i], pv ? pv : "?");
            free(cv);
            free(pv);
            return rc;
        }
    }
    return BNS_OK;
}

/* ---- canonical serialization -------------------------------------------- */

int charter_canonical_json(const deployment_binding_t *binding, char **out)
{
    if (!binding || !out) return BNS_EINVAL;
    *out = NULL;

    cJSON *obj = cJSON_CreateObject();
    if (!obj) return BNS_ENOMEM;

    struct { const char *k; const char *v; } fields[] = {
        { "agentPubKey",                binding->agent_pubkey },
        { "designatedValidatorPubKey",  binding->designated_validator_pubkey },
        { "validatorRabinPubKey",       binding->validator_rabin_pubkey },
        { "maxSlashingTarget",          binding->max_slashing_target },
        { "minSlashConfirmations",      binding->min_slash_confirmations },
        { "initialSlashCheckpointHash", binding->initial_slash_checkpoint_hash },
    };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        const char *v = fields[i].v ? fields[i].v : "";
        if (!cJSON_AddStringToObject(obj, fields[i].k, v)) {
            cJSON_Delete(obj);
            return BNS_ENOMEM;
        }
    }

    int rc = canonical_json(obj, out);
    cJSON_Delete(obj);
    return rc;
}

int canonical_contract_bytes(const char *prose_text,
                             const deployment_binding_t *binding,
                             byte_buf_t *out)
{
    if (!prose_text || !binding || !out) return BNS_EINVAL;

    char *cjson = NULL;
    int rc = charter_canonical_json(binding, &cjson);
    if (rc != BNS_OK) return rc;

    rc = byte_buf_append(out, prose_text, strlen(prose_text));
    if (rc != BNS_OK) goto done;
    rc = byte_buf_append(out, BONSAI_CHARTER_BINDING_SEPARATOR,
                         strlen(BONSAI_CHARTER_BINDING_SEPARATOR));
    if (rc != BNS_OK) goto done;
    rc = byte_buf_append(out, cjson, strlen(cjson));
    if (rc != BNS_OK) goto done;
    rc = byte_buf_append(out, "\n", 1);

done:
    free(cjson);
    return rc;
}

int compute_ricardian_hash(const char *prose_text,
                           const deployment_binding_t *binding,
                           char **out_hex)
{
    if (!prose_text || !binding || !out_hex) return BNS_EINVAL;
    *out_hex = NULL;

    byte_buf_t bytes;
    byte_buf_init(&bytes);
    int rc = canonical_contract_bytes(prose_text, binding, &bytes);
    if (rc != BNS_OK) { byte_buf_free(&bytes); return rc; }

    uint8_t digest[BONSAI_SHA256_LEN];
    sha256(bytes.data, bytes.len, digest);
    byte_buf_free(&bytes);

    char *hex = hex_encode(digest, BONSAI_SHA256_LEN);
    if (!hex) return BNS_ENOMEM;
    *out_hex = hex;
    return BNS_OK;
}

/* ---- sign / verify ------------------------------------------------------ */

/* Deep-copy a binding's six strings into dst (zeroed first). */
static int binding_copy(const deployment_binding_t *src, deployment_binding_t *dst)
{
    memset(dst, 0, sizeof(*dst));
    const char *fields_src[6] = {
        src->agent_pubkey, src->designated_validator_pubkey,
        src->validator_rabin_pubkey, src->max_slashing_target,
        src->min_slash_confirmations, src->initial_slash_checkpoint_hash,
    };
    char **fields_dst[6] = {
        &dst->agent_pubkey, &dst->designated_validator_pubkey,
        &dst->validator_rabin_pubkey, &dst->max_slashing_target,
        &dst->min_slash_confirmations, &dst->initial_slash_checkpoint_hash,
    };
    for (int i = 0; i < 6; i++) {
        const char *s = fields_src[i] ? fields_src[i] : "";
        char *c = strdup(s);
        if (!c) { deployment_binding_free(dst); return BNS_ENOMEM; }
        *fields_dst[i] = c;
    }
    return BNS_OK;
}

int sign_charter(const char *prose_text, const deployment_binding_t *binding,
                 const ecdsa_key_t *issuer_priv, charter_signature_t *out_sig)
{
    if (!prose_text || !binding || !issuer_priv || !out_sig) return BNS_EINVAL;
    memset(out_sig, 0, sizeof(*out_sig));

    int rc;
    byte_buf_t bytes;       byte_buf_init(&bytes);
    byte_buf_t der;         byte_buf_init(&der);
    ecdsa_pubkey_t *pub = NULL;
    char *pub_hex = NULL;
    char *sig_hex = NULL;
    char *rhash = NULL;

    rc = canonical_contract_bytes(prose_text, binding, &bytes);
    if (rc != BNS_OK) goto cleanup;

    uint8_t digest[BONSAI_SHA256_LEN];
    sha256(bytes.data, bytes.len, digest);

    rc = ecdsa_sign_low_s(digest, issuer_priv, &der);
    if (rc != BNS_OK) goto cleanup;
    sig_hex = hex_encode(der.data, der.len);
    if (!sig_hex) { rc = BNS_ENOMEM; goto cleanup; }

    rc = ecdsa_key_derive_pubkey(issuer_priv, &pub);
    if (rc != BNS_OK) goto cleanup;
    rc = ecdsa_pubkey_to_hex(pub, &pub_hex);
    if (rc != BNS_OK) goto cleanup;

    rc = compute_ricardian_hash(prose_text, binding, &rhash);
    if (rc != BNS_OK) goto cleanup;

    out_sig->algo = strdup(BONSAI_CHARTER_ALGO);
    if (!out_sig->algo) { rc = BNS_ENOMEM; goto cleanup; }
    rc = binding_copy(binding, &out_sig->binding);
    if (rc != BNS_OK) goto cleanup;

    out_sig->issuer_pubkey  = pub_hex;  pub_hex = NULL;
    out_sig->signature      = sig_hex;  sig_hex = NULL;
    out_sig->ricardian_hash = rhash;    rhash = NULL;

    rc = BNS_OK;

cleanup:
    if (rc != BNS_OK) charter_signature_free(out_sig);
    byte_buf_free(&bytes);
    byte_buf_free(&der);
    ecdsa_pubkey_free(pub);
    free(pub_hex);
    free(sig_hex);
    free(rhash);
    return rc;
}

/* Case-insensitive ASCII compare (mirrors .toLowerCase() === .toLowerCase()). */
static bool ascii_ieq(const char *a, const char *b)
{
    if (!a || !b) return false;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

int verify_charter_signature(const char *prose_text,
                             const charter_signature_t *sig,
                             charter_verify_result_t *out)
{
    if (!out) return BNS_EINVAL;
    out->ok = false;
    out->reason = NULL;
    if (!prose_text || !sig) return BNS_EINVAL;

    int ret = BNS_OK;
    char *expected = NULL;
    byte_buf_t bytes;   byte_buf_init(&bytes);
    byte_buf_t der;     byte_buf_init(&der);
    ecdsa_pubkey_t *pub = NULL;

    int rc = compute_ricardian_hash(prose_text, &sig->binding, &expected);
    if (rc == BNS_ENOMEM) { ret = BNS_ENOMEM; goto cleanup; }
    if (rc != BNS_OK) {
        out->ok = false;
        out->reason = "ricardian charter: failed to compute hash";
        goto cleanup;
    }

    if (!sig->ricardian_hash || !ascii_ieq(expected, sig->ricardian_hash)) {
        out->ok = false;
        out->reason =
            "ricardianHash mismatch (prose or binding changed since signing)";
        goto cleanup;
    }

    rc = canonical_contract_bytes(prose_text, &sig->binding, &bytes);
    if (rc == BNS_ENOMEM) { ret = BNS_ENOMEM; goto cleanup; }
    if (rc != BNS_OK) {
        out->ok = false;
        out->reason = "ricardian charter: failed to build contract bytes";
        goto cleanup;
    }
    uint8_t digest[BONSAI_SHA256_LEN];
    sha256(bytes.data, bytes.len, digest);

    /* Parse issuer pubkey + DER signature; failures map to the TS catch path. */
    if (!sig->issuer_pubkey ||
        ecdsa_pubkey_from_hex(sig->issuer_pubkey, &pub) != BNS_OK || !pub) {
        out->ok = false;
        out->reason = "ECDSA signature does not verify under issuerPubKey";
        goto cleanup;
    }
    if (!sig->signature || hex_decode(sig->signature, &der) != BNS_OK) {
        out->ok = false;
        out->reason = "ECDSA signature does not verify under issuerPubKey";
        goto cleanup;
    }

    if (ecdsa_verify(digest, der.data, der.len, pub)) {
        out->ok = true;
        out->reason = NULL;
    } else {
        out->ok = false;
        out->reason = "ECDSA signature does not verify under issuerPubKey";
    }

cleanup:
    free(expected);
    byte_buf_free(&bytes);
    byte_buf_free(&der);
    ecdsa_pubkey_free(pub);
    return ret;
}
