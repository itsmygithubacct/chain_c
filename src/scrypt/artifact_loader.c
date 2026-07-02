/*
 * artifact_loader.c — parse a scryptlib compiled-artifact JSON into a
 * scrypt_artifact_t, and flatten an ordered constructor-argument value tree into
 * the leaf sequence scryptlib uses to substitute the <name> placeholders.
 *
 * Faithful port of scryptlib `loadArtifact` (reads "contract", "hex", the
 * abi[].type=='constructor'.params, "structs", "stateProps") and the
 * flattern{Arg,Struct,Array} leaf expansion in scryptlib's typeCheck.js. The
 * flatten ORDER and leaf naming (dotted ".field" / subscripted "[i]") MUST be
 * byte-identical to scryptlib so the reconstructed locking script matches the
 * deployed one.
 */
#include "scrypt/artifact_loader.h"
#include "scrypt/scrypt_contract.h"
#include "common/error.h"
#include "common/bytes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"

/* ------------------------------------------------------------------------- */
/* type-string -> scrypt_type_t resolution                                   */
/* ------------------------------------------------------------------------- */

/* True iff the (already trimmed) scrypt type string denotes a FixedArray,
 * i.e. ends with a "[...]" subscript group. scryptlib detects this via a
 * trailing "[N]" matcher; here we just look for the last '[' coming after the
 * element-type/name characters. */
static bool type_is_array(const char *t)
{
    if (!t) return false;
    size_t n = strlen(t);
    /* must end with ']' to be an array literal */
    return n > 0 && t[n - 1] == ']';
}

/* Resolve a scrypt type string to its tag. `structs`/`num_structs` is the
 * artifact structs table so struct names resolve to SCRYPT_TYPE_STRUCT.
 * Library names and any other compound (non-basic, non-array) names also resolve
 * to STRUCT so they flatten field-wise against the structs table. */
static scrypt_type_t resolve_type(const char *t,
                                  const scrypt_struct_t *structs,
                                  size_t num_structs)
{
    if (type_is_array(t))            return SCRYPT_TYPE_FIXED_ARRAY;
    if (strcmp(t, "int") == 0)       return SCRYPT_TYPE_INT;
    if (strcmp(t, "bool") == 0)      return SCRYPT_TYPE_BOOL;
    if (strcmp(t, "bytes") == 0)     return SCRYPT_TYPE_BYTES;
    if (strcmp(t, "ByteString") == 0)return SCRYPT_TYPE_BYTES;
    if (strcmp(t, "PubKey") == 0)    return SCRYPT_TYPE_PUBKEY;
    if (strcmp(t, "Sig") == 0)       return SCRYPT_TYPE_BYTES;   /* sig payload as bytes */
    if (strcmp(t, "Sha256") == 0)    return SCRYPT_TYPE_SHA256;
    if (strcmp(t, "Ripemd160") == 0) return SCRYPT_TYPE_RIPEMD160;
    if (strcmp(t, "PubKeyHash") == 0)return SCRYPT_TYPE_RIPEMD160;
    if (strcmp(t, "RabinPubKey") == 0) return SCRYPT_TYPE_RABIN_PUBKEY;
    if (strcmp(t, "PrivKey") == 0)   return SCRYPT_TYPE_INT;

    /* a named struct? */
    for (size_t i = 0; i < num_structs; i++) {
        if (structs[i].name && strcmp(structs[i].name, t) == 0)
            return SCRYPT_TYPE_STRUCT;
    }
    /* unknown named type: treat as struct/library to flatten field-wise. */
    return SCRYPT_TYPE_STRUCT;
}

/* ------------------------------------------------------------------------- */
/* small helpers                                                             */
/* ------------------------------------------------------------------------- */

static char *dup_cstr(const char *s)
{
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static void param_free(scrypt_param_t *p)
{
    if (!p) return;
    free(p->name);
    free(p->type_name);
    p->name = NULL;
    p->type_name = NULL;
}

/* Parse a JSON params array (used for ctor params, struct fields, stateProps)
 * into an owned scrypt_param_t[]. Resolves each param type against the structs
 * table (which must already be parsed when this is called for ctor/state). */
static int parse_params(const cJSON *arr,
                        const scrypt_struct_t *structs, size_t num_structs,
                        scrypt_param_t **out, size_t *out_count)
{
    *out = NULL;
    *out_count = 0;
    if (!arr) return BNS_OK;            /* absent => empty */
    if (!cJSON_IsArray(arr)) return BNS_EPARSE;

    int n = cJSON_GetArraySize(arr);
    if (n < 0) return BNS_EPARSE;
    if (n == 0) return BNS_OK;

    scrypt_param_t *params = calloc((size_t)n, sizeof(*params));
    if (!params) return BNS_ENOMEM;

    size_t count = 0;
    for (int i = 0; i < n; i++) {
        const cJSON *e = cJSON_GetArrayItem(arr, i);
        const cJSON *jn = cJSON_GetObjectItemCaseSensitive(e, "name");
        const cJSON *jt = cJSON_GetObjectItemCaseSensitive(e, "type");
        if (!cJSON_IsString(jn) || !cJSON_IsString(jt))
            goto fail_parse;
        params[count].name = dup_cstr(jn->valuestring);
        params[count].type_name = dup_cstr(jt->valuestring);
        if (!params[count].name || !params[count].type_name)
            goto fail_nomem;
        params[count].type = resolve_type(jt->valuestring, structs, num_structs);
        count++;
    }
    *out = params;
    *out_count = count;
    return BNS_OK;

fail_parse:
    for (size_t k = 0; k < count; k++) param_free(&params[k]);
    free(params);
    return BNS_EPARSE;
fail_nomem:
    for (size_t k = 0; k <= count; k++) param_free(&params[k]);
    free(params);
    return BNS_ENOMEM;
}

/* Parse the "structs" table into an owned scrypt_struct_t[]. Each struct's field
 * types are resolved against the same structs table being built (so nested
 * struct fields can reference earlier structs; the parse uses the partial table,
 * matching scryptlib's name-based lazy resolution at flatten time). */
static int parse_structs(const cJSON *arr,
                         scrypt_struct_t **out, size_t *out_count)
{
    *out = NULL;
    *out_count = 0;
    if (!arr) return BNS_OK;
    if (!cJSON_IsArray(arr)) return BNS_EPARSE;

    int n = cJSON_GetArraySize(arr);
    if (n < 0) return BNS_EPARSE;
    if (n == 0) return BNS_OK;

    scrypt_struct_t *structs = calloc((size_t)n, sizeof(*structs));
    if (!structs) return BNS_ENOMEM;

    size_t count = 0;
    for (int i = 0; i < n; i++) {
        const cJSON *e = cJSON_GetArrayItem(arr, i);
        const cJSON *jn = cJSON_GetObjectItemCaseSensitive(e, "name");
        const cJSON *jp = cJSON_GetObjectItemCaseSensitive(e, "params");
        if (!cJSON_IsString(jn)) goto fail_parse;
        structs[count].name = dup_cstr(jn->valuestring);
        if (!structs[count].name) goto fail_nomem;
        /* Resolve field types against the structs parsed so far. */
        int rc = parse_params(jp, structs, count,
                              &structs[count].fields, &structs[count].num_fields);
        if (rc != BNS_OK) {
            free(structs[count].name);
            structs[count].name = NULL;
            if (rc == BNS_ENOMEM) goto fail_nomem_after;
            goto fail_parse_after;
        }
        count++;
    }
    *out = structs;
    *out_count = count;
    return BNS_OK;

fail_parse_after:
    for (size_t k = 0; k < count; k++) {
        free(structs[k].name);
        for (size_t f = 0; f < structs[k].num_fields; f++)
            param_free(&structs[k].fields[f]);
        free(structs[k].fields);
    }
    free(structs);
    return BNS_EPARSE;
fail_nomem_after:
    for (size_t k = 0; k < count; k++) {
        free(structs[k].name);
        for (size_t f = 0; f < structs[k].num_fields; f++)
            param_free(&structs[k].fields[f]);
        free(structs[k].fields);
    }
    free(structs);
    return BNS_ENOMEM;
fail_parse:
    for (size_t k = 0; k < count; k++) {
        free(structs[k].name);
        for (size_t f = 0; f < structs[k].num_fields; f++)
            param_free(&structs[k].fields[f]);
        free(structs[k].fields);
    }
    free(structs);
    return BNS_EPARSE;
fail_nomem:
    for (size_t k = 0; k < count; k++) {
        free(structs[k].name);
        for (size_t f = 0; f < structs[k].num_fields; f++)
            param_free(&structs[k].fields[f]);
        free(structs[k].fields);
    }
    free(structs);
    return BNS_ENOMEM;
}

/* ------------------------------------------------------------------------- */
/* artifact load                                                             */
/* ------------------------------------------------------------------------- */

static int build_artifact(const cJSON *root, scrypt_artifact_t *out)
{
    int rc;
    memset(out, 0, sizeof(*out));

    const cJSON *jcontract = cJSON_GetObjectItemCaseSensitive(root, "contract");
    const cJSON *jhex      = cJSON_GetObjectItemCaseSensitive(root, "hex");
    const cJSON *jabi      = cJSON_GetObjectItemCaseSensitive(root, "abi");
    const cJSON *jstructs  = cJSON_GetObjectItemCaseSensitive(root, "structs");
    const cJSON *jstate    = cJSON_GetObjectItemCaseSensitive(root, "stateProps");

    if (!cJSON_IsString(jcontract) || !cJSON_IsString(jhex))
        return BNS_EPARSE;
    if (!cJSON_IsArray(jabi))
        return BNS_EPARSE;

    out->contract     = dup_cstr(jcontract->valuestring);
    out->hex_template = dup_cstr(jhex->valuestring);
    if (!out->contract || !out->hex_template) { rc = BNS_ENOMEM; goto fail; }

    /* structs table first (ctor/state types resolve against it). */
    rc = parse_structs(jstructs, &out->structs, &out->num_structs);
    if (rc != BNS_OK) goto fail;

    /* locate the constructor entry in the abi array. */
    const cJSON *ctor = NULL;
    int an = cJSON_GetArraySize(jabi);
    for (int i = 0; i < an; i++) {
        const cJSON *e = cJSON_GetArrayItem(jabi, i);
        const cJSON *jt = cJSON_GetObjectItemCaseSensitive(e, "type");
        if (cJSON_IsString(jt) && strcmp(jt->valuestring, "constructor") == 0) {
            ctor = e;
            break;
        }
    }
    if (ctor) {
        const cJSON *jp = cJSON_GetObjectItemCaseSensitive(ctor, "params");
        rc = parse_params(jp, out->structs, out->num_structs,
                         &out->ctor_params, &out->num_ctor_params);
        if (rc != BNS_OK) goto fail;
    }
    /* No constructor entry => zero ctor params (a contract with no ctor args). */

    /* stateProps (absent => stateless). */
    rc = parse_params(jstate, out->structs, out->num_structs,
                     &out->state_props, &out->num_state_props);
    if (rc != BNS_OK) goto fail;

    out->stateful = (out->num_state_props > 0);
    return BNS_OK;

fail:
    scrypt_artifact_free(out);
    return rc;
}

int load_artifact_from_json(const char *json_text, scrypt_artifact_t *out)
{
    if (!json_text || !out) return BNS_EINVAL;
    cJSON *root = cJSON_Parse(json_text);
    if (!root) return BNS_EPARSE;
    int rc = build_artifact(root, out);
    cJSON_Delete(root);
    return rc;
}

int load_artifact(const char *json_path, scrypt_artifact_t *out)
{
    if (!json_path || !out) return BNS_EINVAL;

    FILE *f = fopen(json_path, "rb");
    if (!f) return BNS_EPERSIST;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return BNS_EPERSIST; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return BNS_EPERSIST; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return BNS_EPERSIST; }

    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return BNS_ENOMEM; }

    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return BNS_EPERSIST; }
    buf[got] = '\0';

    int rc = load_artifact_from_json(buf, out);
    free(buf);
    if (rc == BNS_EPARSE) {
        /* differentiate read-vs-parse: file read OK above, so leave as parse. */
        return BNS_EPARSE;
    }
    return rc;
}

/* ------------------------------------------------------------------------- */
/* argument flattening                                                       */
/* ------------------------------------------------------------------------- */

/* Growable leaf accumulator. */
typedef struct {
    scrypt_leaf_t *items;
    size_t         count;
    size_t         cap;
} leaf_acc_t;

static int acc_push(leaf_acc_t *a, char *name, const scrypt_arg_t *value)
{
    if (a->count == a->cap) {
        size_t ncap = a->cap ? a->cap * 2 : 8;
        scrypt_leaf_t *ni = realloc(a->items, ncap * sizeof(*ni));
        if (!ni) return BNS_ENOMEM;
        a->items = ni;
        a->cap = ncap;
    }
    a->items[a->count].name = name;     /* takes ownership */
    a->items[a->count].value = value;   /* borrowed        */
    a->count++;
    return BNS_OK;
}

/* Find a struct definition by name in the artifact table. */
static const scrypt_struct_t *find_struct(const scrypt_artifact_t *art,
                                          const char *name)
{
    if (!name) return NULL;
    for (size_t i = 0; i < art->num_structs; i++) {
        if (art->structs[i].name && strcmp(art->structs[i].name, name) == 0)
            return &art->structs[i];
    }
    return NULL;
}

/* asprintf-style name builders that never depend on _GNU_SOURCE asprintf. */
static char *name_dot(const char *base, const char *field)
{
    size_t n = strlen(base) + 1 + strlen(field) + 1;
    char *s = malloc(n);
    if (s) snprintf(s, n, "%s.%s", base, field);
    return s;
}

static char *name_index(const char *base, size_t idx)
{
    /* "<base>[<idx>]" — single-dimension subscript (our value tree is nested
     * single-dim arrays, matching scryptlib subscript() for arraySizes.len==1). */
    char tmp[32];
    snprintf(tmp, sizeof(tmp), "[%zu]", idx);
    size_t n = strlen(base) + strlen(tmp) + 1;
    char *s = malloc(n);
    if (s) snprintf(s, n, "%s%s", base, tmp);
    return s;
}

/* Recursive flatten of one (possibly compound) value `v` carrying the dotted/
 * subscript path `path`. Scalars push one leaf; struct expands per field
 * (path.<field>); array expands per element (path[<i>]). Depth-first,
 * declaration order — exactly scryptlib flatternArg/Struct/Array. */
static int flatten_value(const scrypt_artifact_t *art,
                        const scrypt_arg_t *v, const char *path,
                        leaf_acc_t *acc)
{
    switch (v->tag) {
    case SCRYPT_TYPE_FIXED_ARRAY: {
        for (size_t i = 0; i < v->as.array.count; i++) {
            char *elem_path = name_index(path, i);
            if (!elem_path) return BNS_ENOMEM;
            int rc = flatten_value(art, &v->as.array.elems[i], elem_path, acc);
            free(elem_path);
            if (rc != BNS_OK) return rc;
        }
        return BNS_OK;
    }
    case SCRYPT_TYPE_STRUCT: {
        const scrypt_struct_t *sd = find_struct(art, v->as.st.struct_name);
        /* Walk fields in declaration order. If a struct def exists, use its field
         * names; otherwise fall back to the parallel value array with indexed
         * names (defensive — scryptlib always has the struct entity). */
        for (size_t i = 0; i < v->as.st.num_fields; i++) {
            char *field_path;
            if (sd && i < sd->num_fields && sd->fields[i].name)
                field_path = name_dot(path, sd->fields[i].name);
            else
                field_path = name_index(path, i);
            if (!field_path) return BNS_ENOMEM;
            int rc = flatten_value(art, &v->as.st.fields[i], field_path, acc);
            free(field_path);
            if (rc != BNS_OK) return rc;
        }
        return BNS_OK;
    }
    default: {
        /* scalar leaf */
        char *leaf = dup_cstr(path);
        if (!leaf) return BNS_ENOMEM;
        int rc = acc_push(acc, leaf, v);
        if (rc != BNS_OK) { free(leaf); return rc; }
        return BNS_OK;
    }
    }
}

int flatten_args(const scrypt_artifact_t *artifact,
                 const scrypt_arg_t *values, size_t num_values,
                 scrypt_leaves_t *out)
{
    if (!artifact || !out) return BNS_EINVAL;
    out->leaves = NULL;
    out->count = 0;

    if (num_values != artifact->num_ctor_params)
        return BNS_EINVAL;
    if (num_values == 0)
        return BNS_OK;
    if (!values)
        return BNS_EINVAL;

    leaf_acc_t acc = {0};
    for (size_t i = 0; i < num_values; i++) {
        const scrypt_param_t *p = &artifact->ctor_params[i];
        const scrypt_arg_t *v = &values[i];

        /* The top-level param name is the placeholder base "<name>". */
        int rc = flatten_value(artifact, v, p->name, &acc);
        if (rc != BNS_OK) {
            /* free names accumulated so far */
            for (size_t k = 0; k < acc.count; k++) free(acc.items[k].name);
            free(acc.items);
            return rc;
        }
    }

    out->leaves = acc.items;
    out->count = acc.count;
    return BNS_OK;
}

void flat_args_free(scrypt_leaves_t *leaves)
{
    if (!leaves) return;
    if (leaves->leaves) {
        for (size_t i = 0; i < leaves->count; i++)
            free(leaves->leaves[i].name);
        free(leaves->leaves);
    }
    leaves->leaves = NULL;
    leaves->count = 0;
}
