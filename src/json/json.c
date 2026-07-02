/*
 * json.c — thin cJSON wrapper + the canonical (sorted-key) JSON serializer.
 *
 * See include/json/json.h for the contract. Two serializers:
 *   - cJSON's own printer (insertion order) for V8 JSON.stringify(...,null,2)
 *     state/sidecar parity (json_print_pretty2_nl / json_print_compact).
 *   - canonical_json(): hand-written sorted-key serializer matching
 *     src/ricardianCharter.ts::canonicalJSON.
 *
 * String escaping (json_escape_string) follows ECMA-262 JSON.stringify:
 *   \" \\ \b \f \n \r \t escaped as two-char sequences; control chars < 0x20
 *   as \u00xx (lowercase hex); forward slash '/' NOT escaped; bytes >= 0x20
 *   (including UTF-8 multibyte sequences) passed through verbatim — V8 emits
 *   the literal character for valid (including astral) codepoints, so passing
 *   the UTF-8 bytes through reproduces JSON.stringify byte-for-byte.
 */
#include "json/json.h"

#include <stdlib.h>
#include <string.h>

#include "cJSON.h"

/* ---- parse / print convenience ------------------------------------------ */

int json_parse(const char *text, cJSON **out)
{
    if (out == NULL) {
        return BNS_EINVAL;
    }
    *out = NULL;
    if (text == NULL) {
        return BNS_EPARSE;
    }
    cJSON *tree = cJSON_Parse(text);
    if (tree == NULL) {
        return BNS_EPARSE;
    }
    *out = tree;
    return BNS_OK;
}

int json_print_pretty2_nl(const cJSON *item, char **out)
{
    if (out == NULL) {
        return BNS_EINVAL;
    }
    *out = NULL;
    if (item == NULL) {
        return BNS_EINVAL;
    }
    /* cJSON_Print uses 2-space indentation, insertion order, ECMA-262 escaping
     * — matching V8 JSON.stringify(obj, null, 2). Append the trailing '\n'. */
    char *pretty = cJSON_Print(item);
    if (pretty == NULL) {
        return BNS_ENOMEM;
    }
    size_t len = strlen(pretty);
    char *withnl = malloc(len + 2);
    if (withnl == NULL) {
        cJSON_free(pretty);
        return BNS_ENOMEM;
    }
    memcpy(withnl, pretty, len);
    withnl[len] = '\n';
    withnl[len + 1] = '\0';
    cJSON_free(pretty);
    *out = withnl;
    return BNS_OK;
}

int json_print_compact(const cJSON *item, char **out)
{
    if (out == NULL) {
        return BNS_EINVAL;
    }
    *out = NULL;
    if (item == NULL) {
        return BNS_EINVAL;
    }
    /* cJSON_PrintUnformatted: no whitespace, insertion order. We re-home the
     * result into a plain malloc'd buffer so the caller frees it with free()
     * regardless of how cJSON was configured. */
    char *compact = cJSON_PrintUnformatted(item);
    if (compact == NULL) {
        return BNS_ENOMEM;
    }
    size_t len = strlen(compact);
    char *copy = malloc(len + 1);
    if (copy == NULL) {
        cJSON_free(compact);
        return BNS_ENOMEM;
    }
    memcpy(copy, compact, len + 1);
    cJSON_free(compact);
    *out = copy;
    return BNS_OK;
}

/* ---- string escaping ---------------------------------------------------- */

int json_escape_string(const char *s, byte_buf_t *out)
{
    static const char hexdig[] = "0123456789abcdef";

    if (out == NULL) {
        return BNS_EINVAL;
    }
    if (s == NULL) {
        return BNS_EINVAL;
    }

    int rc = byte_buf_append_byte(out, (uint8_t)'"');
    if (rc != BNS_OK) {
        return rc;
    }

    for (const unsigned char *p = (const unsigned char *)s; *p != '\0'; ++p) {
        unsigned char c = *p;
        switch (c) {
        case '"':
            rc = byte_buf_append(out, "\\\"", 2);
            break;
        case '\\':
            rc = byte_buf_append(out, "\\\\", 2);
            break;
        case '\b':
            rc = byte_buf_append(out, "\\b", 2);
            break;
        case '\f':
            rc = byte_buf_append(out, "\\f", 2);
            break;
        case '\n':
            rc = byte_buf_append(out, "\\n", 2);
            break;
        case '\r':
            rc = byte_buf_append(out, "\\r", 2);
            break;
        case '\t':
            rc = byte_buf_append(out, "\\t", 2);
            break;
        default:
            if (c < 0x20) {
                /* \u00xx, lowercase hex — matches ECMA-262 / V8. */
                char esc[6];
                esc[0] = '\\';
                esc[1] = 'u';
                esc[2] = '0';
                esc[3] = '0';
                esc[4] = hexdig[(c >> 4) & 0x0f];
                esc[5] = hexdig[c & 0x0f];
                rc = byte_buf_append(out, esc, 6);
            } else {
                /* >= 0x20, including UTF-8 continuation/lead bytes: verbatim. */
                rc = byte_buf_append_byte(out, c);
            }
            break;
        }
        if (rc != BNS_OK) {
            return rc;
        }
    }

    return byte_buf_append_byte(out, (uint8_t)'"');
}

/* ---- canonical (sorted-key) serializer ---------------------------------- */

/* Comparator for qsort over an array of cJSON* members, ordering by the
 * object key (->string) bytewise ascending. JS Array.prototype.sort() default
 * compares by UTF-16 code unit; for the BMP/ASCII keys used here that is
 * identical to an unsigned-byte (UTF-8) comparison of the key strings. */
static int member_key_cmp(const void *pa, const void *pb)
{
    const cJSON *a = *(const cJSON *const *)pa;
    const cJSON *b = *(const cJSON *const *)pb;
    const char *ka = (a->string != NULL) ? a->string : "";
    const char *kb = (b->string != NULL) ? b->string : "";
    /* strcmp compares unsigned char values on conforming implementations? No:
     * strcmp is defined in terms of unsigned char, so it is exactly bytewise
     * ascending — which is what JS sort gives for ASCII keys. */
    return strcmp(ka, kb);
}

int canonical_json(const cJSON *flat_string_object, char **out)
{
    if (out == NULL) {
        return BNS_EINVAL;
    }
    *out = NULL;
    if (flat_string_object == NULL || !cJSON_IsObject(flat_string_object)) {
        return BNS_EINVAL;
    }

    /* Count members and validate every value is a string. */
    size_t n = 0;
    for (const cJSON *m = flat_string_object->child; m != NULL; m = m->next) {
        if (!cJSON_IsString(m) || m->valuestring == NULL || m->string == NULL) {
            return BNS_EINVAL;
        }
        n++;
    }

    cJSON **members = NULL;
    if (n > 0) {
        members = malloc(n * sizeof(*members));
        if (members == NULL) {
            return BNS_ENOMEM;
        }
        size_t i = 0;
        for (const cJSON *m = flat_string_object->child; m != NULL; m = m->next) {
            members[i++] = (cJSON *)m;
        }
        qsort(members, n, sizeof(*members), member_key_cmp);
    }

    byte_buf_t buf;
    byte_buf_init(&buf);
    int rc = byte_buf_append_byte(&buf, (uint8_t)'{');
    if (rc != BNS_OK) {
        goto fail;
    }

    for (size_t i = 0; i < n; ++i) {
        if (i > 0) {
            rc = byte_buf_append_byte(&buf, (uint8_t)',');
            if (rc != BNS_OK) {
                goto fail;
            }
        }
        rc = json_escape_string(members[i]->string, &buf);
        if (rc != BNS_OK) {
            goto fail;
        }
        rc = byte_buf_append_byte(&buf, (uint8_t)':');
        if (rc != BNS_OK) {
            goto fail;
        }
        rc = json_escape_string(members[i]->valuestring, &buf);
        if (rc != BNS_OK) {
            goto fail;
        }
    }

    rc = byte_buf_append_byte(&buf, (uint8_t)'}');
    if (rc != BNS_OK) {
        goto fail;
    }
    /* NUL-terminate so the result is a C string. */
    rc = byte_buf_append_byte(&buf, 0);
    if (rc != BNS_OK) {
        goto fail;
    }

    free(members);
    /* Hand the owned buffer to the caller as a plain malloc'd string. */
    *out = (char *)buf.data;
    return BNS_OK;

fail:
    free(members);
    byte_buf_free(&buf);
    return rc;
}
