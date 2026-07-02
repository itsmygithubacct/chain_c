/*
 * json.h — thin cJSON wrapper + the canonical (sorted-key) JSON serializer.
 *
 * Two distinct serializers live here, and they MUST NOT be conflated:
 *  - cJSON's own printer preserves INSERTION ORDER, matching V8
 *    JSON.stringify() — used for STATE_FILE / .sig sidecars where the TS uses
 *    JSON.stringify(obj, null, 2) and order follows object-literal order.
 *  - canonical_json() is a hand-written SORTED-KEY serializer (keys ascending
 *    by byte value, no spaces) used by ricardianCharter.canonicalJSON — the
 *    deployment-binding preimage. JS Array.sort() default is lexicographic by
 *    UTF-16 code unit == byte order for the ASCII keys involved.
 *
 * TS origin: src/ricardianCharter.ts canonicalJSON / canonicalContractBytes;
 * scripts JSON.stringify(...,null,2). String escaping follows ECMA-262 JSON.
 *
 * cJSON is included here so consumers get the cJSON type via this wrapper.
 */
#ifndef BONSAI_JSON_JSON_H
#define BONSAI_JSON_JSON_H

#include <stddef.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"
#include "cJSON.h"

/* ---- parse / print convenience ------------------------------------------ */

/* Parse a NUL-terminated JSON string. *out is a cJSON tree the caller frees via
 * cJSON_Delete. TS: JSON.parse. BNS_OK / BNS_EPARSE. */
int json_parse(const char *text, cJSON **out);

/* Pretty-print with 2-space indent, INSERTION ORDER preserved, plus a trailing
 * '\n' — matches the TS `JSON.stringify(obj, null, 2) + '\n'` sidecar/state form.
 * *out is freshly malloc'd (caller frees). BNS_OK / BNS_ENOMEM. */
int json_print_pretty2_nl(const cJSON *item, char **out);

/* Compact print (no whitespace), insertion order. TS: JSON.stringify(obj).
 * *out is freshly malloc'd (caller frees). BNS_OK / BNS_ENOMEM. */
int json_print_compact(const cJSON *item, char **out);

/* ---- canonical (sorted-key) serializer ---------------------------------- */

/* Serialize a FLAT string->string object as ricardianCharter.canonicalJSON:
 * sort keys ascending by byte value, then
 *   '{' + sortedKeys.map(k => jsonStr(k)+':'+jsonStr(obj[k])).join(',') + '}'
 * with NO spaces and ECMA-262 escaping on every key and value. Only string
 * values are supported (the binding is all strings). Non-string values =>
 * BNS_EINVAL. *out is freshly malloc'd (caller frees).
 * TS: src/ricardianCharter.ts::canonicalJSON. BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int canonical_json(const cJSON *flat_string_object, char **out);

/* ---- string escaping ---------------------------------------------------- */

/* JSON.stringify of a single STRING value: wrap in double quotes and escape
 * \" \\ \b \f \n \r \t and control chars < 0x20 as \u00XX, per ECMA-262.
 * Appends the quoted+escaped result to `out` (init'd). TS: JSON.stringify(str).
 * BNS_OK / BNS_ENOMEM. */
int json_escape_string(const char *s, byte_buf_t *out);

#endif /* BONSAI_JSON_JSON_H */
