/*
 * agent_state.c — the resumable AgentState model + STATE_FILE JSON
 * (de)serialization. Faithful port of the AgentState shape in
 * scripts/agentd.ts (STATE_SCHEMA, AgentParams/DEFAULT_PARAMS, AgentState +
 * nested rabinPub/tip/state/history).
 *
 * STATE_FILE = JSON.stringify(state, null, 2): cJSON preserves insertion order,
 * so we add members in the EXACT declared field order
 * (schema, network, genesisTxid, ricardianHash, owner, agentPubKey,
 *  counterpartyPubKey, charter, params, rabinPub, identitySats, tip, state,
 *  status, history). bigints are emitted as DECIMAL STRINGS (params.* and
 * state.*); identitySats / tip.vout are JSON numbers (TS `number`).
 */
#include "scripts/agent_state.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "common/bytes.h"
#include "json/json.h"

/* DEFAULT_PARAMS = {100000, 1000000, 86400, 10000, 50000, 2}. */
void agent_params_defaults(agent_params_t *out)
{
    if (out == NULL) return;
    out->per_tx_limit         = 100000;
    out->daily_limit          = 1000000;
    out->window_duration      = 86400;
    out->graduation_threshold = 10000;
    out->validator_threshold  = 50000;
    out->recovery_threshold   = 2;
}

/* ---- free --------------------------------------------------------------- */

void agent_state_free(agent_state_t *st)
{
    if (st == NULL) return;

    free(st->schema);
    free(st->network);
    free(st->genesis_txid);
    free(st->ricardian_hash);
    free(st->owner);
    free(st->agent_pub_key);
    free(st->counterparty_pub_key);
    free(st->charter);

    free(st->rabin_pub.guardian);
    free(st->rabin_pub.own_validator);
    for (size_t i = 0; i < st->rabin_pub.num_recovery; i++)
        free(st->rabin_pub.recovery[i]);
    free(st->rabin_pub.recovery);

    free(st->tip.txid);
    free(st->tip.raw_tx_hex);

    for (size_t i = 0; i < st->num_history; i++) {
        free(st->history[i].op);
        free(st->history[i].txid);
    }
    free(st->history);

    memset(st, 0, sizeof *st);
}

/* ---- serialize ---------------------------------------------------------- *
 *
 * Hand-written JSON.stringify(state, null, 2) emitter. The vendored cJSON's
 * printer uses TAB indentation and inlines arrays, which does NOT match V8's
 * JSON.stringify(obj, null, 2) (two-space indent, ": " after keys, one array
 * element per line). The STATE_FILE must round-trip the TS bytes, so we emit the
 * exact 2-space form here (no trailing newline — TS writeFileSync writes the raw
 * stringify result). String escaping reuses json_escape_string (ECMA-262 / V8).
 */

static const char *status_str(agent_status_t s)
{
    switch (s) {
        case AGENT_STATUS_DEPLOYED: return "deployed";
        case AGENT_STATUS_ACTIONED: return "actioned";
        case AGENT_STATUS_REVOKED:  return "revoked";
    }
    return "deployed";
}

/* Append `n` levels of 2-space indent. */
static int put_indent(byte_buf_t *b, int level)
{
    for (int i = 0; i < level * 2; i++) {
        int rc = byte_buf_append_byte(b, ' ');
        if (rc != BNS_OK) return rc;
    }
    return BNS_OK;
}

/* "  \"key\": " at the given indent level. */
static int put_key(byte_buf_t *b, int level, const char *key)
{
    int rc;
    if ((rc = put_indent(b, level)) != BNS_OK) return rc;
    if ((rc = json_escape_string(key, b)) != BNS_OK) return rc;
    return byte_buf_append(b, ": ", 2);
}

/* A quoted, escaped string value. */
static int put_str_val(byte_buf_t *b, const char *v)
{
    return json_escape_string(v ? v : "", b);
}

/* A bare decimal-string value (TS bigint.toString()): "123". */
static int put_dec_str_val(byte_buf_t *b, int64_t v)
{
    int rc;
    char buf[32];
    int n = snprintf(buf, sizeof buf, "%" PRId64, v);
    if ((rc = byte_buf_append_byte(b, '"')) != BNS_OK) return rc;
    if ((rc = byte_buf_append(b, buf, (size_t)n)) != BNS_OK) return rc;
    return byte_buf_append_byte(b, '"');
}

/* A bare JSON number (TS `number`): no quotes. */
static int put_num_val(byte_buf_t *b, int64_t v)
{
    char buf[32];
    int n = snprintf(buf, sizeof buf, "%" PRId64, v);
    return byte_buf_append(b, buf, (size_t)n);
}

int agent_state_to_json(const agent_state_t *st, char **out)
{
    if (st == NULL || out == NULL) return BNS_EINVAL;
    *out = NULL;

    byte_buf_t b;
    byte_buf_init(&b);
    int rc;

#define APP(lit) do { if ((rc = byte_buf_append(&b, (lit), sizeof(lit) - 1)) != BNS_OK) goto fail; } while (0)

    APP("{\n");

    /* Top-level string fields, declaration order. */
    if ((rc = put_key(&b, 1, "schema"))             != BNS_OK) goto fail;
    if ((rc = put_str_val(&b, st->schema ? st->schema : BONSAI_AGENT_STATE_SCHEMA)) != BNS_OK) goto fail;
    APP(",\n");
    if ((rc = put_key(&b, 1, "network"))            != BNS_OK) goto fail;
    if ((rc = put_str_val(&b, st->network))         != BNS_OK) goto fail;
    APP(",\n");
    if ((rc = put_key(&b, 1, "genesisTxid"))        != BNS_OK) goto fail;
    if ((rc = put_str_val(&b, st->genesis_txid))    != BNS_OK) goto fail;
    APP(",\n");
    if ((rc = put_key(&b, 1, "ricardianHash"))      != BNS_OK) goto fail;
    if ((rc = put_str_val(&b, st->ricardian_hash))  != BNS_OK) goto fail;
    APP(",\n");
    if ((rc = put_key(&b, 1, "owner"))              != BNS_OK) goto fail;
    if ((rc = put_str_val(&b, st->owner))           != BNS_OK) goto fail;
    APP(",\n");
    if ((rc = put_key(&b, 1, "agentPubKey"))        != BNS_OK) goto fail;
    if ((rc = put_str_val(&b, st->agent_pub_key))   != BNS_OK) goto fail;
    APP(",\n");
    if ((rc = put_key(&b, 1, "counterpartyPubKey")) != BNS_OK) goto fail;
    if ((rc = put_str_val(&b, st->counterparty_pub_key)) != BNS_OK) goto fail;
    APP(",\n");
    if ((rc = put_key(&b, 1, "charter"))            != BNS_OK) goto fail;
    if ((rc = put_str_val(&b, st->charter))         != BNS_OK) goto fail;
    APP(",\n");

    /* params: Record<string,string> (bigints stringified). */
    if ((rc = put_key(&b, 1, "params")) != BNS_OK) goto fail;
    APP("{\n");
    if ((rc = put_key(&b, 2, "perTxLimit"))          != BNS_OK) goto fail;
    if ((rc = put_dec_str_val(&b, st->params.per_tx_limit)) != BNS_OK) goto fail;
    APP(",\n");
    if ((rc = put_key(&b, 2, "dailyLimit"))          != BNS_OK) goto fail;
    if ((rc = put_dec_str_val(&b, st->params.daily_limit)) != BNS_OK) goto fail;
    APP(",\n");
    if ((rc = put_key(&b, 2, "windowDuration"))      != BNS_OK) goto fail;
    if ((rc = put_dec_str_val(&b, st->params.window_duration)) != BNS_OK) goto fail;
    APP(",\n");
    if ((rc = put_key(&b, 2, "graduationThreshold")) != BNS_OK) goto fail;
    if ((rc = put_dec_str_val(&b, st->params.graduation_threshold)) != BNS_OK) goto fail;
    APP(",\n");
    if ((rc = put_key(&b, 2, "validatorThreshold"))  != BNS_OK) goto fail;
    if ((rc = put_dec_str_val(&b, st->params.validator_threshold)) != BNS_OK) goto fail;
    APP(",\n");
    if ((rc = put_key(&b, 2, "recoveryThreshold"))   != BNS_OK) goto fail;
    if ((rc = put_dec_str_val(&b, st->params.recovery_threshold)) != BNS_OK) goto fail;
    APP("\n");
    if ((rc = put_indent(&b, 1)) != BNS_OK) goto fail;
    APP("},\n");

    /* rabinPub: { guardian, ownValidator, recovery[] }. */
    if ((rc = put_key(&b, 1, "rabinPub")) != BNS_OK) goto fail;
    APP("{\n");
    if ((rc = put_key(&b, 2, "guardian"))     != BNS_OK) goto fail;
    if ((rc = put_str_val(&b, st->rabin_pub.guardian)) != BNS_OK) goto fail;
    APP(",\n");
    if ((rc = put_key(&b, 2, "ownValidator")) != BNS_OK) goto fail;
    if ((rc = put_str_val(&b, st->rabin_pub.own_validator)) != BNS_OK) goto fail;
    APP(",\n");
    if ((rc = put_key(&b, 2, "recovery"))     != BNS_OK) goto fail;
    if (st->rabin_pub.num_recovery == 0) {
        APP("[]\n");
    } else {
        APP("[\n");
        for (size_t i = 0; i < st->rabin_pub.num_recovery; i++) {
            if ((rc = put_indent(&b, 3)) != BNS_OK) goto fail;
            if ((rc = put_str_val(&b, st->rabin_pub.recovery[i])) != BNS_OK) goto fail;
            if (i + 1 < st->rabin_pub.num_recovery) APP(",\n"); else APP("\n");
        }
        if ((rc = put_indent(&b, 2)) != BNS_OK) goto fail;
    APP("]\n");
    }
    if ((rc = put_indent(&b, 1)) != BNS_OK) goto fail;
    APP("},\n");

    /* identitySats: number. */
    if ((rc = put_key(&b, 1, "identitySats")) != BNS_OK) goto fail;
    if ((rc = put_num_val(&b, st->identity_sats)) != BNS_OK) goto fail;
    APP(",\n");

    /* tip: { txid, vout(number), rawTxHex }. */
    if ((rc = put_key(&b, 1, "tip")) != BNS_OK) goto fail;
    APP("{\n");
    if ((rc = put_key(&b, 2, "txid"))     != BNS_OK) goto fail;
    if ((rc = put_str_val(&b, st->tip.txid)) != BNS_OK) goto fail;
    APP(",\n");
    if ((rc = put_key(&b, 2, "vout"))     != BNS_OK) goto fail;
    if ((rc = put_num_val(&b, (int64_t)st->tip.vout)) != BNS_OK) goto fail;
    APP(",\n");
    if ((rc = put_key(&b, 2, "rawTxHex")) != BNS_OK) goto fail;
    if ((rc = put_str_val(&b, st->tip.raw_tx_hex)) != BNS_OK) goto fail;
    APP("\n");
    if ((rc = put_indent(&b, 1)) != BNS_OK) goto fail;
    APP("},\n");

    /* state: decimal-string fields. */
    if ((rc = put_key(&b, 1, "state")) != BNS_OK) goto fail;
    APP("{\n");
    if ((rc = put_key(&b, 2, "txCount"))       != BNS_OK) goto fail;
    if ((rc = put_dec_str_val(&b, st->state.tx_count)) != BNS_OK) goto fail;
    APP(",\n");
    if ((rc = put_key(&b, 2, "spentInWindow")) != BNS_OK) goto fail;
    if ((rc = put_dec_str_val(&b, st->state.spent_in_window)) != BNS_OK) goto fail;
    APP(",\n");
    if ((rc = put_key(&b, 2, "windowStart"))   != BNS_OK) goto fail;
    if ((rc = put_dec_str_val(&b, st->state.window_start)) != BNS_OK) goto fail;
    APP(",\n");
    if ((rc = put_key(&b, 2, "tier"))          != BNS_OK) goto fail;
    if ((rc = put_dec_str_val(&b, st->state.tier)) != BNS_OK) goto fail;
    APP(",\n");
    if ((rc = put_key(&b, 2, "recoveryCount")) != BNS_OK) goto fail;
    if ((rc = put_dec_str_val(&b, st->state.recovery_count)) != BNS_OK) goto fail;
    APP("\n");
    if ((rc = put_indent(&b, 1)) != BNS_OK) goto fail;
    APP("},\n");

    /* status. */
    if ((rc = put_key(&b, 1, "status")) != BNS_OK) goto fail;
    if ((rc = put_str_val(&b, status_str(st->status))) != BNS_OK) goto fail;
    APP(",\n");

    /* history: [{ op, txid }]. */
    if ((rc = put_key(&b, 1, "history")) != BNS_OK) goto fail;
    if (st->num_history == 0) {
        APP("[]\n");
    } else {
        APP("[\n");
        for (size_t i = 0; i < st->num_history; i++) {
            if ((rc = put_indent(&b, 2)) != BNS_OK) goto fail;
    APP("{\n");
            if ((rc = put_key(&b, 3, "op"))   != BNS_OK) goto fail;
            if ((rc = put_str_val(&b, st->history[i].op))   != BNS_OK) goto fail;
    APP(",\n");
            if ((rc = put_key(&b, 3, "txid")) != BNS_OK) goto fail;
            if ((rc = put_str_val(&b, st->history[i].txid)) != BNS_OK) goto fail;
    APP("\n");
            if ((rc = put_indent(&b, 2)) != BNS_OK) goto fail;
            if (i + 1 < st->num_history) APP("},\n"); else APP("}\n");
        }
        if ((rc = put_indent(&b, 1)) != BNS_OK) goto fail;
    APP("]\n");
    }

    APP("}");

    /* NUL-terminate and hand to the caller as a plain malloc'd string. */
    if ((rc = byte_buf_append_byte(&b, '\0')) != BNS_OK) goto fail;
    {
        char *json = malloc(b.len);
        if (json == NULL) { rc = BNS_ENOMEM; goto fail; }
        memcpy(json, b.data, b.len);
        byte_buf_free(&b);
        *out = json;
        return BNS_OK;
    }

fail:
    byte_buf_free(&b);
    return rc;
}

#undef APP

/* ---- parse -------------------------------------------------------------- */

static char *dup_str(const char *s)
{
    if (s == NULL) return NULL;
    size_t n = strlen(s) + 1;
    char *d = malloc(n);
    if (d) memcpy(d, s, n);
    return d;
}

/* Read a string member into a freshly malloc'd copy (NULL if absent). */
static char *get_str(const cJSON *obj, const char *key)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsString(v) || v->valuestring == NULL) return NULL;
    return dup_str(v->valuestring);
}

/* Read a decimal-string member (TS bigint stringified) into an int64. */
static int64_t get_dec(const cJSON *obj, const char *key)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsString(v) && v->valuestring) return (int64_t)strtoll(v->valuestring, NULL, 10);
    if (cJSON_IsNumber(v)) return (int64_t)v->valuedouble;
    return 0;
}

static int64_t get_num(const cJSON *obj, const char *key)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsNumber(v)) return (int64_t)v->valuedouble;
    if (cJSON_IsString(v) && v->valuestring) return (int64_t)strtoll(v->valuestring, NULL, 10);
    return 0;
}

int agent_state_from_json(const char *json, agent_state_t *out)
{
    if (json == NULL || out == NULL) return BNS_EINVAL;
    memset(out, 0, sizeof *out);

    cJSON *root = NULL;
    int rc = json_parse(json, &root);
    if (rc != BNS_OK) return rc;

    rc = BNS_ENOMEM;

    out->schema               = get_str(root, "schema");
    out->network              = get_str(root, "network");
    out->genesis_txid         = get_str(root, "genesisTxid");
    out->ricardian_hash       = get_str(root, "ricardianHash");
    out->owner                = get_str(root, "owner");
    out->agent_pub_key        = get_str(root, "agentPubKey");
    out->counterparty_pub_key = get_str(root, "counterpartyPubKey");
    out->charter              = get_str(root, "charter");

    const cJSON *p = cJSON_GetObjectItemCaseSensitive(root, "params");
    if (p) {
        out->params.per_tx_limit         = get_dec(p, "perTxLimit");
        out->params.daily_limit          = get_dec(p, "dailyLimit");
        out->params.window_duration      = get_dec(p, "windowDuration");
        out->params.graduation_threshold = get_dec(p, "graduationThreshold");
        out->params.validator_threshold  = get_dec(p, "validatorThreshold");
        out->params.recovery_threshold   = get_dec(p, "recoveryThreshold");
    } else {
        agent_params_defaults(&out->params);
    }

    const cJSON *rp = cJSON_GetObjectItemCaseSensitive(root, "rabinPub");
    if (rp) {
        out->rabin_pub.guardian      = get_str(rp, "guardian");
        out->rabin_pub.own_validator = get_str(rp, "ownValidator");
        const cJSON *rec = cJSON_GetObjectItemCaseSensitive(rp, "recovery");
        if (cJSON_IsArray(rec)) {
            int n = cJSON_GetArraySize(rec);
            if (n > 0) {
                out->rabin_pub.recovery = calloc((size_t)n, sizeof(char *));
                if (out->rabin_pub.recovery == NULL) goto done;
                out->rabin_pub.num_recovery = (size_t)n;
                for (int i = 0; i < n; i++) {
                    const cJSON *e = cJSON_GetArrayItem(rec, i);
                    out->rabin_pub.recovery[i] =
                        (cJSON_IsString(e) && e->valuestring) ? dup_str(e->valuestring) : dup_str("");
                }
            }
        }
    }

    out->identity_sats = get_num(root, "identitySats");

    const cJSON *tip = cJSON_GetObjectItemCaseSensitive(root, "tip");
    if (tip) {
        out->tip.txid       = get_str(tip, "txid");
        out->tip.vout       = (uint32_t)get_num(tip, "vout");
        out->tip.raw_tx_hex = get_str(tip, "rawTxHex");
    }

    const cJSON *s = cJSON_GetObjectItemCaseSensitive(root, "state");
    if (s) {
        out->state.tx_count        = get_dec(s, "txCount");
        out->state.spent_in_window = get_dec(s, "spentInWindow");
        out->state.window_start    = get_dec(s, "windowStart");
        out->state.tier            = get_dec(s, "tier");
        out->state.recovery_count  = get_dec(s, "recoveryCount");
    }

    {
        const cJSON *stv = cJSON_GetObjectItemCaseSensitive(root, "status");
        const char *sv = (cJSON_IsString(stv) && stv->valuestring) ? stv->valuestring : "deployed";
        if (strcmp(sv, "revoked") == 0)       out->status = AGENT_STATUS_REVOKED;
        else if (strcmp(sv, "actioned") == 0) out->status = AGENT_STATUS_ACTIONED;
        else                                  out->status = AGENT_STATUS_DEPLOYED;
    }

    const cJSON *h = cJSON_GetObjectItemCaseSensitive(root, "history");
    if (cJSON_IsArray(h)) {
        int n = cJSON_GetArraySize(h);
        if (n > 0) {
            out->history = calloc((size_t)n, sizeof(agent_history_entry_t));
            if (out->history == NULL) goto done;
            out->num_history = (size_t)n;
            for (int i = 0; i < n; i++) {
                const cJSON *e = cJSON_GetArrayItem(h, i);
                out->history[i].op   = get_str(e, "op");
                out->history[i].txid = get_str(e, "txid");
            }
        }
    }

    rc = BNS_OK;

done:
    cJSON_Delete(root);
    if (rc != BNS_OK) agent_state_free(out);
    return rc;
}
