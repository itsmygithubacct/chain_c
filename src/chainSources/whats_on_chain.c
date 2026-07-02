/*
 * whats_on_chain.c — WhatsOnChainSource: a live chain_source_t implementation
 * backed by the WhatsOnChain REST API over an injectable http_transport_t.
 *
 * Port of src/chainSources/whatsOnChain.ts (WhatsOnChainSource,
 * WhatsOnChainOpts). Implements getRawTx / getTime / getSpendingTxid on the
 * chain_source_t vtable (include/reputation_indexer.h).
 *
 * WoC QUIRKS preserved (header doc + plan.risks #13):
 *  - URL paths interpolated RAW (no URL-encoding): "/tx/{txid}/hex",
 *    "/tx/hash/{txid}", "/tx/{txid}/{vout}/spent".
 *  - Base default "https://api.whatsonchain.com/v1/bsv/{network}", net "main".
 *  - getRawTx returns the body TRIMMED.
 *  - getTime uses blocktime || time (JS truthy): present-but-zero blocktime
 *    falls through to time; both zero/absent => loud error (never returns 0).
 *  - getSpendingTxid: HTTP 404 => NULL BEFORE the !ok check; other non-2xx =>
 *    error; else body.txid ?? NULL.
 *  - the woc-api-key header is sent ONLY when an API key is present.
 */
#include "chainSources/whats_on_chain.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>   /* isfinite/floor — guard the untrusted JSON time before the int64 cast */

#include "json/json.h"

/* ---- handle ------------------------------------------------------------- */

struct whats_on_chain_s {
    char                   *base;       /* owned: resolved base URL              */
    char                   *api_header; /* owned or NULL: "woc-api-key: <key>"   */
    const http_transport_t *transport;  /* borrowed (must outlive the source)    */
};

/* HTTP ok == 200..299 (TS: res.ok). */
static bool http_ok(int status)
{
    return status >= 200 && status < 300;
}

/* Build "<base><path>" into a freshly malloc'd string (caller frees). */
static char *join_url(const char *base, const char *path)
{
    size_t lb = strlen(base);
    size_t lp = strlen(path);
    char  *u  = (char *)malloc(lb + lp + 1);
    if (u == NULL) {
        return NULL;
    }
    memcpy(u, base, lb);
    memcpy(u + lb, path, lp);
    u[lb + lp] = '\0';
    return u;
}

/* Perform GET <base><path> through the transport, sending the api-key header
 * when present. Fills *out (caller frees via http_response_free). */
static int woc_get(const whats_on_chain_t *src, const char *path,
                   http_response_t *out)
{
    char *url = join_url(src->base, path);
    if (url == NULL) {
        return BNS_ENOMEM;
    }

    const char *hdrs[1];
    size_t      nh = 0;
    if (src->api_header != NULL) {
        hdrs[0] = src->api_header;
        nh      = 1;
    }

    int rc = src->transport->request(src->transport->ctx, "GET", url,
                                     nh ? hdrs : NULL, nh, NULL, 0, out);
    free(url);
    return rc;
}

/* ---- lifecycle ---------------------------------------------------------- */

int whats_on_chain_new(const whats_on_chain_opts_t *opts, whats_on_chain_t **out)
{
    if (opts == NULL || out == NULL || opts->transport == NULL) {
        return BNS_EINVAL;
    }

    whats_on_chain_t *src = (whats_on_chain_t *)calloc(1, sizeof(*src));
    if (src == NULL) {
        return BNS_ENOMEM;
    }

    if (opts->base_url != NULL) {
        src->base = strdup(opts->base_url);
    } else {
        const char *net = (opts->network == WOC_NETWORK_TEST) ? "test" : "main";
        size_t      need = strlen(BONSAI_WOC_BASE_TEMPLATE) + strlen(net) + 1;
        src->base = (char *)malloc(need);
        if (src->base != NULL) {
            snprintf(src->base, need, BONSAI_WOC_BASE_TEMPLATE, net);
        }
    }
    if (src->base == NULL) {
        free(src);
        return BNS_ENOMEM;
    }

    if (opts->api_key != NULL) {
        size_t need = strlen("woc-api-key: ") + strlen(opts->api_key) + 1;
        src->api_header = (char *)malloc(need);
        if (src->api_header == NULL) {
            free(src->base);
            free(src);
            return BNS_ENOMEM;
        }
        snprintf(src->api_header, need, "woc-api-key: %s", opts->api_key);
    }

    src->transport = opts->transport;
    *out = src;
    return BNS_OK;
}

void whats_on_chain_free(whats_on_chain_t *src)
{
    if (src == NULL) {
        return;
    }
    free(src->base);
    free(src->api_header);
    free(src);
}

/* ---- operations --------------------------------------------------------- */

/* Trim ASCII whitespace from both ends of [s, s+len), returning a freshly
 * malloc'd NUL-terminated copy of the trimmed span (caller frees). Mirrors
 * String.prototype.trim() over the chars JS treats as whitespace for the WoC
 * hex bodies (space, \t, \n, \r, \f, \v). */
static char *trim_dup(const char *s, size_t len)
{
    size_t start = 0;
    while (start < len) {
        unsigned char c = (unsigned char)s[start];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
            c == '\f' || c == '\v') {
            start++;
        } else {
            break;
        }
    }
    size_t end = len;
    while (end > start) {
        unsigned char c = (unsigned char)s[end - 1];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
            c == '\f' || c == '\v') {
            end--;
        } else {
            break;
        }
    }
    size_t n = end - start;
    char  *r = (char *)malloc(n + 1);
    if (r == NULL) {
        return NULL;
    }
    memcpy(r, s + start, n);
    r[n] = '\0';
    return r;
}

/* getRawTx(txid): GET /tx/{txid}/hex; !ok => BNS_ENET; else trimmed body. */
static int woc_get_raw_tx(void *ctx, const char *txid, char **out_hex)
{
    whats_on_chain_t *src = (whats_on_chain_t *)ctx;
    if (src == NULL || txid == NULL || out_hex == NULL) {
        return BNS_EINVAL;
    }
    *out_hex = NULL;

    char path[160];
    snprintf(path, sizeof(path), "/tx/%s/hex", txid);

    http_response_t res;
    int rc = woc_get(src, path, &res);
    if (rc != BNS_OK) {
        return rc; /* BNS_ENET: no reply */
    }

    if (!http_ok(res.status)) {
        http_response_free(&res);
        return BNS_ENET; /* TS: throw `getRawTx ...: HTTP <status>` */
    }

    char *hex = trim_dup((const char *)(res.body.data ? (char *)res.body.data : ""),
                         res.body.len);
    http_response_free(&res);
    if (hex == NULL) {
        return BNS_ENOMEM;
    }
    *out_hex = hex;
    return BNS_OK;
}

/* getTime(txid): GET /tx/hash/{txid}; !ok => error; t = blocktime || time;
 * !t => loud error (never 0). */
static int woc_get_time(void *ctx, const char *txid, int64_t *out_time)
{
    whats_on_chain_t *src = (whats_on_chain_t *)ctx;
    if (src == NULL || txid == NULL || out_time == NULL) {
        return BNS_EINVAL;
    }
    *out_time = 0;

    char path[160];
    snprintf(path, sizeof(path), "/tx/hash/%s", txid);

    http_response_t res;
    int rc = woc_get(src, path, &res);
    if (rc != BNS_OK) {
        return rc;
    }

    if (!http_ok(res.status)) {
        http_response_free(&res);
        return BNS_ENET; /* TS: throw `getTime ...: HTTP <status>` */
    }

    /* NUL-terminate the body for json_parse. */
    char *text = trim_dup((const char *)(res.body.data ? (char *)res.body.data : ""),
                          res.body.len);
    http_response_free(&res);
    if (text == NULL) {
        return BNS_ENOMEM;
    }

    cJSON *root = NULL;
    rc = json_parse(text, &root);
    free(text);
    if (rc != BNS_OK) {
        return BNS_EPARSE;
    }

    /* t = data.blocktime || data.time (JS truthy: a present-but-0 falls through).
     * Numbers may arrive as JSON number; treat 0 / absent / non-number as falsy. */
    cJSON *bt = cJSON_GetObjectItemCaseSensitive(root, "blocktime");
    cJSON *tm = cJSON_GetObjectItemCaseSensitive(root, "time");

    int64_t t = 0;
    double td = 0.0;
    if (cJSON_IsNumber(bt) && bt->valuedouble != 0) {
        td = bt->valuedouble;
    } else if (cJSON_IsNumber(tm) && tm->valuedouble != 0) {
        td = tm->valuedouble;
    }
    /* Guard the untrusted JSON number before the int64 cast: cJSON sets valuedouble to +/-HUGE_VAL
     * on strtod overflow, and (int64_t)inf/NaN/out-of-range is C undefined behavior. Accept only a
     * finite, positive, integral value within 2^53; otherwise leave t=0 so the t==0 fail-closed
     * branch below fires (review-2 #8). */
    if (isfinite(td) && td > 0.0 && td <= 9007199254740992.0 && floor(td) == td) {
        t = (int64_t)td;
    }

    cJSON_Delete(root);

    if (t == 0) {
        /* Neither timestamp usable: fail loudly (never silently coerce to 0). */
        return BNS_EPARSE;
    }
    *out_time = t;
    return BNS_OK;
}

/* getSpendingTxid(txid, vout): GET /tx/{txid}/{vout}/spent; 404 => NULL BEFORE
 * the !ok check; other non-2xx => error; else body.txid ?? NULL. */
static int woc_get_spending_txid(void *ctx, const char *txid, uint32_t vout,
                                 char **out_spender)
{
    whats_on_chain_t *src = (whats_on_chain_t *)ctx;
    if (src == NULL || txid == NULL || out_spender == NULL) {
        return BNS_EINVAL;
    }
    *out_spender = NULL;

    char path[176];
    snprintf(path, sizeof(path), "/tx/%s/%u/spent", txid, vout);

    http_response_t res;
    int rc = woc_get(src, path, &res);
    if (rc != BNS_OK) {
        return rc;
    }

    if (res.status == 404) {
        http_response_free(&res);
        return BNS_OK; /* unspent sentinel: *out_spender stays NULL */
    }
    if (!http_ok(res.status)) {
        http_response_free(&res);
        return BNS_ENET; /* TS: throw `getSpendingTxid ...: HTTP <status>` */
    }

    char *text = trim_dup((const char *)(res.body.data ? (char *)res.body.data : ""),
                          res.body.len);
    http_response_free(&res);
    if (text == NULL) {
        return BNS_ENOMEM;
    }

    cJSON *root = NULL;
    rc = json_parse(text, &root);
    free(text);
    if (rc != BNS_OK) {
        return BNS_EPARSE;
    }

    /* data?.txid ?? null — null/absent/non-string body => NULL sentinel. */
    cJSON *tx = cJSON_GetObjectItemCaseSensitive(root, "txid");
    if (cJSON_IsString(tx) && tx->valuestring != NULL) {
        char *dup = strdup(tx->valuestring);
        cJSON_Delete(root);
        if (dup == NULL) {
            return BNS_ENOMEM;
        }
        *out_spender = dup;
        return BNS_OK;
    }

    cJSON_Delete(root);
    return BNS_OK; /* NULL sentinel */
}

int whats_on_chain_as_source(whats_on_chain_t *src, chain_source_t *out_vtable)
{
    if (src == NULL || out_vtable == NULL) {
        return BNS_EINVAL;
    }
    out_vtable->ctx               = src;
    out_vtable->get_raw_tx        = woc_get_raw_tx;
    out_vtable->get_time          = woc_get_time;
    out_vtable->get_spending_txid = woc_get_spending_txid;
    return BNS_OK;
}
