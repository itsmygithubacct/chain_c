/*
 * woc_client.c — WocClient: the single rate-limited, reliability-hardened
 * WhatsOnChain client. Port of src/chainSources/wocClient.ts (TxState, TxStatus,
 * interpretTxStatus, WaitOpts, WocClient).
 *
 * WoC QUIRKS preserved (header doc + plan.risks #13):
 *  - BASE hard-coded mainnet: "https://api.whatsonchain.com/v1/bsv/main".
 *  - get() order: 404-allow -> 429 (carry status so the limiter's is_429 fires)
 *    -> non-ok. Every call runs through woc_rate_limited (serialise + backoff).
 *  - interpretTxStatus reads WIRE key 'blockheight' (lowercase);
 *    Number(confirmations ?? 0); >= 1 => confirmed.
 *  - txStatus short-circuits to 'confirmed' WITHOUT a raw fetch when
 *    confirmations >= 1 (preserves HTTP call counts).
 *  - isOutputSpent: 404 => false (unspent; index may lag); else !!body.txid.
 *  - broadcast derives txid from raw bytes and only checks the provider body.
 *  - waitForMempool checks rawTx FIRST then deadline (>= 1 attempt);
 *    waitForConfirmation order: confirmation -> unknown/dropped -> deadline.
 */
#include "chainSources/woc_client.h"
#include "chainSources/woc_rate_limiter.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/bytes.h"
#include "common/hex.h"
#include "crypto/hash.h"
#include "json/json.h"

/* ---- handle ------------------------------------------------------------- */

struct woc_client_s {
    const http_transport_t *transport;  /* borrowed                            */
    woc_sleep_fn            sleep;       /* NULL => default real sleep          */
    void                   *sleep_user;
};

static bool http_ok(int status)
{
    return status >= 200 && status < 300;
}

static char *join_url(const char *path)
{
    size_t lb = strlen(BONSAI_WOC_CLIENT_BASE);
    size_t lp = strlen(path);
    char  *u  = (char *)malloc(lb + lp + 1);
    if (u == NULL) {
        return NULL;
    }
    memcpy(u, BONSAI_WOC_CLIENT_BASE, lb);
    memcpy(u + lb, path, lp);
    u[lb + lp] = '\0';
    return u;
}

static int64_t now_ms_wall(void)
{
    /* Wall clock so wait-loop deadlines match Date.now() semantics. */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void default_sleep(void *user, int64_t ms)
{
    (void)user;
    if (ms <= 0) {
        return;
    }
    struct timespec req;
    req.tv_sec  = (time_t)(ms / 1000);
    req.tv_nsec = (long)((ms % 1000) * 1000000L);
    while (nanosleep(&req, &req) == -1) {
        /* EINTR: req holds the remainder; loop. */
    }
}

static void client_sleep(woc_client_t *c, int64_t ms)
{
    if (c->sleep != NULL) {
        c->sleep(c->sleep_user, ms);
    } else {
        default_sleep(NULL, ms);
    }
}

/* ---- gated GET ---------------------------------------------------------- */

/* Per-request gated state. The gated fn performs the HTTP exchange and applies
 * the get() ordering, leaving the consumed response in `res` (when not a 404
 * sentinel). */
typedef struct {
    woc_client_t   *c;
    const char     *url;
    bool            allow404;
    /* outputs */
    http_response_t res;       /* valid iff have_res                          */
    bool            have_res;  /* false on 404-allow sentinel                 */
    bool            is_404;    /* 404 with allow404                           */
} get_state_t;

static int gated_get(void *user, int *out_status)
{
    get_state_t *g = (get_state_t *)user;

    http_response_t res;
    int rc = g->c->transport->request(g->c->transport->ctx, "GET", g->url,
                                      NULL, 0, NULL, 0, &res);
    if (rc != BNS_OK) {
        *out_status = 0;
        return rc; /* BNS_ENET: no reply (propagates, non-retryable) */
    }

    *out_status = res.status;

    /* TS get() order: 404-allow -> 429 -> non-ok. */
    if (res.status == 404 && g->allow404) {
        http_response_free(&res);
        g->have_res = false;
        g->is_404   = true;
        return BNS_OK; /* null sentinel */
    }
    if (res.status == 429) {
        http_response_free(&res);
        return BNS_ENET; /* status 429 carried -> limiter retries */
    }
    if (!http_ok(res.status)) {
        http_response_free(&res);
        return BNS_ENET; /* TS: throw `WoC GET ...: HTTP <status>` */
    }

    g->res      = res;
    g->have_res = true;
    g->is_404   = false;
    return BNS_OK;
}

/* Run a rate-limited GET. On BNS_OK either g->have_res (response owned by
 * caller, free via http_response_free) or g->is_404 (null sentinel). */
static int woc_get(woc_client_t *c, const char *path, bool allow404,
                   get_state_t *g)
{
    g->c        = c;
    g->allow404 = allow404;
    g->have_res = false;
    g->is_404   = false;
    g->res.status = 0;
    byte_buf_init(&g->res.body);

    g->url = join_url(path);
    if (g->url == NULL) {
        return BNS_ENOMEM;
    }

    int rc = woc_rate_limited(gated_get, g, NULL);
    free((void *)g->url);
    g->url = NULL;
    return rc;
}

/* NUL-terminated copy of a response body (caller frees). */
static char *body_dup(const http_response_t *res)
{
    size_t n  = res->body.len;
    char  *s  = (char *)malloc(n + 1);
    if (s == NULL) {
        return NULL;
    }
    if (n > 0) {
        memcpy(s, res->body.data, n);
    }
    s[n] = '\0';
    return s;
}

/* Trimmed copy of a response body (caller frees). */
static char *body_dup_trim(const http_response_t *res)
{
    const char *p   = res->body.data ? (const char *)res->body.data : "";
    size_t      len = res->body.len;
    size_t      a   = 0;
    while (a < len) {
        unsigned char c = (unsigned char)p[a];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
            c == '\f' || c == '\v') {
            a++;
        } else {
            break;
        }
    }
    size_t b = len;
    while (b > a) {
        unsigned char c = (unsigned char)p[b - 1];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
            c == '\f' || c == '\v') {
            b--;
        } else {
            break;
        }
    }
    size_t n = b - a;
    char  *s = (char *)malloc(n + 1);
    if (s == NULL) {
        return NULL;
    }
    memcpy(s, p + a, n);
    s[n] = '\0';
    return s;
}

/* ---- JSON number -> int64 (fail-closed) --------------------------------- */

/* WoC sends satoshi/height/fee/confirmation values as JS numbers (doubles). A
 * double represents integers exactly only up to 2^53; a value above that would
 * cast to a wrong-but-deterministic int64 and corrupt funding-sum math. Any
 * legitimate single value is <= MAX_MONEY (21e6 * 1e8 ~= 2.1e15 < 2^53), so
 * valid data is always exact and behaviour is unchanged — only finite,
 * non-negative, integral values <= 2^53 are accepted; junk fails closed.
 * Returns 1 and writes *out on success, 0 on violation (*out left untouched). */
static int woc_json_i64(const cJSON *n, int64_t *out)
{
    if (!cJSON_IsNumber(n)) {
        return 0;
    }
    double d = n->valuedouble;
    if (!isfinite(d) || d < 0.0 || floor(d) != d || d > 9007199254740992.0) {
        return 0;
    }
    *out = (int64_t)d;
    return 1;
}

/* Satoshi-amount variant. A single on-chain value can never legitimately exceed
 * the total BSV money supply (BONSAI_MAX_MONEY = 21e6 * 1e8 = 2.1e15 sats), which
 * is already < 2^53 so the woc_json_i64 exactness/non-negativity guard holds for
 * every legal value (happy path unchanged). Bounding to MAX_MONEY here fails an
 * inflated `value` CLOSED at parse time, so a malicious/buggy WoC response cannot
 * feed a near-2^53 entry into the downstream funding/output SUM accumulators
 * (utxo_select funding_utxos_total, wallet total_in loops, tx_change out_sum).
 * Returns 1 and writes *out on success; 0 (out untouched) on any violation. */
static int woc_json_money(const cJSON *n, int64_t *out)
{
    int64_t v;
    if (!woc_json_i64(n, &v) || v > BONSAI_MAX_MONEY) {
        return 0;
    }
    *out = v;
    return 1;
}

/* Signed variant for balance fields. The WhatsOnChain balance endpoint can
 * legitimately return a NEGATIVE `unconfirmed` value (net pending spends from
 * confirmed UTXOs), so the non-negative guard above would wrongly clamp it to 0.
 * Same finite/integral/exactness guard, magnitude bounded to +/-2^53, sign kept. */
static int woc_json_i64_signed(const cJSON *n, int64_t *out)
{
    if (!cJSON_IsNumber(n)) {
        return 0;
    }
    double d = n->valuedouble;
    if (!isfinite(d) || floor(d) != d ||
        d > 9007199254740992.0 || d < -9007199254740992.0) {
        return 0;
    }
    *out = (int64_t)d;
    return 1;
}

/* ---- pure status fusion ------------------------------------------------- */

int interpret_tx_status(bool raw_present,
                        int64_t confirmations,
                        int64_t blockheight, bool has_blockheight,
                        tx_status_t *out)
{
    if (out == NULL) {
        return BNS_EINVAL;
    }
    if (confirmations >= 1) {
        out->state            = TX_STATE_CONFIRMED;
        out->confirmations    = confirmations;
        out->block_height     = has_blockheight ? blockheight : 0;
        out->has_block_height = has_blockheight;
        return BNS_OK;
    }
    if (raw_present) {
        out->state            = TX_STATE_MEMPOOL;
        out->confirmations    = 0;
        out->block_height     = 0;
        out->has_block_height = false;
        return BNS_OK;
    }
    out->state            = TX_STATE_UNKNOWN;
    out->confirmations    = 0;
    out->block_height     = 0;
    out->has_block_height = false;
    return BNS_OK;
}

/* ---- lifecycle ---------------------------------------------------------- */

int woc_client_new(const woc_client_opts_t *opts, woc_client_t **out)
{
    if (opts == NULL || out == NULL || opts->transport == NULL) {
        return BNS_EINVAL;
    }
    woc_client_t *c = (woc_client_t *)calloc(1, sizeof(*c));
    if (c == NULL) {
        return BNS_ENOMEM;
    }
    c->transport  = opts->transport;
    c->sleep      = opts->sleep;
    c->sleep_user = opts->sleep_user;
    *out = c;
    return BNS_OK;
}

void woc_client_free(woc_client_t *c)
{
    free(c);
}

/* ---- internal seam (not in the frozen header) --------------------------- *
 * throttled_provider's non-override fee path must reach the rate-limited
 * transport. The TS getFeePerKb delegates to scrypt-ts's WhatsonchainProvider
 * (node_modules — not portable); we expose a rate-limited WoC fee-rate GET here
 * and let throttled_provider forward-declare it. */
int woc_client_internal_fee_per_kb(woc_client_t *c, int64_t *out_fee_per_kb);

int woc_client_internal_fee_per_kb(woc_client_t *c, int64_t *out_fee_per_kb)
{
    if (c == NULL || out_fee_per_kb == NULL) {
        return BNS_EINVAL;
    }
    *out_fee_per_kb = 0;

    /* WoC fee-rate endpoint (scrypt-ts WhatsonchainProvider.getFeePerKb hits
     * GET /fee/rate returning {feePerKb} on mainnet). */
    get_state_t g;
    int rc = woc_get(c, "/fee/rate", false, &g);
    if (rc != BNS_OK) {
        return rc;
    }

    char *text = body_dup(&g.res);
    http_response_free(&g.res);
    if (text == NULL) {
        return BNS_ENOMEM;
    }

    cJSON *root = NULL;
    rc = json_parse(text, &root);
    free(text);
    if (rc != BNS_OK) {
        return BNS_EPARSE;
    }

    cJSON *fpk = cJSON_GetObjectItemCaseSensitive(root, "feePerKb");
    if (!woc_json_i64(fpk, out_fee_per_kb)) {
        cJSON_Delete(root);
        return BNS_EPARSE;
    }
    cJSON_Delete(root);
    return BNS_OK;
}

/* ---- operations --------------------------------------------------------- */

int woc_client_raw_tx(woc_client_t *c, const char *txid, char **out_hex)
{
    if (c == NULL || txid == NULL || out_hex == NULL) {
        return BNS_EINVAL;
    }
    *out_hex = NULL;

    char path[160];
    snprintf(path, sizeof(path), "/tx/%s/hex", txid);

    get_state_t g;
    int rc = woc_get(c, path, true, &g);
    if (rc != BNS_OK) {
        return rc;
    }
    if (g.is_404) {
        return BNS_OK; /* null: node doesn't have it */
    }

    char *hex = body_dup_trim(&g.res);
    http_response_free(&g.res);
    if (hex == NULL) {
        return BNS_ENOMEM;
    }
    *out_hex = hex;
    return BNS_OK;
}

/* Parse the /tx/hash body for confirmations + blockheight (lowercase wire key).
 * Sets *has_bh to mirror presence of the 'blockheight' key. */
static int parse_hash_body(const char *text, int64_t *confirmations,
                           int64_t *blockheight, bool *has_bh)
{
    *confirmations = 0;
    *blockheight   = 0;
    *has_bh        = false;

    cJSON *root = NULL;
    int rc = json_parse(text, &root);
    if (rc != BNS_OK) {
        return BNS_EPARSE;
    }

    cJSON *conf = cJSON_GetObjectItemCaseSensitive(root, "confirmations");
    /* Out-of-range/non-integral junk leaves the 0 default (fail-closed). */
    (void)woc_json_i64(conf, confirmations);
    /* WIRE key is lowercase 'blockheight'. null/out-of-range => absent. */
    cJSON *bh = cJSON_GetObjectItemCaseSensitive(root, "blockheight");
    if (woc_json_i64(bh, blockheight)) {
        *has_bh = true;
    }
    cJSON_Delete(root);
    return BNS_OK;
}

int woc_client_tx_status(woc_client_t *c, const char *txid, tx_status_t *out)
{
    if (c == NULL || txid == NULL || out == NULL) {
        return BNS_EINVAL;
    }

    char path[160];
    snprintf(path, sizeof(path), "/tx/hash/%s", txid);

    get_state_t g;
    int rc = woc_get(c, path, true, &g);
    if (rc != BNS_OK) {
        return rc;
    }

    int64_t confirmations = 0, blockheight = 0;
    bool    has_bh = false;
    bool    hash_present = false;

    if (!g.is_404) {
        hash_present = true;
        char *text = body_dup(&g.res);
        http_response_free(&g.res);
        if (text == NULL) {
            return BNS_ENOMEM;
        }
        rc = parse_hash_body(text, &confirmations, &blockheight, &has_bh);
        free(text);
        if (rc != BNS_OK) {
            return rc;
        }
    }
    (void)hash_present;

    /* Short-circuit: confirmed without a raw fetch when confirmations >= 1. */
    if (confirmations >= 1) {
        return interpret_tx_status(true, confirmations, blockheight, has_bh, out);
    }

    /* Otherwise pay for the raw fetch to distinguish mempool from unknown. */
    char *raw = NULL;
    rc = woc_client_raw_tx(c, txid, &raw);
    if (rc != BNS_OK) {
        return rc;
    }
    bool raw_present = (raw != NULL);
    free(raw);
    return interpret_tx_status(raw_present, confirmations, blockheight, has_bh, out);
}

int woc_client_is_output_spent(woc_client_t *c, const char *txid, uint32_t vout,
                               bool *out_spent)
{
    if (c == NULL || txid == NULL || out_spent == NULL) {
        return BNS_EINVAL;
    }
    *out_spent = false;

    char path[176];
    snprintf(path, sizeof(path), "/tx/%s/%u/spent", txid, vout);

    get_state_t g;
    int rc = woc_get(c, path, true, &g);
    if (rc != BNS_OK) {
        return rc;
    }
    if (g.is_404) {
        *out_spent = false; /* 404 = unspent (index may lag) */
        return BNS_OK;
    }

    char *text = body_dup(&g.res);
    http_response_free(&g.res);
    if (text == NULL) {
        return BNS_ENOMEM;
    }

    cJSON *root = NULL;
    rc = json_parse(text, &root);
    free(text);
    if (rc != BNS_OK) {
        return BNS_EPARSE;
    }

    /* !!body?.txid : present & non-empty string. */
    cJSON *tx = cJSON_GetObjectItemCaseSensitive(root, "txid");
    *out_spent = cJSON_IsString(tx) && tx->valuestring != NULL &&
                 tx->valuestring[0] != '\0';
    cJSON_Delete(root);
    return BNS_OK;
}

void woc_utxos_free(woc_utxos_t *u)
{
    if (u == NULL) {
        return;
    }
    free(u->items);
    u->items = NULL;
    u->count = 0;
}

int woc_client_list_utxos(woc_client_t *c, const char *address, woc_utxos_t *out)
{
    if (c == NULL || address == NULL || out == NULL) {
        return BNS_EINVAL;
    }
    out->items = NULL;
    out->count = 0;

    char path[160];
    snprintf(path, sizeof(path), "/address/%s/unspent", address);

    get_state_t g;
    int rc = woc_get(c, path, false, &g);
    if (rc != BNS_OK) {
        return rc;
    }

    char *text = body_dup(&g.res);
    http_response_free(&g.res);
    if (text == NULL) {
        return BNS_ENOMEM;
    }

    cJSON *root = NULL;
    rc = json_parse(text, &root);
    free(text);
    if (rc != BNS_OK) {
        return BNS_EPARSE;
    }
    if (!cJSON_IsArray(root)) {
        cJSON_Delete(root);
        return BNS_EPARSE;
    }

    int n = cJSON_GetArraySize(root);
    if (n > 0) {
        out->items = (woc_utxo_t *)calloc((size_t)n, sizeof(woc_utxo_t));
        if (out->items == NULL) {
            cJSON_Delete(root);
            return BNS_ENOMEM;
        }
    }

    int idx = 0;
    cJSON *e = NULL;
    cJSON_ArrayForEach(e, root) {
        woc_utxo_t *u = &out->items[idx];
        /* WoC wire field names: tx_hash, tx_pos, value, height. */
        cJSON *th = cJSON_GetObjectItemCaseSensitive(e, "tx_hash");
        cJSON *tp = cJSON_GetObjectItemCaseSensitive(e, "tx_pos");
        cJSON *vl = cJSON_GetObjectItemCaseSensitive(e, "value");
        cJSON *ht = cJSON_GetObjectItemCaseSensitive(e, "height");

        if (cJSON_IsString(th) && th->valuestring != NULL) {
            strncpy(u->tx_hash, th->valuestring, sizeof(u->tx_hash) - 1);
            u->tx_hash[sizeof(u->tx_hash) - 1] = '\0';
        } else {
            u->tx_hash[0] = '\0';
        }
        /* tx_pos: route through the finite/integral/range-guarded helper (like value/
         * height). A direct (uint32_t)valuedouble of an out-of-range double is C UB and
         * yields a garbage vout. Fail-closed to 0 outside [0, UINT32_MAX]. */
        {
            int64_t tp_i = 0;
            u->tx_pos = (woc_json_i64(tp, &tp_i) && tp_i <= (int64_t)UINT32_MAX)
                            ? (uint32_t)tp_i : 0;
        }
        /* Satoshi value: fail-closed to 0 on out-of-range/junk. Uses the
         * MAX_MONEY-bounded helper so an inflated `value` (> the money supply)
         * is rejected here and can never inflate a downstream funding sum.
         * Height keeps the plain i64 guard (heights are not money). */
        if (!woc_json_money(vl, &u->value)) {
            u->value = 0;
        }
        if (!woc_json_i64(ht, &u->height)) {
            u->height = 0;
        }
        idx++;
    }
    out->count = (size_t)idx;

    cJSON_Delete(root);
    return BNS_OK;
}

int woc_client_balance(woc_client_t *c, const char *address, woc_balance_t *out)
{
    if (c == NULL || address == NULL || out == NULL) {
        return BNS_EINVAL;
    }
    out->confirmed   = 0;
    out->unconfirmed = 0;

    char path[160];
    snprintf(path, sizeof(path), "/address/%s/balance", address);

    get_state_t g;
    int rc = woc_get(c, path, false, &g);
    if (rc != BNS_OK) {
        return rc;
    }

    char *text = body_dup(&g.res);
    http_response_free(&g.res);
    if (text == NULL) {
        return BNS_ENOMEM;
    }

    cJSON *root = NULL;
    rc = json_parse(text, &root);
    free(text);
    if (rc != BNS_OK) {
        return BNS_EPARSE;
    }

    cJSON *cf = cJSON_GetObjectItemCaseSensitive(root, "confirmed");
    cJSON *uc = cJSON_GetObjectItemCaseSensitive(root, "unconfirmed");
    /* Satoshi balances: fail-closed to 0 on out-of-range/junk. */
    if (!woc_json_i64(cf, &out->confirmed)) {
        out->confirmed = 0;
    }
    if (!woc_json_i64_signed(uc, &out->unconfirmed)) {  /* unconfirmed may be negative */
        out->unconfirmed = 0;
    }
    cJSON_Delete(root);
    return BNS_OK;
}

int woc_client_pick_funding(woc_client_t *c, const char *address,
                            const rank_opts_t *opts,
                            funding_utxo_t *out, bool *out_found)
{
    if (c == NULL || address == NULL || out == NULL || out_found == NULL) {
        return BNS_EINVAL;
    }
    *out_found = false;

    woc_utxos_t utxos;
    int rc = woc_client_list_utxos(c, address, &utxos);
    if (rc != BNS_OK) {
        return rc;
    }

    funding_utxos_t ranked;
    rc = rank_funding_utxos(utxos.items, utxos.count, opts, &ranked);
    woc_utxos_free(&utxos);
    if (rc != BNS_OK) {
        return rc;
    }

    for (size_t i = 0; i < ranked.count; i++) {
        const funding_utxo_t *u = &ranked.items[i];
        bool spent = false;
        rc = woc_client_is_output_spent(c, u->tx_id, u->output_index, &spent);
        if (rc != BNS_OK) {
            funding_utxos_free(&ranked);
            return rc;
        }
        if (!spent) {
            *out       = *u;
            *out_found = true;
            funding_utxos_free(&ranked);
            return BNS_OK;
        }
    }

    funding_utxos_free(&ranked);
    return BNS_OK; /* none survived (TS null) */
}

/* ---- broadcast ---------------------------------------------------------- */

typedef struct {
    woc_client_t   *c;
    const char     *url;
    const char     *body;
    size_t          body_len;
    http_response_t res;
    bool            have_res;
} post_state_t;

static int gated_post(void *user, int *out_status)
{
    post_state_t *p = (post_state_t *)user;
    static const char *hdrs[1] = { "Content-Type: application/json" };

    http_response_t res;
    int rc = p->c->transport->request(p->c->transport->ctx, "POST", p->url,
                                      hdrs, 1, p->body, p->body_len, &res);
    if (rc != BNS_OK) {
        *out_status = 0;
        return rc;
    }
    *out_status = res.status;

    /* TS broadcast: body = (await res.text()).trim(); 429 first, then !ok. */
    if (res.status == 429) {
        http_response_free(&res);
        return BNS_ENET; /* status 429 carried -> limiter retries */
    }
    if (!http_ok(res.status)) {
        /* Surface WoC's rejection reason instead of swallowing it as a bare BNS_ENET — the body
         * carries the real cause (e.g. "...mempool conflict", "tx-size", "66: insufficient priority"). */
        fprintf(stderr, "[woc] broadcast rejected: HTTP %d — %.*s\n", res.status,
                (int)(res.body.len > 500 ? 500 : res.body.len),
                res.body.data ? (const char *)res.body.data : "");
        http_response_free(&res);
        return BNS_ENET; /* TS: throw `WoC broadcast: HTTP ...` */
    }

    p->res      = res;
    p->have_res = true;
    return BNS_OK;
}

static int txid_from_raw_hex(const char *raw_hex, char **out_txid)
{
    *out_txid = NULL;
    byte_buf_t raw;
    byte_buf_init(&raw);
    int rc = hex_decode(raw_hex, &raw);
    if (rc != BNS_OK) {
        byte_buf_free(&raw);
        return rc;
    }
    if (raw.len == 0) {
        byte_buf_free(&raw);
        return BNS_EINVAL;
    }

    uint8_t hash[BONSAI_SHA256_LEN], display[BONSAI_SHA256_LEN];
    sha256d(raw.data, raw.len, hash);
    byte_buf_free(&raw);
    for (size_t i = 0; i < BONSAI_SHA256_LEN; i++)
        display[i] = hash[BONSAI_SHA256_LEN - 1 - i];
    *out_txid = hex_encode(display, sizeof display);
    return *out_txid != NULL ? BNS_OK : BNS_ENOMEM;
}

static bool response_matches_txid(const char *body, size_t start, size_t len,
                                  const char *expected)
{
    if (len != 2 * BONSAI_SHA256_LEN) return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)body[start + i];
        if (!isxdigit(c) || (char)tolower(c) != expected[i]) return false;
    }
    return true;
}

int woc_client_broadcast(woc_client_t *c, const char *raw_hex, char **out_txid)
{
    if (c == NULL || raw_hex == NULL || out_txid == NULL) {
        return BNS_EINVAL;
    }
    *out_txid = NULL;

    /* A transaction's id is a property of its signed bytes, not of the HTTP
     * provider's response. Compute it before sending so malformed raw hex is
     * rejected locally and every accepted broadcast is persisted under the
     * correct, independently derived id. */
    char *expected_txid = NULL;
    int rc = txid_from_raw_hex(raw_hex, &expected_txid);
    if (rc != BNS_OK) return rc;

    /* Debug hook: dump the exact raw tx hex about to be broadcast (BONSAI_DUMP_RAWTX=1). */
    if (getenv("BONSAI_DUMP_RAWTX") != NULL) {
        fprintf(stderr, "[rawtx] %s\n", raw_hex);
    }

    /* JSON body {"txhex": rawHex} via the escaping serializer. */
    cJSON *obj = cJSON_CreateObject();
    if (obj == NULL) {
        free(expected_txid);
        return BNS_ENOMEM;
    }
    if (cJSON_AddStringToObject(obj, "txhex", raw_hex) == NULL) {
        cJSON_Delete(obj);
        free(expected_txid);
        return BNS_ENOMEM;
    }
    char *json = NULL;
    rc = json_print_compact(obj, &json);
    cJSON_Delete(obj);
    if (rc != BNS_OK) {
        free(expected_txid);
        return rc;
    }

    char *url = join_url("/tx/raw");
    if (url == NULL) {
        free(json);
        free(expected_txid);
        return BNS_ENOMEM;
    }

    post_state_t p;
    p.c        = c;
    p.url      = url;
    p.body     = json;
    p.body_len = strlen(json);
    p.have_res = false;
    p.res.status = 0;
    byte_buf_init(&p.res.body);

    rc = woc_rate_limited(gated_post, &p, NULL);
    free(url);
    free(json);
    if (rc != BNS_OK) {
        free(expected_txid);
        return rc;
    }

    /* trim then strip a SINGLE leading and a SINGLE trailing double-quote. */
    char *body = body_dup_trim(&p.res);
    http_response_free(&p.res);
    if (body == NULL) {
        fprintf(stderr, "[woc] WARNING: broadcast was accepted but its response could not be "
                        "inspected; using locally computed txid %s for recovery/state\n", expected_txid);
        *out_txid = expected_txid;
        return BNS_OK;
    }

    size_t len = strlen(body);
    size_t start = 0;
    if (len > 0 && body[0] == '"') {
        start = 1;
        len--;
    }
    if (len > 0 && body[start + len - 1] == '"') {
        len--;
    }

    if (!response_matches_txid(body, start, len, expected_txid)) {
        fprintf(stderr, "[woc] WARNING: broadcast returned an invalid or mismatched txid; "
                        "using locally computed txid %s for recovery/state\n", expected_txid);
    }
    free(body);

    *out_txid = expected_txid;
    return BNS_OK;
}

/* ---- wait loops --------------------------------------------------------- */

int woc_client_wait_for_mempool(woc_client_t *c, const char *txid,
                                const woc_wait_opts_t *opts)
{
    if (c == NULL || txid == NULL) {
        return BNS_EINVAL;
    }
    int64_t timeout_ms  = (opts != NULL && opts->has_timeout_ms)
                              ? opts->timeout_ms : BONSAI_WOC_MEMPOOL_TIMEOUT_MS;
    int64_t interval_ms = (opts != NULL && opts->has_interval_ms)
                              ? opts->interval_ms : BONSAI_WOC_MEMPOOL_INTERVAL_MS;
    int64_t deadline = now_ms_wall() + timeout_ms;

    for (;;) {
        char *raw = NULL;
        int rc = woc_client_raw_tx(c, txid, &raw);
        if (rc != BNS_OK) {
            return rc;
        }
        if (raw != NULL) {
            free(raw);
            return BNS_OK;
        }
        if (now_ms_wall() >= deadline) {
            return BNS_ENOTFOUND; /* TS: throw `waitForMempool: ... not seen` */
        }
        client_sleep(c, interval_ms);
    }
}

int woc_client_wait_for_confirmation(woc_client_t *c, const char *txid,
                                     const woc_wait_opts_t *opts,
                                     tx_status_t *out)
{
    if (c == NULL || txid == NULL || out == NULL) {
        return BNS_EINVAL;
    }
    int64_t timeout_ms  = (opts != NULL && opts->has_timeout_ms)
                              ? opts->timeout_ms : BONSAI_WOC_CONFIRM_TIMEOUT_MS;
    int64_t interval_ms = (opts != NULL && opts->has_interval_ms)
                              ? opts->interval_ms : BONSAI_WOC_CONFIRM_INTERVAL_MS;
    int64_t target      = (opts != NULL && opts->has_confirmations)
                              ? opts->confirmations : 1;
    int64_t deadline = now_ms_wall() + timeout_ms;

    for (;;) {
        tx_status_t st;
        int rc = woc_client_tx_status(c, txid, &st);
        if (rc != BNS_OK) {
            return rc;
        }
        /* Order: confirmation -> unknown/dropped -> deadline. */
        if (st.confirmations >= target) {
            *out = st;
            return BNS_OK;
        }
        if (st.state == TX_STATE_UNKNOWN) {
            return BNS_ENOTFOUND; /* TS: throw `... not in mempool (dropped?)` */
        }
        if (now_ms_wall() >= deadline) {
            return BNS_ENOTFOUND; /* TS: throw `... not confirmed in ...ms` */
        }
        client_sleep(c, interval_ms);
    }
}
