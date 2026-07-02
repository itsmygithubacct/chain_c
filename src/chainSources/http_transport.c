/*
 * http_transport.c — the injectable HTTP transport seam.
 *
 * Two implementations of the http_transport_t vtable declared in
 * include/chainSources/http_transport.h:
 *
 *   - http_transport_curl: a libcurl easy-handle backed transport used in
 *     production. GET/POST with woc-api-key / Content-Type headers, request
 *     body via CURLOPT_POSTFIELDS, the response body streamed into a byte_buf
 *     via CURLOPT_WRITEFUNCTION, and the raw HTTP status read back from
 *     CURLINFO_RESPONSE_CODE (so the WoC rate limiter's is429() and the
 *     404-as-sentinel logic can see it — plan.risks #13: status MUST flow
 *     through, never collapse to a bool).
 *
 *   - http_transport_stub: a deterministic canned-response transport for unit
 *     tests, mirroring the injected stub fetchFn used in the TS tests.
 *
 * TS origin: src/chainSources/whatsOnChain.ts FetchFn / FetchResponse. The C
 * port maps `fetch(url, init)` onto request(ctx, method, url, headers, body)
 * and the structural FetchResponse {ok, status, ...} onto http_response_t
 * {status, body} (ok being derived by the caller as 200<=status<300).
 */
#include "chainSources/http_transport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

/* ---- http_response_t ---------------------------------------------------- */

void http_response_free(http_response_t *r)
{
    if (r == NULL) {
        return;
    }
    byte_buf_free(&r->body);
    r->status = 0;
}

/* ===================== libcurl-backed transport ========================== */

/* curl_global_init() must run exactly once before any easy handle is used and
 * is not thread-safe; we do it under a one-shot guard. The transport never
 * calls curl_global_cleanup() — global teardown across a process with multiple
 * possible curl users is unsafe to sequence, and leaking the global init at
 * exit is the conventional, harmless choice for a long-lived library. */
static int g_curl_global_inited = 0;

static int ensure_curl_global(void)
{
    if (!g_curl_global_inited) {
        if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
            return BNS_ENET;
        }
        g_curl_global_inited = 1;
    }
    return BNS_OK;
}

/* Bounds for an untrusted WhatsOnChain exchange. Without these, one stalled or
 * hostile endpoint wedges ALL chain I/O (the call is made under the process-global
 * rate-limiter mutex) and/or OOMs the host by streaming an unbounded body. */
#define HTTP_CONNECT_TIMEOUT_S 15L                       /* TCP/TLS connect cap        */
#define HTTP_TOTAL_TIMEOUT_S   60L                       /* whole-request cap          */
#define HTTP_LOW_SPEED_LIMIT   64L                       /* < this many bytes/sec ...  */
#define HTTP_LOW_SPEED_TIME_S  20L                       /* ... for this long => abort */
#define HTTP_MAX_BODY_BYTES    (64UL * 1024UL * 1024UL)  /* 64 MiB response ceiling    */

/* CURLOPT_WRITEFUNCTION sink: append the chunk into the caller's byte_buf.
 * Returning a short count aborts the transfer (on OOM, or when the body exceeds
 * HTTP_MAX_BODY_BYTES — the real cap for chunked replies with no Content-Length,
 * which CURLOPT_MAXFILESIZE cannot catch). */
static size_t curl_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    byte_buf_t *body = (byte_buf_t *)userdata;
    size_t total = size * nmemb;
    if (total == 0) {
        return 0;
    }
    if (body->len > HTTP_MAX_BODY_BYTES - total) {
        return 0; /* would exceed the response ceiling -> abort the transfer */
    }
    if (byte_buf_append(body, ptr, total) != BNS_OK) {
        return 0; /* signal failure to libcurl */
    }
    return total;
}

static int curl_request(void *ctx, const char *method, const char *url,
                        const char *const *headers, size_t nheaders,
                        const char *body, size_t body_len,
                        http_response_t *out)
{
    CURL *easy = (CURL *)ctx;
    struct curl_slist *hdr_list = NULL;
    http_response_t resp;
    int rc = BNS_ENET;
    CURLcode cc;
    long http_status = 0;
    bool woc_key_attached = false;

    if (easy == NULL || method == NULL || url == NULL || out == NULL) {
        return BNS_EINVAL;
    }

    resp.status = 0;
    byte_buf_init(&resp.body);

    curl_easy_reset(easy);

    curl_easy_setopt(easy, CURLOPT_URL, url);
    curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(easy, CURLOPT_WRITEDATA, (void *)&resp.body);
    curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(easy, CURLOPT_USERAGENT, "bonsai-chain-c/1.0");
    /* Bounded timeouts: curl_easy_reset() cleared every option, so without these a
     * stalled/slowloris peer blocks curl_easy_perform() indefinitely while holding
     * the global rate-limiter mutex, wedging all chain I/O. A timeout maps to a
     * CURLE error below -> rc=BNS_ENET and the mutex is released. */
    curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT, HTTP_CONNECT_TIMEOUT_S);
    curl_easy_setopt(easy, CURLOPT_TIMEOUT, HTTP_TOTAL_TIMEOUT_S);
    curl_easy_setopt(easy, CURLOPT_LOW_SPEED_LIMIT, HTTP_LOW_SPEED_LIMIT);
    curl_easy_setopt(easy, CURLOPT_LOW_SPEED_TIME, HTTP_LOW_SPEED_TIME_S);
    curl_easy_setopt(easy, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)HTTP_MAX_BODY_BYTES);

    /* Method selection. POST carries the body via CURLOPT_POSTFIELDS so the
     * exact bytes (and length, which permits NULs) are sent verbatim. */
    if (strcmp(method, "POST") == 0) {
        curl_easy_setopt(easy, CURLOPT_POST, 1L);
        curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE, (long)body_len);
        curl_easy_setopt(easy, CURLOPT_POSTFIELDS,
                         (const char *)(body != NULL ? body : ""));
    } else if (strcmp(method, "GET") == 0) {
        curl_easy_setopt(easy, CURLOPT_HTTPGET, 1L);
    } else {
        /* Any other verb (HEAD/PUT/DELETE) — honour it explicitly. */
        curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, method);
        if (body != NULL && body_len > 0) {
            curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE, (long)body_len);
            curl_easy_setopt(easy, CURLOPT_POSTFIELDS, (const char *)body);
        }
    }

    /* Caller-supplied headers (e.g. "woc-api-key: ...", "Content-Type: ..."). */
    for (size_t i = 0; i < nheaders; i++) {
        if (headers == NULL || headers[i] == NULL) {
            continue;
        }
        if (strncmp(headers[i], "woc-api-key:", 12) == 0) {
            woc_key_attached = true;
        }
        struct curl_slist *next = curl_slist_append(hdr_list, headers[i]);
        if (next == NULL) {
            rc = BNS_ENOMEM;
            goto cleanup;
        }
        hdr_list = next;
    }

    /* Rate-limit relief: attach the WoC API key (env WOC_API_KEY) to WhatsOnChain requests so the
     * higher paid-tier limit applies instead of the ~3 req/s free tier. Only for whatsonchain.com URLs,
     * and only if the caller didn't already supply the header. Mirrors the Python wallet + poorwallet_41. */
    {
        const char *woc_key = getenv("WOC_API_KEY");
        if (woc_key != NULL && woc_key[0] != '\0' && strstr(url, "whatsonchain.com") != NULL) {
            bool already = false;
            for (size_t i = 0; i < nheaders; i++) {
                if (headers != NULL && headers[i] != NULL &&
                    strncmp(headers[i], "woc-api-key:", 12) == 0) { already = true; break; }
            }
            char hdr[600];
            int n = snprintf(hdr, sizeof hdr, "woc-api-key: %s", woc_key);
            if (!already && n > 0 && (size_t)n < sizeof hdr) {
                struct curl_slist *next = curl_slist_append(hdr_list, hdr);
                if (next == NULL) { rc = BNS_ENOMEM; goto cleanup; }
                hdr_list = next;
                woc_key_attached = true;
            }
        }
    }

    if (hdr_list != NULL) {
        curl_easy_setopt(easy, CURLOPT_HTTPHEADER, hdr_list);
    }

    /* libcurl does NOT strip custom headers on a cross-host redirect, so a
     * redirect would leak the woc-api-key to the redirect target. WhatsOnChain
     * endpoints never legitimately redirect, so disable redirect-following for
     * any request that carries the key (overrides the default FOLLOWLOCATION). */
    if (woc_key_attached) {
        curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 0L);
    }

    cc = curl_easy_perform(easy);
    if (cc != CURLE_OK) {
        /* No HTTP reply obtained (DNS/connect/timeout, or our write sink
         * aborted on OOM). The header contract maps this to BNS_ENET. */
        rc = BNS_ENET;
        goto cleanup;
    }

    curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &http_status);
    resp.status = (int)http_status;

    /* Hand the completed exchange to the caller. 4xx/5xx are BNS_OK — the
     * status rides through in out->status. */
    *out = resp;
    byte_buf_init(&resp.body); /* ownership transferred to *out */
    rc = BNS_OK;

cleanup:
    if (hdr_list != NULL) {
        curl_slist_free_all(hdr_list);
    }
    if (rc != BNS_OK) {
        byte_buf_free(&resp.body);
    }
    return rc;
}

static void curl_free_ctx(void *ctx)
{
    if (ctx != NULL) {
        curl_easy_cleanup((CURL *)ctx);
    }
}

int http_transport_curl(http_transport_t *out)
{
    CURL *easy;
    int rc;

    if (out == NULL) {
        return BNS_EINVAL;
    }

    rc = ensure_curl_global();
    if (rc != BNS_OK) {
        return rc;
    }

    easy = curl_easy_init();
    if (easy == NULL) {
        return BNS_ENOMEM;
    }

    out->ctx     = easy;
    out->request = curl_request;
    out->free    = curl_free_ctx;
    return BNS_OK;
}

/* ========================= test stub transport =========================== */

/* Stub ctx: the borrowed ordered script. Heap-allocated only so out->free can
 * release it uniformly; the entries themselves are borrowed (not copied). */
typedef struct {
    const http_stub_entry_t *entries;
    size_t                   count;
} stub_ctx_t;

/* A substring needle matches if it is NULL (wildcard) or contained in hay. */
static int substr_match(const char *needle, const char *hay)
{
    if (needle == NULL) {
        return 1;
    }
    if (hay == NULL) {
        return 0;
    }
    return strstr(hay, needle) != NULL;
}

static int stub_request(void *ctx, const char *method, const char *url,
                        const char *const *headers, size_t nheaders,
                        const char *body, size_t body_len,
                        http_response_t *out)
{
    stub_ctx_t *sc = (stub_ctx_t *)ctx;

    (void)headers;
    (void)nheaders;
    (void)body;
    (void)body_len;

    if (sc == NULL || method == NULL || url == NULL || out == NULL) {
        return BNS_EINVAL;
    }

    for (size_t i = 0; i < sc->count; i++) {
        const http_stub_entry_t *e = &sc->entries[i];
        if (!substr_match(e->method_substr, method)) {
            continue;
        }
        if (!substr_match(e->url_substr, url)) {
            continue;
        }

        /* First matching entry wins. Synthesize the canned response. */
        out->status = e->status;
        byte_buf_init(&out->body);
        if (e->body != NULL) {
            size_t len = e->body_len != 0 ? e->body_len : strlen(e->body);
            if (len > 0) {
                if (byte_buf_from(&out->body, e->body, len) != BNS_OK) {
                    byte_buf_free(&out->body);
                    out->status = 0;
                    return BNS_ENOMEM;
                }
            }
        }
        return BNS_OK;
    }

    /* No script entry matched: behave like a transport with no reply. */
    return BNS_ENET;
}

static void stub_free_ctx(void *ctx)
{
    free(ctx);
}

int http_transport_stub(const http_stub_entry_t *entries, size_t count,
                         http_transport_t *out)
{
    stub_ctx_t *sc;

    if (out == NULL || (entries == NULL && count != 0)) {
        return BNS_EINVAL;
    }

    sc = (stub_ctx_t *)malloc(sizeof(*sc));
    if (sc == NULL) {
        return BNS_ENOMEM;
    }
    sc->entries = entries;
    sc->count   = count;

    out->ctx     = sc;
    out->request = stub_request;
    out->free    = stub_free_ctx;
    return BNS_OK;
}
