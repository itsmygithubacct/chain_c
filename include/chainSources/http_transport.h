/*
 * http_transport.h — the injectable HTTP transport seam (the C analogue of the
 * TS `fetchFn` injection), so whats_on_chain / woc_client are testable offline.
 *
 * The TS chain sources accept an injected `fetch` (FetchFn) and only depend on a
 * minimal structural FetchResponse {ok, status, text(), json()}. The C port
 * mirrors that: an http_transport_t vtable with a single request() entry point
 * and an http_response_t carrying the status + body bytes. A libcurl-backed
 * implementation (http_transport_curl) is used in production; a stub
 * (http_transport_stub) feeds canned responses to unit tests.
 *
 * No <curl/...> appears here — the libcurl handle lives behind the opaque `ctx`.
 *
 * TS origin: src/chainSources/whatsOnChain.ts FetchFn / FetchResponse; the
 * WocClient HTTP layer. status is the raw HTTP status code so the WoC rate
 * limiter's is429() and the 404-as-sentinel logic can see it (plan.risks #13:
 * the status MUST flow through; never collapse to a bool).
 */
#ifndef BONSAI_CHAINSOURCES_HTTP_TRANSPORT_H
#define BONSAI_CHAINSOURCES_HTTP_TRANSPORT_H

#include <stddef.h>
#include "common/error.h"
#include "common/bytes.h"

/* A completed HTTP response. `status` is the numeric HTTP status (e.g. 200, 404,
 * 429); `body` owns the raw response bytes. TS: FetchResponse {ok, status,
 * text(), json()} — `ok` is derived as (status >= 200 && status < 300). */
typedef struct {
    int        status; /* HTTP status code (0 == transport failure before a reply) */
    byte_buf_t body;   /* owned response body bytes                                */
} http_response_t;

/* Free an http_response_t's owned body (NULL-safe). */
void http_response_free(http_response_t *r);

/* The injectable transport vtable. TS: FetchFn. */
typedef struct http_transport_s http_transport_t;
struct http_transport_s {
    void *ctx; /* implementation-private state (curl handle / stub script)         */

    /* Perform one request. `method` is "GET"/"POST"; `url` the absolute URL;
     * `headers` is an array of `nheaders` "Name: value" strings (may be NULL/0);
     * `body`/`body_len` is the request body (NULL/0 for GET). On a completed
     * exchange fills *out (caller frees via http_response_free) and returns
     * BNS_OK even for 4xx/5xx (the status is carried in out->status). Returns
     * BNS_ENET only when no HTTP reply was obtained (DNS/connect/timeout).
     * TS: fetch(url, init). */
    int (*request)(void *ctx, const char *method, const char *url,
                   const char *const *headers, size_t nheaders,
                   const char *body, size_t body_len,
                   http_response_t *out);

    /* Release implementation-private state (NULL-safe). */
    void (*free)(void *ctx);
};

/* ---- factories ---------------------------------------------------------- */

/* Build a libcurl-backed transport into *out (caller releases via
 * out->free(out->ctx)). TS: globalThis.fetch. BNS_OK / BNS_ENOMEM / BNS_ENET. */
int http_transport_curl(http_transport_t *out);

/* One canned (request-pattern -> response) entry for the test stub. A NULL
 * `url_substr` matches any URL; the first matching script entry (in order) wins.
 * `status` + `body`/`body_len` populate the synthesized http_response_t. */
typedef struct {
    const char *method_substr; /* match if method contains this (NULL = any)      */
    const char *url_substr;    /* match if URL contains this (NULL = any)         */
    int         status;        /* status to return                                */
    const char *body;          /* response body (NUL-terminated; may be NULL)     */
    size_t      body_len;      /* body length (0 => strlen(body) if body != NULL) */
} http_stub_entry_t;

/* Build a deterministic stub transport from an ordered script of `count`
 * entries (borrowed for the transport's lifetime) into *out. Unmatched requests
 * yield BNS_ENET (no reply). TS: an injected stub fetchFn in tests.
 * BNS_OK / BNS_ENOMEM. */
int http_transport_stub(const http_stub_entry_t *entries, size_t count,
                        http_transport_t *out);

#endif /* BONSAI_CHAINSOURCES_HTTP_TRANSPORT_H */
