/*
 * mock_http_transport.h — a recording http_transport_t (http_transport.h) stub
 * for the offline whats_on_chain / woc_client tests. The C port of the TS
 * mockFetch route table (whatsOnChain.test.ts).
 *
 * Unlike the library's static http_transport_stub (a borrowed const script),
 * this owns its registered responses, supports dynamic enqueue/register at
 * runtime, and RECORDS every request (method+url+body) so a test can assert what
 * the client actually sent.
 *
 * Matching: a request matches the first registered route whose `url_suffix`
 * matches end-of-URL (TS mockFetch keys are URL suffixes / endpoint paths) AND
 * whose `method` matches (NULL method = any). A route may be one-shot (consumed)
 * or sticky (reusable). With no match, request() returns the configured
 * `default_status` body (TS mockFetch returns 404/'' on miss).
 */
#ifndef BONSAI_TEST_MOCK_HTTP_TRANSPORT_H
#define BONSAI_TEST_MOCK_HTTP_TRANSPORT_H

#include <stddef.h>
#include <stdbool.h>
#include "common/error.h"
#include "chainSources/http_transport.h"   /* http_transport_t, http_response_t */

/* Opaque recording stub. Owns all registered route strings + the request log. */
typedef struct mock_http_s mock_http_t;

/* A captured request (TS: the `calls` array of URLs, extended with method/body). */
typedef struct {
    char  *method;   /* owned copy ("GET"/"POST")        */
    char  *url;      /* owned copy of the absolute URL   */
    char  *body;     /* owned copy of the request body (NUL-terminated; "" if none) */
    size_t body_len; /* request body length              */
} mock_http_call_t;

/* ---- lifecycle ---------------------------------------------------------- */

/* Allocate an empty stub. `default_status` is returned (with an empty body) for
 * unmatched requests (TS mockFetch miss => 404 ''). Returns NULL on OOM. */
mock_http_t *mock_http_new(int default_status);

/* Release the stub, its routes, and its recorded calls (NULL-safe). */
void mock_http_free(mock_http_t *h);

/* ---- response registration (TS mockFetch route table) ------------------- */

/* Register a route: match when the request URL ends with `url_suffix` (NULL =
 * any URL) and `method` matches (NULL = any method). On match synthesize a
 * response {status, body}. `body`/`body_len` are copied; body NULL => empty;
 * body_len 0 with non-NULL body => strlen(body). `sticky` true => reusable for
 * every match; false => one-shot (removed after first match, FIFO among routes
 * sharing the same pattern). TS: mockFetch routes / enqueue.
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int mock_http_register(mock_http_t *h, const char *method, const char *url_suffix,
                       int status, const char *body, size_t body_len,
                       bool sticky);

/* Convenience: register a sticky route returning status 200 and a NUL-terminated
 * `body` for any request whose URL ends with `url_suffix`. */
int mock_http_register_ok(mock_http_t *h, const char *url_suffix,
                          const char *body);

/* ---- request assertions ------------------------------------------------- */

/* Number of requests issued through this transport so far (TS: calls.length). */
size_t mock_http_call_count(const mock_http_t *h);

/* Borrowed pointer to the i-th recorded call (oldest first), or NULL if i is out
 * of range. Valid until the stub is freed. TS: calls[i]. */
const mock_http_call_t *mock_http_call(const mock_http_t *h, size_t i);

/* True iff SOME recorded request's URL ends with `url_suffix`. TS:
 * expect(calls.some(u => u.endsWith(suffix))). */
bool mock_http_requested(const mock_http_t *h, const char *url_suffix);

/* ---- vtable export ------------------------------------------------------ */

/* Fill *out with an http_transport_t whose ctx borrows `h` (h must outlive it).
 * out->free is a no-op (the caller owns `h` and frees it via mock_http_free).
 * BNS_OK / BNS_EINVAL. */
int mock_http_as_transport(mock_http_t *h, http_transport_t *out);

#endif /* BONSAI_TEST_MOCK_HTTP_TRANSPORT_H */
