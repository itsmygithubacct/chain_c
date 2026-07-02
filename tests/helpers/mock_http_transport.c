/* mock_http_transport.c — see mock_http_transport.h. */
#include "mock_http_transport.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    char  *method;     /* NULL = any */
    char  *url_suffix; /* NULL = any */
    int    status;
    char  *body;       /* owned; may be NULL */
    size_t body_len;
    bool   sticky;
    bool   consumed;
} route_t;

struct mock_http_s {
    route_t          *routes; size_t route_n, route_cap;
    mock_http_call_t *calls;  size_t call_n,  call_cap;
    int               default_status;
};

static char *dup_str(const char *s)
{
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *d = malloc(n);
    if (d) memcpy(d, s, n);
    return d;
}

static char *dup_bytes(const char *s, size_t n)
{
    char *d = malloc(n + 1);
    if (!d) return NULL;
    if (s && n) memcpy(d, s, n);
    d[n] = '\0';
    return d;
}

mock_http_t *mock_http_new(int default_status)
{
    mock_http_t *h = calloc(1, sizeof(*h));
    if (h) h->default_status = default_status;
    return h;
}

void mock_http_free(mock_http_t *h)
{
    if (!h) return;
    for (size_t i = 0; i < h->route_n; i++) {
        free(h->routes[i].method);
        free(h->routes[i].url_suffix);
        free(h->routes[i].body);
    }
    for (size_t i = 0; i < h->call_n; i++) {
        free(h->calls[i].method);
        free(h->calls[i].url);
        free(h->calls[i].body);
    }
    free(h->routes);
    free(h->calls);
    free(h);
}

int mock_http_register(mock_http_t *h, const char *method, const char *url_suffix,
                       int status, const char *body, size_t body_len,
                       bool sticky)
{
    if (!h) return BNS_EINVAL;
    if (body && body_len == 0) body_len = strlen(body);
    if (h->route_n == h->route_cap) {
        size_t nc = h->route_cap ? h->route_cap * 2 : 8;
        route_t *p = realloc(h->routes, nc * sizeof(*p));
        if (!p) return BNS_ENOMEM;
        h->routes = p; h->route_cap = nc;
    }
    route_t r;
    memset(&r, 0, sizeof(r));
    r.status = status;
    r.sticky = sticky;
    r.body_len = body ? body_len : 0;
    if (method && !(r.method = dup_str(method))) return BNS_ENOMEM;
    if (url_suffix && !(r.url_suffix = dup_str(url_suffix))) { free(r.method); return BNS_ENOMEM; }
    if (body && !(r.body = dup_bytes(body, body_len))) {
        free(r.method); free(r.url_suffix); return BNS_ENOMEM;
    }
    h->routes[h->route_n++] = r;
    return BNS_OK;
}

int mock_http_register_ok(mock_http_t *h, const char *url_suffix, const char *body)
{
    return mock_http_register(h, NULL, url_suffix, 200, body, 0, true);
}

static bool ends_with(const char *s, const char *suffix)
{
    if (!suffix) return true;
    size_t ls = strlen(s), lf = strlen(suffix);
    return lf <= ls && memcmp(s + ls - lf, suffix, lf) == 0;
}

size_t mock_http_call_count(const mock_http_t *h)
{
    return h ? h->call_n : 0;
}

const mock_http_call_t *mock_http_call(const mock_http_t *h, size_t i)
{
    if (!h || i >= h->call_n) return NULL;
    return &h->calls[i];
}

bool mock_http_requested(const mock_http_t *h, const char *url_suffix)
{
    if (!h) return false;
    for (size_t i = 0; i < h->call_n; i++) {
        if (ends_with(h->calls[i].url, url_suffix)) return true;
    }
    return false;
}

static int record_call(mock_http_t *h, const char *method, const char *url,
                       const char *body, size_t body_len)
{
    if (h->call_n == h->call_cap) {
        size_t nc = h->call_cap ? h->call_cap * 2 : 8;
        mock_http_call_t *p = realloc(h->calls, nc * sizeof(*p));
        if (!p) return BNS_ENOMEM;
        h->calls = p; h->call_cap = nc;
    }
    mock_http_call_t c;
    memset(&c, 0, sizeof(c));
    c.method = dup_str(method ? method : "");
    c.url = dup_str(url ? url : "");
    c.body = dup_bytes(body, body ? body_len : 0);
    c.body_len = body ? body_len : 0;
    if (!c.method || !c.url || !c.body) {
        free(c.method); free(c.url); free(c.body); return BNS_ENOMEM;
    }
    h->calls[h->call_n++] = c;
    return BNS_OK;
}

static int mh_request(void *ctx, const char *method, const char *url,
                      const char *const *headers, size_t nheaders,
                      const char *body, size_t body_len, http_response_t *out)
{
    (void)headers; (void)nheaders;
    mock_http_t *h = ctx;
    if (!out) return BNS_EINVAL;
    int rc = record_call(h, method, url, body, body_len);
    if (rc != BNS_OK) return rc;

    out->status = 0;
    byte_buf_init(&out->body);

    for (size_t i = 0; i < h->route_n; i++) {
        route_t *r = &h->routes[i];
        if (r->consumed) continue;
        bool m_ok = (!r->method) || (method && strcmp(r->method, method) == 0);
        bool u_ok = ends_with(url ? url : "", r->url_suffix);
        if (m_ok && u_ok) {
            out->status = r->status;
            if (r->body && r->body_len) {
                if (byte_buf_append(&out->body, r->body, r->body_len) != BNS_OK)
                    return BNS_ENOMEM;
            }
            if (!r->sticky) r->consumed = true;
            return BNS_OK;
        }
    }
    /* No route -> TS mockFetch miss (e.g. 404 with empty body). */
    out->status = h->default_status;
    return BNS_OK;
}

static void mh_free(void *ctx) { (void)ctx; /* stub owned by the test */ }

int mock_http_as_transport(mock_http_t *h, http_transport_t *out)
{
    if (!h || !out) return BNS_EINVAL;
    out->ctx = h;
    out->request = mh_request;
    out->free = mh_free;
    return BNS_OK;
}
