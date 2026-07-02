/*
 * error.h — the result/error convention for the whole bonsai_chain_c port.
 *
 * Convention (mirrors how the TS code throws Error with a specific message):
 *   - Functions return `int` == a bonsai_err_t code. BNS_OK (0) on success.
 *   - Outputs are returned via out-parameters (pointers).
 *   - For the (many) places where the TS asserts a *specific* error string,
 *     callers may pass a bonsai_err_ctx to capture a verbatim message so the C
 *     tests can pin the exact text the TS produced.
 *   - Predicate-style helpers that the TS writes as `boolean` return `bool`
 *     directly (documented per-function); everything fallible uses bonsai_err_t.
 */
#ifndef BONSAI_COMMON_ERROR_H
#define BONSAI_COMMON_ERROR_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    BNS_OK = 0,
    BNS_EINVAL,        /* malformed / out-of-range argument                   */
    BNS_ECRYPTO,       /* a crypto primitive failed (sign/verify/parse)       */
    BNS_ENET,          /* network / HTTP transport error                      */
    BNS_EPARSE,        /* JSON / hex / tx / artifact parse error               */
    BNS_ENOTFOUND,     /* resource not found (404, missing key, no UTXO)      */
    BNS_EPERSIST,      /* filesystem / persistence error                      */
    BNS_ESHREDDED,     /* crypto-shredded payload requested                   */
    BNS_EINTEGRITY,    /* hash/commitment mismatch                            */
    BNS_EBINDING,      /* on-chain binding / locking-script mismatch          */
    BNS_EHOPLIMIT,     /* authorization hop / window limit exceeded           */
    BNS_EPERM,         /* revoked / out-of-scope / capability denied          */
    BNS_ENOMEM,        /* allocation failure                                  */
    BNS_EUNSUPPORTED,  /* feature compiled out (e.g. ZK without BONSAI_ENABLE_ZK) */
    BNS_ERANGE,        /* numeric overflow / size cap exceeded                */
} bonsai_err_t;

/* Optional verbatim-message capture. Pass NULL when the message is not needed.
 * `msg` is a fixed buffer so error reporting never allocates on the failure path. */
typedef struct {
    bonsai_err_t code;
    char msg[256];
} bonsai_err_ctx;

/* Record a message into ctx (no-op if ctx == NULL). Always returns `code` so
 * callers can `return bns_fail(ctx, BNS_EPARSE, "bad hex");`. */
int bns_fail(bonsai_err_ctx *ctx, bonsai_err_t code, const char *fmt, ...);

/* Human-readable name of an error code (for logs / test diagnostics). */
const char *bns_err_name(bonsai_err_t code);

#endif /* BONSAI_COMMON_ERROR_H */
