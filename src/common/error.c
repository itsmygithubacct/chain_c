/*
 * error.c — error context capture + error-code naming.
 *
 * Pure C over libc only. bns_fail formats a verbatim message into the
 * caller-provided ctx (no-op when ctx == NULL) and always returns `code`
 * so callers can `return bns_fail(ctx, BNS_EPARSE, "bad hex");`.
 */
#include "common/error.h"

#include <stdarg.h>
#include <stdio.h>

int bns_fail(bonsai_err_ctx *ctx, bonsai_err_t code, const char *fmt, ...)
{
    if (ctx != NULL) {
        ctx->code = code;
        if (fmt != NULL) {
            va_list ap;
            va_start(ap, fmt);
            /* vsnprintf always NUL-terminates when sizeof(msg) > 0. */
            (void)vsnprintf(ctx->msg, sizeof(ctx->msg), fmt, ap);
            va_end(ap);
        } else {
            ctx->msg[0] = '\0';
        }
    }
    return (int)code;
}

const char *bns_err_name(bonsai_err_t code)
{
    switch (code) {
    case BNS_OK:           return "BNS_OK";
    case BNS_EINVAL:       return "BNS_EINVAL";
    case BNS_ECRYPTO:      return "BNS_ECRYPTO";
    case BNS_ENET:         return "BNS_ENET";
    case BNS_EPARSE:       return "BNS_EPARSE";
    case BNS_ENOTFOUND:    return "BNS_ENOTFOUND";
    case BNS_EPERSIST:     return "BNS_EPERSIST";
    case BNS_ESHREDDED:    return "BNS_ESHREDDED";
    case BNS_EINTEGRITY:   return "BNS_EINTEGRITY";
    case BNS_EBINDING:     return "BNS_EBINDING";
    case BNS_EHOPLIMIT:    return "BNS_EHOPLIMIT";
    case BNS_EPERM:        return "BNS_EPERM";
    case BNS_ENOMEM:       return "BNS_ENOMEM";
    case BNS_EUNSUPPORTED: return "BNS_EUNSUPPORTED";
    case BNS_ERANGE:       return "BNS_ERANGE";
    }
    return "BNS_UNKNOWN";
}
