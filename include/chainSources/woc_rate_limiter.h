/*
 * woc_rate_limiter.h — the PROCESS-GLOBAL WhatsOnChain rate limiter: serialize
 * all WoC calls, enforce a minimum inter-request spacing, and retry HTTP 429
 * with exponential backoff. One process = one well-behaved WoC consumer.
 *
 * The TS limiter is a module-level promise chain (FIFO serialization + failure
 * isolation) with file-static `chain`/`lastStart`. The C port uses file-static
 * state behind a PROCESS-GLOBAL pthread mutex (NOT per-instance) under a
 * single-threaded synchronous model, where the whole thing collapses to:
 * lock -> spacing sleep -> retry loop with backoff -> unlock.
 *
 * TS origin: src/chainSources/wocRateLimiter.ts (is429, rateLimited).
 *
 * CONSTANTS (exact, load-bearing — plan.risks #13):
 *   MIN_INTERVAL_MS = 400, MAX_RETRIES = 6, BASE_BACKOFF_MS = 1000.
 *   Backoff schedule (attempts 0..5): 1000, 2000, 4000, 8000, 16000, 32000 ms.
 *   lastStart is updated at the START of each attempt (retries count toward
 *   spacing). MAX_RETRIES=6 => up to 7 total fn invocations.
 */
#ifndef BONSAI_CHAINSOURCES_WOC_RATE_LIMITER_H
#define BONSAI_CHAINSOURCES_WOC_RATE_LIMITER_H

#include <stdbool.h>
#include "common/error.h"

/* Exact rate-limiter constants. TS: MIN_INTERVAL_MS / MAX_RETRIES /
 * BASE_BACKOFF_MS. */
#define BONSAI_WOC_MIN_INTERVAL_MS 400
#define BONSAI_WOC_MAX_RETRIES     6
#define BONSAI_WOC_BASE_BACKOFF_MS 1000

/* Classify whether a result is a WoC rate-limit (HTTP 429): true if
 * `status` == 429 OR `message` (may be NULL) matches /429|too many requests/i
 * (case-insensitive substring). Both paths are checked (some clients only
 * surface 429 in the message). TS: is429(e). */
bool is_429(int status, const char *message);

/* The gated work function: runs one WoC operation. Returns BNS_OK on success;
 * on an HTTP 429 it MUST report status 429 via *out_status so the limiter can
 * retry. Any other error is returned verbatim and propagates immediately
 * (non-429 errors are not retried). `user` is opaque caller state.
 * TS: the `fn` passed to rateLimited. */
typedef int (*woc_gated_fn)(void *user, int *out_status);

/* Run `fn` through the process-global gate: acquire the global mutex (FIFO),
 * enforce >= MIN_INTERVAL_MS spacing from the previous attempt start, then the
 * retry loop (on a 429 result sleep BASE_BACKOFF_MS * 2^attempt and retry up to
 * MAX_RETRIES; non-429 errors propagate at once). Returns fn's final result
 * code; a 429 that exhausts retries propagates as the underlying error.
 * `out_status` (optional) receives the last HTTP status observed.
 * TS: rateLimited(fn). BNS_OK / BNS_ENET / (fn's error). */
int woc_rate_limited(woc_gated_fn fn, void *user, int *out_status);

#endif /* BONSAI_CHAINSOURCES_WOC_RATE_LIMITER_H */
