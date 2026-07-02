/*
 * woc_rate_limiter.c — the PROCESS-GLOBAL WhatsOnChain rate limiter.
 * Port of src/chainSources/wocRateLimiter.ts (is429, rateLimited).
 *
 * The TS limiter is a module-level promise chain (FIFO serialization +
 * failure isolation) with file-static `chain` / `lastStart`. Under a
 * single-threaded synchronous C model the whole thing collapses to:
 *   lock -> spacing sleep -> retry loop with backoff -> unlock.
 * A PROCESS-GLOBAL pthread mutex (not per-instance) provides the FIFO
 * serialization the promise chain gave us.
 *
 * CONSTANTS (woc_rate_limiter.h, plan.risks #13):
 *   MIN_INTERVAL_MS=400, MAX_RETRIES=6, BASE_BACKOFF_MS=1000.
 *   Backoff (attempts 0..5): 1000,2000,4000,8000,16000,32000 ms.
 *   lastStart updated at the START of each attempt (retries count to spacing).
 *   MAX_RETRIES=6 => up to 7 total fn invocations.
 */
#include "chainSources/woc_rate_limiter.h"

#include <ctype.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* Process-global state mirroring the TS file-static `chain`/`lastStart`. */
static pthread_mutex_t g_woc_mutex = PTHREAD_MUTEX_INITIALIZER;
static int64_t g_last_start_ms = 0; /* monotonic ms of previous attempt start */

/* Monotonic clock in milliseconds (matches Date.now() ordering, never goes
 * backwards across spacing computations). */
static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void sleep_ms(int64_t ms)
{
    if (ms <= 0)
        return;
    struct timespec req;
    req.tv_sec = (time_t)(ms / 1000);
    req.tv_nsec = (long)((ms % 1000) * 1000000L);
    /* Resume across signal interruptions so the full spacing/backoff elapses. */
    while (nanosleep(&req, &req) == -1) {
        /* errno==EINTR -> req holds the remaining time; loop. */
    }
}

/* Case-insensitive substring search (needle in haystack). */
static bool ci_contains(const char *haystack, const char *needle)
{
    if (haystack == NULL || needle == NULL)
        return false;
    if (needle[0] == '\0')
        return true;

    for (const char *h = haystack; *h; h++) {
        const char *hp = h;
        const char *np = needle;
        while (*hp && *np &&
               tolower((unsigned char)*hp) == tolower((unsigned char)*np)) {
            hp++;
            np++;
        }
        if (*np == '\0')
            return true;
    }
    return false;
}

bool is_429(int status, const char *message)
{
    /* TS: anyE?.status === 429 || /429|too many requests/i.test(message ?? '') */
    if (status == 429)
        return true;
    if (ci_contains(message, "429"))
        return true;
    if (ci_contains(message, "too many requests"))
        return true;
    return false;
}

int woc_rate_limited(woc_gated_fn fn, void *user, int *out_status)
{
    if (fn == NULL)
        return BNS_EINVAL;

    pthread_mutex_lock(&g_woc_mutex);

    /* Spacing: wait until at least MIN_INTERVAL_MS after the previous start. */
    int64_t wait = g_last_start_ms + BONSAI_WOC_MIN_INTERVAL_MS - now_ms();
    if (wait > 0)
        sleep_ms(wait);

    int rc = BNS_OK;
    int last_status = 0;

    for (int attempt = 0;; attempt++) {
        /* lastStart updated at the START of each attempt (retries count toward
         * spacing). */
        g_last_start_ms = now_ms();

        int status = 0;
        rc = fn(user, &status);
        last_status = status;

        if (rc == BNS_OK)
            break;

        /* Retry only on a 429, and only while attempts remain. */
        if (is_429(status, NULL) && attempt < BONSAI_WOC_MAX_RETRIES) {
            /* BASE_BACKOFF_MS * 2^attempt: 1000,2000,4000,8000,16000,32000 */
            int64_t backoff =
                (int64_t)BONSAI_WOC_BASE_BACKOFF_MS * ((int64_t)1 << attempt);
            sleep_ms(backoff);
            continue;
        }

        /* Non-429 error, or 429 with retries exhausted: propagate verbatim. */
        break;
    }

    if (out_status != NULL)
        *out_status = last_status;

    pthread_mutex_unlock(&g_woc_mutex);
    return rc;
}
