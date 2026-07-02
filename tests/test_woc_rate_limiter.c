/*
 * test_woc_rate_limiter.c — Unity port of
 *   chain/tests/priscilla/wocRateLimiter.test.ts
 *
 * Pins is_429: the sole retry trigger of the WhatsOnChain rate limiter. A true
 * verdict means retry-with-backoff; false means propagate immediately. Both the
 * structured status field and the message text (case-insensitive) are checked,
 * plus fail-safe handling of empty/malformed inputs.
 *
 * Real API: include/chainSources/woc_rate_limiter.h (bool is_429(int status,
 * const char *message)).
 *
 * Note: the C port flattens the TS error-object shapes (which carry either a
 * `status` field, a `message` field, both, or are a bare Error/string/null) into
 * the two scalar args. An "absent" status is modelled as 0 (no HTTP status), and
 * an "absent"/non-string message is modelled as NULL.
 *
 * OFFLINE: no network — is_429 is a pure classifier. (Filename carries 'woc' so
 * CMake labels it 'net'; it still runs without any live endpoint.)
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "unity.h"
#include "chainSources/woc_rate_limiter.h"

void setUp(void) {}
void tearDown(void) {}

/* it('recognises a 429 by structured status field') */
static void test_status_429(void)
{
    TEST_ASSERT_TRUE(is_429(429, NULL));
    TEST_ASSERT_TRUE(is_429(429, "whatever"));
}

/* it('recognises a 429 surfaced only in the message text (case-insensitive)') */
static void test_message_429_case_insensitive(void)
{
    /* status 0 == no structured status; classification comes from message only */
    TEST_ASSERT_TRUE(is_429(0, "Request failed with status 429"));
    TEST_ASSERT_TRUE(is_429(0, "Too Many Requests"));
    TEST_ASSERT_TRUE(is_429(0, "too many requests"));
    TEST_ASSERT_TRUE(is_429(0, "429 Too Many Requests")); /* new Error('429 ...') */
}

/* it('does NOT classify other errors as 429 (so they propagate, not retry)') */
static void test_non_429_propagates(void)
{
    TEST_ASSERT_FALSE(is_429(500, NULL));
    TEST_ASSERT_FALSE(is_429(404, "not found"));
    TEST_ASSERT_FALSE(is_429(0, "connection timeout"));
    TEST_ASSERT_FALSE(is_429(0, "ECONNREFUSED")); /* new Error('ECONNREFUSED') */
}

/* it('handles malformed / empty errors without throwing (fail-safe to non-retry)') */
static void test_malformed_empty_fail_safe(void)
{
    /* null / undefined / {} / bare string all map to: no status, no/empty message */
    TEST_ASSERT_FALSE(is_429(0, NULL));      /* null / undefined */
    TEST_ASSERT_FALSE(is_429(0, ""));        /* {} with no fields */
    TEST_ASSERT_FALSE(is_429(0, "a string error")); /* bare string, not a 429 */
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_status_429);
    RUN_TEST(test_message_429_case_insensitive);
    RUN_TEST(test_non_429_propagates);
    RUN_TEST(test_malformed_empty_fail_safe);
    return UNITY_END();
}
