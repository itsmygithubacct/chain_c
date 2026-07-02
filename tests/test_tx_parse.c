/*
 * test_tx_parse.c — adversarial / malformed-input tests for tx_deserialize.
 *
 * The other tx coverage is golden (well-formed vectors captured from the TS
 * layer). This suite is the HOSTILE-input complement: it feeds truncated,
 * non-hex, and maliciously oversized-count raw-tx hex into tx_deserialize and
 * asserts it FAILS CLOSED (non-BNS_OK) without crashing — which, run under the
 * ASan/UBSan CI job (-DBONSAI_ASAN=ON), pins the parser as memory-safe against
 * attacker-influenceable WhatsOnChain `rawtx` data.
 *
 * It directly exercises the defensive guards added for the public-release audit:
 *   - the input/output count caps (a tiny buffer declaring millions of entries
 *     must not force a huge calloc), and
 *   - the wrap-safe length bounds checks (`slen > len - off`).
 *
 * A positive control (a minimal well-formed tx) confirms the guards never reject
 * a VALID transaction.
 *
 * Real API: include/bsv/tx.h — int tx_deserialize(const char *hex, bsv_tx_t*).
 * OFFLINE: pure deserialize, no network. Labelled 'unit' (no net/zk/golden tag).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "unity.h"
#include "bsv/tx.h"
#include "common/error.h"

void setUp(void) {}
void tearDown(void) {}

/* tx_deserialize is self-initializing and frees its own partial state on the
 * error path; on hex-decode failure it never touches `tx`. We tx_init first so
 * an early return still leaves `tx` in a valid empty state, and only tx_free on
 * success (never double-free a failed parse). */
static int parse(const char *hex, bsv_tx_t *tx)
{
    tx_init(tx);
    return tx_deserialize(hex, tx);
}

#define ASSERT_REJECTS(hex)                                  \
    do {                                                     \
        bsv_tx_t _tx;                                        \
        int _rc = parse((hex), &_tx);                        \
        TEST_ASSERT_NOT_EQUAL_INT(BNS_OK, _rc);              \
    } while (0)

/* --- malformed hex / truncation ------------------------------------------- */

static void test_empty_and_nonhex_rejected(void)
{
    ASSERT_REJECTS("");            /* zero bytes: no version            */
    ASSERT_REJECTS("0");           /* odd-length hex                    */
    ASSERT_REJECTS("zz");          /* non-hex digits                    */
    ASSERT_REJECTS("010000");      /* 3 bytes: version (4 LE) truncated */
}

static void test_truncated_after_version_rejected(void)
{
    /* version ok, then a declared input but no input bytes follow. */
    ASSERT_REJECTS("01000000" "01");
    /* version + input count 2, only a partial first input. */
    ASSERT_REJECTS("01000000" "02" "00");
}

/* --- finding #5: maliciously oversized declared counts -------------------- */

static void test_oversized_input_count_rejected(void)
{
    /* version + varint 0xff <8-byte count = 0xffffffffffffffff> and nothing
     * more: a ~13-byte buffer declaring ~1.8e19 inputs must be rejected by the
     * (len-off)/41 cap, not forwarded to calloc. */
    ASSERT_REJECTS("01000000" "ff" "ffffffffffffffff");
    /* a more modest but still impossible count: 0xfe <4-byte> = 0x00100000
     * (~1M) inputs with no payload -> > (len-off)/41. */
    ASSERT_REJECTS("01000000" "fe" "00001000");
}

static void test_oversized_output_count_rejected(void)
{
    /* one valid empty input, then an impossible output count with no payload.
     * input: prevTxid(32) vout(4)=0 scriptlen(1)=0 seq(4)=ffffffff */
    ASSERT_REJECTS("01000000" "01"
                   "0000000000000000000000000000000000000000000000000000000000000000"
                   "00000000" "00" "ffffffff"
                   "ff" "ffffffffffffffff");          /* output count 0xff... */
}

/* --- finding #6: oversized length field inside an entry ------------------- */

static void test_oversized_scriptsig_len_rejected(void)
{
    /* one input whose scriptSig length varint claims 0xffffffffffffffff bytes
     * but supplies none: `slen > len - off` must reject (no over-read). */
    ASSERT_REJECTS("01000000" "01"
                   "0000000000000000000000000000000000000000000000000000000000000000"
                   "00000000"
                   "ff" "ffffffffffffffff");          /* scriptSig len 0xff... */
}

/* --- positive control: a minimal VALID tx still parses -------------------- */

static void test_minimal_valid_tx_accepted(void)
{
    /* version(1) | vin=1 | [prevout 0x00*32 | vout=0 | scriptSig len 0 |
     * seq 0xffffffff] | vout=1 | [value=0 | script len 0] | locktime=0 */
    const char *hex =
        "01000000" "01"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "00000000" "00" "ffffffff"
        "01" "0000000000000000" "00"
        "00000000";
    bsv_tx_t tx;
    int rc = parse(hex, &tx);
    TEST_ASSERT_EQUAL_INT(BNS_OK, rc);
    TEST_ASSERT_EQUAL_UINT(1u, (unsigned)tx.num_inputs);
    TEST_ASSERT_EQUAL_UINT(1u, (unsigned)tx.num_outputs);
    tx_free(&tx);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_empty_and_nonhex_rejected);
    RUN_TEST(test_truncated_after_version_rejected);
    RUN_TEST(test_oversized_input_count_rejected);
    RUN_TEST(test_oversized_output_count_rejected);
    RUN_TEST(test_oversized_scriptsig_len_rejected);
    RUN_TEST(test_minimal_valid_tx_accepted);
    return UNITY_END();
}
