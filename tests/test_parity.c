/*
 * test_parity.c — CROSS-LANGUAGE (C <-> Python/TS) differential golden vectors.
 *
 * Coverage-gap closure: the deep review noted parity was reasoned about analytically
 * but never validated by feeding IDENTICAL inputs through the C and Python paths and
 * comparing bytes. This pins those goldens so any future divergence (field order,
 * int2ByteString width/endianness, pubkey/hash lengths, tag bytes) breaks a test.
 *
 * The golden below is produced by the Python encoder for the SAME fixed inputs:
 *   trinote.bundle.stateful.agent_action_receipt_hash(
 *     ricardian_hash="f6"*32, agent_pubkey="02"+"11"*32,
 *     counterparty_pubkey="03"+"22"*32, amount=1000, action_hash="aa"*32,
 *     provenance_hash="bb"*32, tx_count=7, lock_time=1700000000)
 * and the byte layout matches AgentTea.executeAction in
 * ~/bonsai-notarized-bitnet/chain/src/contracts-next/agentTea.ts. The Python side
 * pins the same constant in integer_inference_engine/bonsai/tests/test_parity.py.
 */
#include "unity.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>   /* free */

#include "contracts_next/agent_tea.h"
#include "crypto/bignum.h"
#include "common/bytes.h"

/* AgentTea executeAction receiptHash over the 8 committed fields (see header). */
#define PY_AGENT_ACTION_HASH "56e6f591625f7927cf3bb3ef1a97d5bf3ad84d94c4df843cf3136cd2fc2b7d33"

void setUp(void) {}
void tearDown(void) {}

static void test_agent_tea_action_hash_matches_python_golden(void)
{
    uint8_t rh[32], agent33[33], cp33[33], ah[32], ph[32];
    memset(rh, 0xf6, 32);
    agent33[0] = 0x02; memset(agent33 + 1, 0x11, 32);   /* "02" + "11"*32 */
    cp33[0]    = 0x03; memset(cp33 + 1,    0x22, 32);   /* "03" + "22"*32 */
    memset(ah, 0xaa, 32);
    memset(ph, 0xbb, 32);

    agent_tea_t c;
    memset(&c, 0, sizeof c);
    byte_buf_init(&c.params.ricardian_hash);
    byte_buf_init(&c.params.agent);
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&c.params.ricardian_hash, rh, 32));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&c.params.agent, agent33, 33));
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("7", &c.state.tx_count));   /* PRE-increment txCount */

    bn_t *amt = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("1000", &amt));

    char *got = NULL;
    int rc = agent_tea_receipt_hash(&c, cp33, amt, ah, ph, (int64_t)1700000000, &got);
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, rc, "agent_tea_receipt_hash");
    TEST_ASSERT_EQUAL_STRING_MESSAGE(PY_AGENT_ACTION_HASH, got,
        "C AgentTea executeAction receiptHash diverged from the Python golden "
        "(C<->Python stateful-receipt encoder parity is broken)");

    free(got);
    bn_free(amt);
    byte_buf_free(&c.params.ricardian_hash);
    byte_buf_free(&c.params.agent);
    bn_free(c.state.tx_count);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_agent_tea_action_hash_matches_python_golden);
    return UNITY_END();
}
