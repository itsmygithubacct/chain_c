/*
 * test_recover_scriptsig.c — BYTE-LEVEL framing test for the AgentTea.recover
 * unlocking script assembled by contract_recover_sign()
 * (src/txbuilders/contract_sign.c).
 *
 * WHY THIS TEST EXISTS: the recover spend has NO captured golden vector in
 * tests/golden/broadcast.json (unlike deploy/revoke/executeAction, which the
 * standalone test_broadcast_golden.c pins byte-for-byte). recover is money-
 * critical — a wrong push order or wrong integer encoding silently produces an
 * unspendable / mis-authorized social-recovery tx — so this Unity test is the
 * PRIMARY byte-level check on the recover scriptSig framing.
 *
 * It drives the real contract_recover_sign() on a minimal UNSIGNED skeleton
 *   input[0] = contract input (placeholder scriptSig)
 *   input[1] = P2PKH funding input (a deterministic funder key)
 *   output[0] = a P2PKH change output
 * and then asserts the AgentTea.recover (ABI index 3) push order on the
 * contract input's scriptSig at the deterministic byte offsets:
 *
 *   newAgent(PubKey 33B) | recoverUsed[0..2](bool) |
 *   recoverySigs[0..2]( RabinSig.s int2Asm, padding bytes ) |
 *   SigHashPreimage | changeAmount(int) | changeAddress(20B) |
 *   prevouts(PUSHDATA1) | selector(int2Asm OP_3)
 *
 * INT ENCODING NOTE (load-bearing): every `int` push (the bools, RabinSig.s,
 * changeAmount, the selector) routes through the scryptlib CONSTRUCTOR int2Asm
 * encoder (scrypt/script_codec.c ctor_int_push). That encoder applies the
 * OP_0 / OP_1..OP_16 / OP_1NEGATE small-int optimization, so:
 *   RabinSig.s = 5  ->  OP_5 (0x55)      (NOT a length-prefixed push 0x01 0x05)
 *   RabinSig.s = 9  ->  OP_9 (0x59)
 *   selector   = 3  ->  OP_3 (0x53)
 *   bool true/false ->  OP_1 (0x51) / OP_0 (0x00)
 * The padding (a `bytes` field) uses the bytes2hex push: an empty padding -> OP_0
 * (0x00); a single 0x00 byte (NOT in 1..16) -> a length-1 data push 0x01 0x00.
 *
 * The bytes asserted here were independently confirmed against the live encoder.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "unity.h"

#include "common/error.h"
#include "common/bytes.h"
#include "crypto/bignum.h"
#include "crypto/ecdsa.h"
#include "bsv/tx.h"
#include "bsv/tx_builder.h"
#include "bsv/script_utils.h"
#include "txbuilders/contract_sign.h"

#include "tx_helper.h"   /* deterministic funder key + hash160 (test helper) */

/* AGENT_TEA_RECOVER_SELECTOR is a private #define in src/scripts/agentd_lib.c
 * (the AgentTea.recover ABI index). Mirror it here so the test pins the same
 * literal the CLI uses. */
#define AGENT_TEA_RECOVER_SELECTOR 3

/* fixed contract-input outpoint (any 64-hex DISPLAY txid). */
#define CONTRACT_PREV_TXID \
    "1111111111111111111111111111111111111111111111111111111111111111"

void setUp(void) {}
void tearDown(void) {}

/* ---------------------------------------------------------------------------
 * Shared builder: lay out the UNSIGNED skeleton, run contract_recover_sign with
 * the fixed recover inputs, and hand back BOTH the contract-input scriptSig
 * (copied into *out_ss) and the full raw-tx hex (*out_hex, caller frees). Also
 * fills *out_new_agent33 with the 33-byte newAgent used. Returns the
 * contract_recover_sign() return code. The builder is freed before returning;
 * *out_ss owns its bytes (byte_buf_free) and *out_hex must be free()'d.
 * ------------------------------------------------------------------------- */
static int recover_build(uint8_t out_new_agent33[33],
                         byte_buf_t *out_ss, char **out_hex)
{
    *out_hex = NULL;
    byte_buf_init(out_ss);

    /* newAgent: a fixed compressed-pubkey-shaped pattern (0x02 then 32 bytes). */
    out_new_agent33[0] = 0x02;
    memset(out_new_agent33 + 1, 0xAB, 32);

    /* change address: fixed 20-byte hash160. */
    uint8_t change20[20];
    memset(change20, 0xCD, 20);

    /* funder key + its P2PKH locking script (the funding prevout scriptCode). */
    ecdsa_key_t *funder = NULL;
    if (tx_helper_key(TX_KEY_AGENT, &funder) != BNS_OK) return BNS_EINVAL;
    uint8_t funder_h160[20];
    if (tx_helper_hash160(TX_KEY_AGENT, funder_h160) != BNS_OK) {
        ecdsa_key_free(funder); return BNS_EINVAL;
    }
    byte_buf_t fund_spk; byte_buf_init(&fund_spk);
    if (build_p2pkh_script(funder_h160, &fund_spk) != BNS_OK) {
        ecdsa_key_free(funder); byte_buf_free(&fund_spk); return BNS_EINVAL;
    }

    /* contract scriptCode (the AgentTea locking script). Its exact bytes do not
     * affect the contract-input scriptSig FRAMING under test — they only feed the
     * BIP143 preimage that is pushed as data — so a fixed placeholder suffices. */
    const uint8_t contract_code[8] =
        { 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58 };

    /* RabinSig.s values: s0 = 5, s1 = 9, s2 unused (NULL -> dummy OP_0). */
    bn_t *s0 = NULL, *s1 = NULL;
    bn_parse_dec("5", &s0);
    bn_parse_dec("9", &s1);

    contract_recover_sig_t rsigs[3];
    memset(rsigs, 0, sizeof rsigs);
    rsigs[0].used = true;  rsigs[0].s = s0;   rsigs[0].padding_len = 0;
    rsigs[1].used = true;  rsigs[1].s = s1;   rsigs[1].padding_len = 1;
    rsigs[2].used = false; rsigs[2].s = NULL; rsigs[2].padding_len = 0;

    /* UNSIGNED skeleton: input[0]=contract, input[1]=funding, output[0]=change. */
    tx_builder_t b; tx_builder_init(&b);
    int rc = tx_builder_add_input(&b, CONTRACT_PREV_TXID, 0, NULL, 0, 0xffffffff);
    if (rc == BNS_OK)
        rc = tx_builder_add_input(&b, TX_HELPER_FUNDING_TXID, 0, NULL, 0, 0xffffffff);
    if (rc == BNS_OK) {
        byte_buf_t chg; byte_buf_init(&chg);
        rc = build_p2pkh_script(change20, &chg);
        if (rc == BNS_OK) rc = tx_builder_add_output(&b, chg.data, chg.len, 1000);
        byte_buf_free(&chg);
    }

    if (rc == BNS_OK) {
        contract_funding_input_t fund;
        memset(&fund, 0, sizeof fund);
        fund.input_index     = 1;
        fund.script_code     = fund_spk.data;
        fund.script_code_len = fund_spk.len;
        fund.value           = TX_HELPER_FUNDING_SATS;
        fund.key             = funder;

        rc = contract_recover_sign(&b, 0,
                                   contract_code, sizeof contract_code,
                                   1 /* identity_value sats */,
                                   out_new_agent33, rsigs,
                                   1000 /* change_amount */, change20,
                                   AGENT_TEA_RECOVER_SELECTOR,
                                   &fund, 1, out_hex);

        if (rc == BNS_OK) {
            /* Copy input[0]'s scriptSig out before the builder is freed. */
            const byte_buf_t *ss = &b.tx.inputs[0].script_sig;
            if (byte_buf_from(out_ss, ss->data, ss->len) != BNS_OK) rc = BNS_ENOMEM;
        }
    }

    bn_free(s0); bn_free(s1);
    byte_buf_free(&fund_spk);
    ecdsa_key_free(funder);
    tx_builder_free(&b);
    return rc;
}

/* Assert the AgentTea.recover scriptSig framing at the deterministic offsets.
 * `p`/`len` are the contract-input scriptSig bytes; `new_agent33` the expected
 * newAgent push body. */
static void assert_recover_framing(const uint8_t *p, size_t len,
                                   const uint8_t new_agent33[33])
{
    /* The fixed prefix runs offsets 0..43 (newAgent push + 3 bools + 3 RabinSigs)
     * and there is at least the trailing selector after the preimage/change/
     * prevouts pushes, so the scriptSig is comfortably longer than 44 bytes. */
    TEST_ASSERT_GREATER_THAN_size_t(44, len);

    /* newAgent: a 33-byte data push -> 0x21 || 33 bytes. */
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x21, p[0], "newAgent push opcode (len 33)");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(new_agent33, p + 1, 33,
                                         "newAgent push body");

    /* recoverUsed[0..2]: bool OP_1/OP_0 (used,used,unused). */
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x51, p[34], "recoverUsed[0]=true -> OP_1");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x51, p[35], "recoverUsed[1]=true -> OP_1");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x00, p[36], "recoverUsed[2]=false -> OP_0");

    /* recoverySigs[0..2] = (RabinSig.s int2Asm) then (padding bytes2hex):
     *  s0=5 -> OP_5 (0x55); pad0 empty   -> OP_0 (0x00)
     *  s1=9 -> OP_9 (0x59); pad1 one 0x00-> push 0x01 0x00
     *  s2=0 -> OP_0 (0x00); pad2 empty   -> OP_0 (0x00)
     * (OP_5/OP_9 NOT 0x01 0x05/0x01 0x09: int2Asm applies the OP_1..OP_16 opt.) */
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x55, p[37], "recoverySigs[0].s=5 -> OP_5");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x00, p[38], "recoverySigs[0].padding '' -> OP_0");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x59, p[39], "recoverySigs[1].s=9 -> OP_9");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x01, p[40], "recoverySigs[1].padding push len=1");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x00, p[41], "recoverySigs[1].padding byte 0x00");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x00, p[42], "recoverySigs[2].s unused -> OP_0");
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x00, p[43], "recoverySigs[2].padding '' -> OP_0");

    /* The LAST push of the scriptSig is the method selector: OP_3 for recover. */
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x53, p[len - 1],
                                   "final selector push -> OP_3 (AgentTea.recover)");
}

/* (1) Direct read of b->tx.inputs[0].script_sig after contract_recover_sign. */
static void test_recover_scriptsig_framing_direct(void)
{
    uint8_t new_agent33[33];
    byte_buf_t ss; char *hex = NULL;
    int rc = recover_build(new_agent33, &ss, &hex);

    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, rc, "contract_recover_sign");
    TEST_ASSERT_NOT_NULL_MESSAGE(hex, "raw tx hex produced");
    TEST_ASSERT_TRUE_MESSAGE(strlen(hex) > 0, "raw tx hex non-empty");

    assert_recover_framing(ss.data, ss.len, new_agent33);

    free(hex);
    byte_buf_free(&ss);
}

/* (2) Same framing must survive a full serialize -> deserialize round-trip:
 * re-parse the raw tx hex and assert input[0].scriptSig matches byte-for-byte. */
static void test_recover_scriptsig_framing_reparse(void)
{
    uint8_t new_agent33[33];
    byte_buf_t ss; char *hex = NULL;
    int rc = recover_build(new_agent33, &ss, &hex);
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, rc, "contract_recover_sign");
    TEST_ASSERT_NOT_NULL(hex);

    bsv_tx_t tx; tx_init(&tx);
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, tx_deserialize(hex, &tx),
                                  "re-parse raw tx hex");
    TEST_ASSERT_GREATER_OR_EQUAL_size_t(2, tx.num_inputs);

    const byte_buf_t *rss = &tx.inputs[0].script_sig;
    /* the re-parsed contract-input scriptSig equals the in-place one ... */
    TEST_ASSERT_EQUAL_size_t_MESSAGE(ss.len, rss->len,
                                     "reparsed scriptSig length");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(ss.data, rss->data, ss.len,
                                         "reparsed scriptSig bytes");
    /* ... and still satisfies the recover framing. */
    assert_recover_framing(rss->data, rss->len, new_agent33);

    tx_free(&tx);
    free(hex);
    byte_buf_free(&ss);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_recover_scriptsig_framing_direct);
    RUN_TEST(test_recover_scriptsig_framing_reparse);
    return UNITY_END();
}
