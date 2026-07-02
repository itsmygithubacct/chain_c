/*
 * test_ricardian_tea_change.c — regression for review finding #2 (money-safety).
 *
 * The RicardianTea executeTea/revoke/checkpoint builders seeded their change
 * output with `funding_total` ALONE, omitting the spent identity UTXO's value.
 * update_change_output subtracts every non-change output (including output[0],
 * which recreates identity->value 1:1) from that seed, so the seed MUST be the
 * FULL input total = funding_total + identity->value. With the bug, when
 * funding < identity->value the tx cannot be built (BNS_ERANGE); when
 * over-funded the staked collateral is burned to the miner as fee.
 *
 * This drives the REAL build_ricardian_tea_execute with funding (200k) far below
 * the identity collateral (50M): the fixed builder produces a valid tx whose
 * realized fee is a few hundred/thousand sats (collateral preserved at
 * output[0]); the buggy builder returns BNS_ERANGE. Mirrors the agent_tea
 * sibling and bsv.Transaction.change() in ricardianTeaTxBuilder.ts, which sum
 * all inputs. No broadcast: pure unsigned-tx construction.
 */
#include "unity.h"

#include <string.h>
#include <stdint.h>

#include "txbuilders/ricardian_tea_tx_builder.h"
#include "contracts/ricardian_tea.h"
#include "scrypt/artifact_loader.h"
#include "crypto/bignum.h"
#include "common/bytes.h"
#include "bsv/tx_builder.h"
#include "tx_helper.h"

#define IDENTITY_VALUE   50000000ULL   /* 0.5 BSV staked collateral */
#define FUND_EACH        100000ULL     /* 2 funding UTXOs => 200k total (< collateral) */
#define PAY_AMOUNT       30000ULL

static scrypt_artifact_t g_art;
static int g_art_ok;

void setUp(void) {}
void tearDown(void) {}

static bn_t *mkbn(const char *dec)
{
    bn_t *n = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec(dec, &n));
    return n;
}

static void fill_params(ricardian_tea_t *c)
{
    uint8_t owner33[33], agent33[33], h32[32];
    TEST_ASSERT_EQUAL_INT(BNS_OK, tx_helper_pubkey_bytes(TX_KEY_ELDER, owner33));
    TEST_ASSERT_EQUAL_INT(BNS_OK, tx_helper_pubkey_bytes(TX_KEY_AGENT, agent33));
    for (int i = 0; i < 32; i++) h32[i] = (uint8_t)(0x40 + i);

    byte_buf_init(&c->params.owner);
    byte_buf_init(&c->params.agent);
    byte_buf_init(&c->params.ricardian_hash);
    byte_buf_init(&c->params.initial_slash_checkpoint_hash);
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&c->params.owner, owner33, 33));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&c->params.agent, agent33, 33));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&c->params.ricardian_hash, h32, 32));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&c->params.initial_slash_checkpoint_hash, h32, 32));

    c->params.per_tx_limit             = mkbn("1000000");
    c->params.daily_limit              = mkbn("10000000");
    c->params.window_duration          = mkbn("86400");
    c->params.graduation_threshold     = mkbn("100");
    c->params.validator_threshold      = mkbn("3");
    c->params.designated_validator_pubkey = mkbn("123456789123456789");
    c->params.validator_rabin_pubkey   = mkbn("987654321987654321");
    c->params.max_slashing_target      = mkbn("1000000");
    c->params.min_slash_confirmations  = mkbn("6");

    byte_buf_init(&c->state.slash_checkpoint_hash);
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&c->state.slash_checkpoint_hash, h32, 32));
    c->state.tx_count        = mkbn("0");
    c->state.spent_in_window = mkbn("0");
    c->state.window_start    = mkbn("0");
    c->state.tier            = mkbn("1");
}

static void free_params(ricardian_tea_t *c)
{
    byte_buf_free(&c->params.owner);
    byte_buf_free(&c->params.agent);
    byte_buf_free(&c->params.ricardian_hash);
    byte_buf_free(&c->params.initial_slash_checkpoint_hash);
    bn_free(c->params.per_tx_limit);
    bn_free(c->params.daily_limit);
    bn_free(c->params.window_duration);
    bn_free(c->params.graduation_threshold);
    bn_free(c->params.validator_threshold);
    bn_free(c->params.designated_validator_pubkey);
    bn_free(c->params.validator_rabin_pubkey);
    bn_free(c->params.max_slashing_target);
    bn_free(c->params.min_slash_confirmations);
    byte_buf_free(&c->state.slash_checkpoint_hash);
    bn_free(c->state.tx_count);
    bn_free(c->state.spent_in_window);
    bn_free(c->state.window_start);
    bn_free(c->state.tier);
}

/* executeTea: funding (200k) << identity collateral (50M). The fix MUST build a
 * valid tx with collateral preserved and a sane fee; the bug returned BNS_ERANGE. */
static void test_executeTea_change_includes_identity_value(void)
{
    if (!g_art_ok) { TEST_IGNORE_MESSAGE("artifacts/ricardianTea.json not loadable from CWD"); return; }

    ricardian_tea_t c;
    memset(&c, 0, sizeof c);
    c.artifact = &g_art;
    fill_params(&c);

    ricardian_tea_utxo_t id;
    memset(&id, 0, sizeof id);
    memcpy(id.txid_display, "1111111111111111111111111111111111111111111111111111111111111111", 64);
    id.vout = 0;
    id.value = IDENTITY_VALUE;

    funding_utxo_t items[2];
    memset(items, 0, sizeof items);
    memcpy(items[0].tx_id, "2222222222222222222222222222222222222222222222222222222222222222", 64);
    items[0].output_index = 0; items[0].satoshis = (int64_t)FUND_EACH; items[0].confirmed = true;
    memcpy(items[1].tx_id, "3333333333333333333333333333333333333333333333333333333333333333", 64);
    items[1].output_index = 1; items[1].satoshis = (int64_t)FUND_EACH; items[1].confirmed = true;
    funding_utxos_t fund = { items, 2 };

    uint8_t change20[20], cp33[33], inv32[32], prov32[32];
    TEST_ASSERT_EQUAL_INT(BNS_OK, tx_helper_hash160(TX_KEY_AGENT, change20));
    TEST_ASSERT_EQUAL_INT(BNS_OK, tx_helper_pubkey_bytes(TX_KEY_COUNTERPARTY, cp33));
    for (int i = 0; i < 32; i++) { inv32[i] = 0x11; prov32[i] = 0x22; }

    ricardian_tea_builder_opts_t opts;
    memset(&opts, 0, sizeof opts);
    opts.funding = &fund;
    opts.change_hash160 = change20;
    opts.has_change = true;
    opts.fee_per_kb = 0;   /* default */

    bn_t *amount = mkbn("30000");

    tx_builder_t b;
    tx_builder_init(&b);

    int rc = build_ricardian_tea_execute(&c, &id, cp33, amount, inv32, prov32,
                                         1700000000, &opts, &b);

    /* The bug seeded change with funding_total alone (200k); with collateral 50M
     * that underflows -> BNS_ERANGE. The fix seeds funding_total + identity->value. */
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, rc,
        "executeTea must build with funding < collateral (regression: change seed omitted identity->value)");

    /* outputs: [0]=recreated identity, [1]=payment, [2]=OP_RETURN, [3]=change */
    TEST_ASSERT_EQUAL_UINT(4u, (unsigned)b.tx.num_outputs);
    TEST_ASSERT_EQUAL_UINT64_MESSAGE(IDENTITY_VALUE, b.tx.outputs[0].satoshis,
        "identity collateral must be recreated 1:1 at output[0]");
    TEST_ASSERT_EQUAL_UINT64(PAY_AMOUNT, b.tx.outputs[1].satoshis);
    TEST_ASSERT_EQUAL_UINT64(0u, b.tx.outputs[2].satoshis);

    uint64_t total_in  = IDENTITY_VALUE + 2 * FUND_EACH;
    uint64_t total_out = 0;
    for (size_t i = 0; i < b.tx.num_outputs; i++) total_out += b.tx.outputs[i].satoshis;
    TEST_ASSERT_TRUE_MESSAGE(total_out <= total_in, "outputs exceed inputs (negative fee)");
    uint64_t fee = total_in - total_out;

    /* The realized miner fee must be a real tx fee, NOT ~= the staked collateral
     * (which is exactly what the bug burned). */
    TEST_ASSERT_TRUE_MESSAGE(fee > 0, "fee must be positive");
    TEST_ASSERT_TRUE_MESSAGE(fee < 1000000ULL,
        "realized fee ~= staked collateral: change seed omitted identity->value (collateral burned)");

    /* change = funding_total - payment - fee */
    TEST_ASSERT_EQUAL_UINT64(2 * FUND_EACH - PAY_AMOUNT - fee, b.tx.outputs[3].satoshis);

    /* review-2 #1: output[0] MUST encode the POST-spend (advanced) state — txCount+1, window roll,
     * tier graduation — or the on-chain hashOutputs assert fails and the tx is unminable. The old
     * builder emitted the PRE-spend state and this test only checked satoshis, masking the break.
     * Now assert output[0]'s locking script == the advanced-state script AND != the pre-spend one. */
    {
        ricardian_tea_state_t adv;
        TEST_ASSERT_EQUAL_INT(BNS_OK, ricardian_tea_apply_action(&c, amount, 1700000000, &adv));
        ricardian_tea_t ac = c;                 /* shallow copy; artifact + params shared */
        ricardian_tea_state_t saved = ac.state;
        ac.state = adv;
        byte_buf_t exp; byte_buf_init(&exp);
        TEST_ASSERT_EQUAL_INT(BNS_OK, ricardian_tea_locking_script(&ac, false, &exp));
        ac.state = saved;
        ricardian_tea_state_free(&adv);

        byte_buf_t pre; byte_buf_init(&pre);
        TEST_ASSERT_EQUAL_INT(BNS_OK, ricardian_tea_locking_script(&c, false, &pre));

        TEST_ASSERT_EQUAL_UINT_MESSAGE((unsigned)exp.len, (unsigned)b.tx.outputs[0].script.len,
            "output[0] locking-script length != advanced-state script (state not advanced)");
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(exp.data, b.tx.outputs[0].script.data, exp.len,
            "output[0] locking script != advanced-state script (executeTea emitted stale state -> unminable)");
        bool same_as_pre = (pre.len == b.tx.outputs[0].script.len
                            && memcmp(pre.data, b.tx.outputs[0].script.data, pre.len) == 0);
        TEST_ASSERT_FALSE_MESSAGE(same_as_pre,
            "output[0] == PRE-spend state script: executeTea did not advance txCount/window/tier");
        byte_buf_free(&exp); byte_buf_free(&pre);
    }

    bn_free(amount);
    tx_builder_free(&b);
    free_params(&c);
}

int main(void)
{
    g_art_ok = (load_artifact("artifacts/ricardianTea.json", &g_art) == BNS_OK);
    UNITY_BEGIN();
    RUN_TEST(test_executeTea_change_includes_identity_value);
    return UNITY_END();
}
