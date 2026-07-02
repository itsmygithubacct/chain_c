/*
 * test_spend.c — Unity tests for wallet_build_signed_spend (wallet/spend.h).
 *
 * OFFLINE: builds + signs spends against synthetic UTXOs (no network) and proves
 * correctness by VERIFYING every input's ECDSA signature against the recomputed
 * BIP143/FORKID sighash. A tx whose every input signature verifies is spendable.
 * Also checks value conservation, UTXO selection, change/dust, and sweep.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "unity.h"
#include "wallet/spend.h"
#include "wallet/keygen.h"
#include "bsv/address.h"
#include "bsv/tx.h"
#include "bsv/sighash.h"
#include "bsv/script_utils.h"
#include "crypto/ecdsa.h"
#include "crypto/hash.h"
#include "common/bytes.h"

void setUp(void) {}
void tearDown(void) {}

/* Make a synthetic confirmed funding UTXO. */
static funding_utxo_t mk_utxo(char tag, uint32_t vout, int64_t sats)
{
    funding_utxo_t u;
    memset(&u, 0, sizeof u);
    memset(u.tx_id, tag, 64);
    u.tx_id[64] = '\0';
    u.output_index = vout;
    u.satoshis = sats;
    u.confirmed = true;
    return u;
}

/* Verify input `k` of a signed, deserialized tx against `pub`, spending a
 * prevout of `input_sats` locked to `funder_spk`. Returns true iff the
 * scriptSig's DER signature verifies over the recomputed BIP143 sighash. */
static bool verify_input(const bsv_tx_t *tx, size_t k,
                         const uint8_t *funder_spk, size_t funder_spk_len,
                         uint64_t input_sats, const ecdsa_pubkey_t *pub)
{
    uint8_t digest[BONSAI_SHA256_LEN];
    if (bip143_sighash(tx, k, funder_spk, funder_spk_len, input_sats,
                       BONSAI_SIGHASH_ALL_FORKID, digest) != BNS_OK)
        return false;
    const byte_buf_t *ss = &tx->inputs[k].script_sig;
    if (ss->len < 2) return false;
    size_t push = ss->data[0];          /* DER||sighashtype length */
    if (push < 2 || (size_t)1 + push > ss->len) return false;
    size_t der_len = push - 1;          /* strip the trailing sighash byte */
    const uint8_t *der = ss->data + 1;
    if (ss->data[1 + der_len] != BONSAI_SIGHASH_ALL_FORKID) return false;
    return ecdsa_verify(digest, der, der_len, pub);
}

/* Common fixture: a funding key + its P2PKH scriptCode + a recipient address. */
typedef struct {
    char *fund_wif, *fund_addr, *recip_addr, *unused;
    ecdsa_key_t *key;
    ecdsa_pubkey_t *pub;
    byte_buf_t funder_spk;
} fix_t;

static void fix_make(fix_t *f)
{
    memset(f, 0, sizeof *f);
    TEST_ASSERT_EQUAL_INT(BNS_OK, wallet_generate_key(BSV_MAINNET, &f->fund_wif, &f->fund_addr));
    TEST_ASSERT_EQUAL_INT(BNS_OK, wallet_generate_key(BSV_MAINNET, &f->unused, &f->recip_addr));
    TEST_ASSERT_EQUAL_INT(BNS_OK, ecdsa_key_from_wif(f->fund_wif, &f->key, NULL));
    TEST_ASSERT_EQUAL_INT(BNS_OK, ecdsa_key_derive_pubkey(f->key, &f->pub));
    uint8_t pc[BONSAI_ECDSA_PUBKEY_COMPRESSED_LEN], h[BONSAI_HASH160_LEN];
    TEST_ASSERT_EQUAL_INT(BNS_OK, ecdsa_pubkey_serialize_compressed(f->pub, pc));
    hash160(pc, sizeof pc, h);
    byte_buf_init(&f->funder_spk);
    TEST_ASSERT_EQUAL_INT(BNS_OK, build_p2pkh_script(h, &f->funder_spk));
}

static void fix_free(fix_t *f)
{
    byte_buf_free(&f->funder_spk);
    ecdsa_pubkey_free(f->pub);
    ecdsa_key_free(f->key);
    free(f->fund_wif); free(f->fund_addr); free(f->recip_addr); free(f->unused);
}

/* feeForSize(sizeBytes, feePerKb) = ceil(sizeBytes/1000 * feePerKb) — the divide-
 * first order chain_c uses (bsv_fees / tx_change). */
static uint64_t fee_for_size_bytes(size_t size_bytes, uint64_t rate)
{
    return (uint64_t)ceil(((double)size_bytes / 1000.0) * (double)rate);
}

/* Regression for the fee-on-unsigned-size bug: the fee actually paid must cover
 * the REAL signed transaction at the policy rate. Before the fix the fee was
 * computed over the unsigned tx (empty scriptSigs, ~41B/input) and underpaid ~2x,
 * so res.fee came out well below feeForSize(real_signed_size). */
static void assert_fee_covers_signed_size(const spend_result_t *res, uint64_t rate)
{
    size_t signed_size = strlen(res->raw_hex) / 2;   /* deserialized wire bytes */
    uint64_t need = fee_for_size_bytes(signed_size, rate);
    /* No underpay: the paid fee must meet the policy minimum for the signed size. */
    TEST_ASSERT_TRUE_MESSAGE(res->fee >= need, "fee underpays the signed-size policy rate");
    /* No gross overpay: the estimate is a tight upper bound (<=2B/input of DER slack),
     * so the paid fee stays within one KB-rate step of the exact minimum. */
    TEST_ASSERT_TRUE_MESSAGE(res->fee <= need + rate, "fee grossly overpays");
}

/* A 2-input -> recipient+change spend: every signature must verify, and value
 * must be conserved. */
static void test_spend_pay_two_inputs_verifies(void)
{
    fix_t f; fix_make(&f);
    funding_utxo_t utxos[2] = { mk_utxo('a', 0, 100000), mk_utxo('b', 1, 50000) };

    spend_recipient_t r;
    memset(&r, 0, sizeof r);
    strncpy(r.address, f.recip_addr, sizeof r.address - 1);
    r.satoshis = 120000;

    spend_plan_t plan;
    memset(&plan, 0, sizeof plan);
    plan.recipients = &r; plan.num_recipients = 1;
    plan.change_address = f.fund_addr; plan.fee_per_kb = 50;

    spend_result_t res;
    bonsai_err_ctx err = {0};
    int rc = wallet_build_signed_spend(BSV_MAINNET, f.key, f.fund_addr,
                                       utxos, 2, &plan, &res, &err);
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, rc, err.msg);
    TEST_ASSERT_EQUAL_UINT64(150000, res.total_in);
    TEST_ASSERT_EQUAL_UINT64(res.total_in, res.total_out + res.fee); /* conservation */
    TEST_ASSERT_EQUAL_UINT(2, res.num_inputs);
    TEST_ASSERT_TRUE(res.fee > 0);
    TEST_ASSERT_TRUE(res.change > 0);
    assert_fee_covers_signed_size(&res, 50);   /* regression: fee-on-unsigned-size */

    bsv_tx_t tx; tx_init(&tx);
    TEST_ASSERT_EQUAL_INT(BNS_OK, tx_deserialize(res.raw_hex, &tx));
    TEST_ASSERT_EQUAL_UINT(2, tx.num_inputs);
    TEST_ASSERT_EQUAL_UINT(2, tx.num_outputs); /* recipient + change */
    TEST_ASSERT_TRUE(verify_input(&tx, 0, f.funder_spk.data, f.funder_spk.len, 100000, f.pub));
    TEST_ASSERT_TRUE(verify_input(&tx, 1, f.funder_spk.data, f.funder_spk.len, 50000, f.pub));
    /* recipient output 0 carries the requested amount */
    TEST_ASSERT_EQUAL_UINT64(120000, tx.outputs[0].satoshis);

    tx_free(&tx);
    spend_result_free(&res);
    fix_free(&f);
}

/* A single-input pay where change is dust => no change output, remainder to fee. */
static void test_spend_dust_change_folds_into_fee(void)
{
    fix_t f; fix_make(&f);
    funding_utxo_t utxos[1] = { mk_utxo('c', 0, 50500) };

    spend_recipient_t r; memset(&r, 0, sizeof r);
    strncpy(r.address, f.recip_addr, sizeof r.address - 1);
    r.satoshis = 50000;  /* leaves ~500 which is < dust(546) after fee */

    spend_plan_t plan; memset(&plan, 0, sizeof plan);
    plan.recipients = &r; plan.num_recipients = 1;
    plan.change_address = f.fund_addr; plan.fee_per_kb = 50;

    spend_result_t res; bonsai_err_ctx err = {0};
    int rc = wallet_build_signed_spend(BSV_MAINNET, f.key, f.fund_addr, utxos, 1, &plan, &res, &err);
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, rc, err.msg);
    TEST_ASSERT_EQUAL_UINT64(0, res.change);
    TEST_ASSERT_EQUAL_UINT64(res.total_in, res.total_out + res.fee);

    bsv_tx_t tx; tx_init(&tx);
    TEST_ASSERT_EQUAL_INT(BNS_OK, tx_deserialize(res.raw_hex, &tx));
    TEST_ASSERT_EQUAL_UINT(1, tx.num_outputs); /* recipient only, no change */
    TEST_ASSERT_TRUE(verify_input(&tx, 0, f.funder_spk.data, f.funder_spk.len, 50500, f.pub));
    tx_free(&tx);
    spend_result_free(&res);
    fix_free(&f);
}

/* Sweep (send_all) sends everything minus fee to one recipient, no change. */
static void test_spend_sweep_verifies(void)
{
    fix_t f; fix_make(&f);
    funding_utxo_t utxos[2] = { mk_utxo('d', 0, 30000), mk_utxo('e', 3, 70000) };

    spend_recipient_t r; memset(&r, 0, sizeof r);
    strncpy(r.address, f.recip_addr, sizeof r.address - 1);

    spend_plan_t plan; memset(&plan, 0, sizeof plan);
    plan.recipients = &r; plan.num_recipients = 1;
    plan.send_all = true; plan.fee_per_kb = 50;

    spend_result_t res; bonsai_err_ctx err = {0};
    int rc = wallet_build_signed_spend(BSV_MAINNET, f.key, f.fund_addr, utxos, 2, &plan, &res, &err);
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, rc, err.msg);
    TEST_ASSERT_EQUAL_UINT64(100000, res.total_in);
    TEST_ASSERT_EQUAL_UINT64(0, res.change);
    TEST_ASSERT_EQUAL_UINT64(res.total_in, res.total_out + res.fee);
    assert_fee_covers_signed_size(&res, 50);   /* regression: fee-on-unsigned-size */

    bsv_tx_t tx; tx_init(&tx);
    TEST_ASSERT_EQUAL_INT(BNS_OK, tx_deserialize(res.raw_hex, &tx));
    TEST_ASSERT_EQUAL_UINT(1, tx.num_outputs);
    TEST_ASSERT_EQUAL_UINT64(res.total_out, tx.outputs[0].satoshis);
    TEST_ASSERT_TRUE(verify_input(&tx, 0, f.funder_spk.data, f.funder_spk.len, 30000, f.pub));
    TEST_ASSERT_TRUE(verify_input(&tx, 1, f.funder_spk.data, f.funder_spk.len, 70000, f.pub));
    tx_free(&tx);
    spend_result_free(&res);
    fix_free(&f);
}

/* OP_RETURN data output + change; signature verifies, opreturn output is 0-sat. */
static void test_spend_opreturn_verifies(void)
{
    fix_t f; fix_make(&f);
    funding_utxo_t utxos[1] = { mk_utxo('f', 0, 100000) };
    const uint8_t data[] = "hello chain_c";

    spend_plan_t plan; memset(&plan, 0, sizeof plan);
    plan.num_recipients = 0;
    plan.op_return_data = data; plan.op_return_len = sizeof data - 1;
    plan.change_address = f.fund_addr; plan.fee_per_kb = 50;

    spend_result_t res; bonsai_err_ctx err = {0};
    int rc = wallet_build_signed_spend(BSV_MAINNET, f.key, f.fund_addr, utxos, 1, &plan, &res, &err);
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, rc, err.msg);
    TEST_ASSERT_EQUAL_UINT64(res.total_in, res.total_out + res.fee);
    assert_fee_covers_signed_size(&res, 50);   /* regression: fee-on-unsigned-size */

    bsv_tx_t tx; tx_init(&tx);
    TEST_ASSERT_EQUAL_INT(BNS_OK, tx_deserialize(res.raw_hex, &tx));
    TEST_ASSERT_EQUAL_UINT(2, tx.num_outputs);        /* opreturn + change */
    TEST_ASSERT_EQUAL_UINT64(0, tx.outputs[0].satoshis); /* OP_RETURN is 0-sat */
    TEST_ASSERT_EQUAL_HEX8(0x6a, tx.outputs[0].script.data[1]); /* 00 6a ... */
    TEST_ASSERT_TRUE(verify_input(&tx, 0, f.funder_spk.data, f.funder_spk.len, 100000, f.pub));
    tx_free(&tx);
    spend_result_free(&res);
    fix_free(&f);
}

/* Insufficient funds is reported, not silently mis-built. */
static void test_spend_insufficient_funds(void)
{
    fix_t f; fix_make(&f);
    funding_utxo_t utxos[1] = { mk_utxo('g', 0, 1000) };
    spend_recipient_t r; memset(&r, 0, sizeof r);
    strncpy(r.address, f.recip_addr, sizeof r.address - 1);
    r.satoshis = 1000000;
    spend_plan_t plan; memset(&plan, 0, sizeof plan);
    plan.recipients = &r; plan.num_recipients = 1; plan.change_address = f.fund_addr;
    spend_result_t res; bonsai_err_ctx err = {0};
    int rc = wallet_build_signed_spend(BSV_MAINNET, f.key, f.fund_addr, utxos, 1, &plan, &res, &err);
    TEST_ASSERT_EQUAL_INT(BNS_ERANGE, rc);
    fix_free(&f);
}

/* A bad recipient address is rejected (never silently burned). */
static void test_spend_bad_address_rejected(void)
{
    fix_t f; fix_make(&f);
    funding_utxo_t utxos[1] = { mk_utxo('h', 0, 100000) };
    spend_recipient_t r; memset(&r, 0, sizeof r);
    strncpy(r.address, "1ThisIsNotAValidAddressXXXXXXXXX", sizeof r.address - 1);
    r.satoshis = 50000;
    spend_plan_t plan; memset(&plan, 0, sizeof plan);
    plan.recipients = &r; plan.num_recipients = 1; plan.change_address = f.fund_addr;
    spend_result_t res; bonsai_err_ctx err = {0};
    int rc = wallet_build_signed_spend(BSV_MAINNET, f.key, f.fund_addr, utxos, 1, &plan, &res, &err);
    TEST_ASSERT_NOT_EQUAL(BNS_OK, rc);
    fix_free(&f);
}

static void test_spend_rejects_recipient_total_over_money(void)
{
    fix_t f; fix_make(&f);
    funding_utxo_t utxos[1] = { mk_utxo('i', 0, 100000) };

    spend_recipient_t rs[2];
    memset(rs, 0, sizeof rs);
    strncpy(rs[0].address, f.recip_addr, sizeof rs[0].address - 1);
    strncpy(rs[1].address, f.recip_addr, sizeof rs[1].address - 1);
    rs[0].satoshis = (uint64_t)BONSAI_MAX_MONEY;
    rs[1].satoshis = WALLET_DUST_THRESHOLD;

    spend_plan_t plan; memset(&plan, 0, sizeof plan);
    plan.recipients = rs; plan.num_recipients = 2; plan.change_address = f.fund_addr;
    spend_result_t res; bonsai_err_ctx err = {0};
    int rc = wallet_build_signed_spend(BSV_MAINNET, f.key, f.fund_addr, utxos, 1, &plan, &res, &err);
    TEST_ASSERT_EQUAL_INT(BNS_ERANGE, rc);
    fix_free(&f);
}

static void test_spend_rejects_funding_total_over_money(void)
{
    fix_t f; fix_make(&f);
    funding_utxo_t utxos[2] = {
        mk_utxo('j', 0, BONSAI_MAX_MONEY),
        mk_utxo('k', 1, 1),
    };

    spend_recipient_t r; memset(&r, 0, sizeof r);
    strncpy(r.address, f.recip_addr, sizeof r.address - 1);
    spend_plan_t plan; memset(&plan, 0, sizeof plan);
    plan.recipients = &r; plan.num_recipients = 1; plan.send_all = true;
    spend_result_t res; bonsai_err_ctx err = {0};
    int rc = wallet_build_signed_spend(BSV_MAINNET, f.key, f.fund_addr, utxos, 2, &plan, &res, &err);
    TEST_ASSERT_EQUAL_INT(BNS_ERANGE, rc);
    fix_free(&f);
}

static void test_spend_rejects_negative_utxo(void)
{
    fix_t f; fix_make(&f);
    funding_utxo_t utxos[1] = { mk_utxo('l', 0, -1) };

    spend_recipient_t r; memset(&r, 0, sizeof r);
    strncpy(r.address, f.recip_addr, sizeof r.address - 1);
    spend_plan_t plan; memset(&plan, 0, sizeof plan);
    plan.recipients = &r; plan.num_recipients = 1; plan.send_all = true;
    spend_result_t res; bonsai_err_ctx err = {0};
    int rc = wallet_build_signed_spend(BSV_MAINNET, f.key, f.fund_addr, utxos, 1, &plan, &res, &err);
    TEST_ASSERT_EQUAL_INT(BNS_ERANGE, rc);
    fix_free(&f);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_spend_pay_two_inputs_verifies);
    RUN_TEST(test_spend_dust_change_folds_into_fee);
    RUN_TEST(test_spend_sweep_verifies);
    RUN_TEST(test_spend_opreturn_verifies);
    RUN_TEST(test_spend_insufficient_funds);
    RUN_TEST(test_spend_bad_address_rejected);
    RUN_TEST(test_spend_rejects_recipient_total_over_money);
    RUN_TEST(test_spend_rejects_funding_total_over_money);
    RUN_TEST(test_spend_rejects_negative_utxo);
    return UNITY_END();
}
