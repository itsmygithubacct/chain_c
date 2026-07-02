/*
 * wallet/spend.c — reusable multi-input/output P2PKH spend builder.
 * See include/wallet/spend.h. Generalizes scripts/cpfp_lib.c.
 */
#include "wallet/spend.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "common/bytes.h"
#include "crypto/hash.h"
#include "bsv/base58.h"
#include "bsv/tx.h"
#include "bsv/tx_builder.h"
#include "bsv/sighash.h"
#include "bsv/script_utils.h"
#include "bsv/tx_change.h"   /* estimate_size + sendtime_fee_window (NOT bsv_fees.h:
                              * both headers define a conflicting fee_window_t) */

void spend_result_free(spend_result_t *r)
{
    if (!r) return;
    free(r->raw_hex);
    free(r->txid);
    r->raw_hex = NULL;
    r->txid = NULL;
}

/* Decode a base58check P2PKH address -> 20-byte hash160, verifying the version
 * byte for `net`. Mirrors deploy_lib.c address_to_hash160. */
static int addr_to_h160(const char *addr, bsv_network_t net, uint8_t out[20])
{
    if (!addr || !addr[0]) return BNS_EINVAL;
    byte_buf_t payload;
    byte_buf_init(&payload);
    int rc = base58check_decode(addr, &payload);
    if (rc != BNS_OK) { byte_buf_free(&payload); return rc; }
    if (payload.len != 21) { byte_buf_free(&payload); return BNS_EPARSE; }
    uint8_t want = (net == BSV_TESTNET) ? 0x6f : 0x00;
    if (payload.data[0] != want) { byte_buf_free(&payload); return BNS_EINVAL; }
    memcpy(out, payload.data + 1, 20);
    byte_buf_free(&payload);
    return BNS_OK;
}

/* Minimum fee (sats) for a tx of `size` bytes at `rate` sats/KB. Uses
 * sendtime_fee_window().min == feeForSize (divide-by-1000-first order). */
static int fee_for(size_t size, uint64_t rate, uint64_t *out)
{
    fee_window_t w;
    int rc = sendtime_fee_window(size, rate, &w);
    if (rc != BNS_OK) return rc;
    *out = w.min;
    return BNS_OK;
}

/* Conservative signed-size estimate by counts (selection only; the final fee is
 * settled from estimate_size on the tx AFTER placeholder scriptSigs are installed,
 * see WALLET_P2PKH_SCRIPTSIG_MAX below). */
static size_t est_size_by_counts(size_t n_in, size_t n_out, size_t opreturn_len)
{
    size_t s = 10 + 9;            /* version+locktime+varint slack */
    s += n_in * 148;             /* P2PKH input incl. ~107B scriptSig */
    s += n_out * 34;             /* P2PKH output */
    if (opreturn_len) s += 8 + 3 + opreturn_len; /* value+pushhdr+data */
    return s;
}

/* Worst-case serialized length of a compressed-P2PKH scriptSig, used as a stand-in
 * so the final fee is computed over the SIGNED size (estimate_size serializes the
 * CURRENT scriptSig, which is empty until we sign). The scriptSig is
 * push(DER||sighashType) + push(33-byte pubkey) = (1 + (DERmax+1)) + (1 + 33).
 * A low-S secp256k1 DER signature is at most 72 bytes, so 1 + 73 + 1 + 33 = 108.
 * Using the maximum keeps the estimate an upper bound, so the fee never underpays
 * the policy rate (the real signatures, 0-2 bytes shorter, replace these below). */
#define WALLET_P2PKH_SCRIPTSIG_MAX 108

static int add_money_u64(uint64_t *total, uint64_t v)
{
    if (!total) return BNS_EINVAL;
    if (*total > (uint64_t)BONSAI_MAX_MONEY ||
        v > (uint64_t)BONSAI_MAX_MONEY ||
        v > (uint64_t)BONSAI_MAX_MONEY - *total)
        return BNS_ERANGE;
    *total += v;
    return BNS_OK;
}

static int add_money_i64(uint64_t *total, int64_t v)
{
    if (v < 0) return BNS_ERANGE;
    return add_money_u64(total, (uint64_t)v);
}

static int money_sum2(uint64_t a, uint64_t b, uint64_t *out)
{
    uint64_t total = a;
    int rc = add_money_u64(&total, b);
    if (rc != BNS_OK) return rc;
    *out = total;
    return BNS_OK;
}

int wallet_build_signed_spend(bsv_network_t net,
                              const ecdsa_key_t *key,
                              const char *funding_address,
                              const funding_utxo_t *utxos, size_t num_utxos,
                              const spend_plan_t *plan,
                              spend_result_t *out,
                              bonsai_err_ctx *err)
{
    if (!key || !funding_address || !plan || !out || (num_utxos && !utxos) ||
        (plan->num_recipients && !plan->recipients))
        return bns_fail(err, BNS_EINVAL, "invalid spend arguments");
    memset(out, 0, sizeof *out);

    const uint64_t rate = plan->fee_per_kb ? plan->fee_per_kb
                                           : (uint64_t)BONSAI_FEE_PER_KB;
    const char *change_addr = plan->change_address ? plan->change_address
                                                   : funding_address;
    const bool has_opreturn = plan->op_return_data && plan->op_return_len > 0;

    if (plan->send_all) {
        if (plan->num_recipients != 1)
            return bns_fail(err, BNS_EINVAL, "send_all requires exactly one recipient");
    } else if (plan->num_recipients == 0 && !has_opreturn) {
        return bns_fail(err, BNS_EINVAL, "no recipients and no OP_RETURN data");
    }

    int rc = BNS_OK;
    size_t *sel = NULL;          /* selected utxo indices */
    ecdsa_pubkey_t *pub = NULL;
    byte_buf_t funder_spk; byte_buf_init(&funder_spk);
    byte_buf_t opret_spk;  byte_buf_init(&opret_spk);
    tx_builder_t b; bool b_init = false;
    char *raw = NULL, *txid = NULL;

    /* --- funding key -> pubkey/hash160/scriptCode --------------------------- */
    uint8_t pub_comp[BONSAI_ECDSA_PUBKEY_COMPRESSED_LEN];
    rc = ecdsa_key_derive_pubkey(key, &pub);
    if (rc != BNS_OK) { bns_fail(err, rc, "pubkey derive failed"); goto cleanup; }
    rc = ecdsa_pubkey_serialize_compressed(pub, pub_comp);
    if (rc != BNS_OK) { bns_fail(err, rc, "pubkey serialize failed"); goto cleanup; }
    uint8_t funder_h160[BONSAI_HASH160_LEN];
    hash160(pub_comp, sizeof pub_comp, funder_h160);
    rc = build_p2pkh_script(funder_h160, &funder_spk);
    if (rc != BNS_OK) { bns_fail(err, rc, "scriptCode build failed"); goto cleanup; }

    /* --- recipient totals + output count for estimation --------------------- */
    uint64_t total_recip = 0;
    if (!plan->send_all) {
        for (size_t i = 0; i < plan->num_recipients; i++) {
            if (plan->recipients[i].satoshis == 0)
                { rc = bns_fail(err, BNS_EINVAL, "recipient amount is zero"); goto cleanup; }
            if (plan->recipients[i].satoshis < WALLET_DUST_THRESHOLD)
                { rc = bns_fail(err, BNS_EINVAL, "recipient amount below dust"); goto cleanup; }
            rc = add_money_u64(&total_recip, plan->recipients[i].satoshis);
            if (rc != BNS_OK)
                { rc = bns_fail(err, BNS_ERANGE, "recipient total out of range"); goto cleanup; }
        }
    }
    if (has_opreturn) {
        rc = build_opreturn_script(plan->op_return_data, plan->op_return_len, &opret_spk);
        if (rc != BNS_OK) { bns_fail(err, rc, "OP_RETURN build failed"); goto cleanup; }
    }
    size_t n_recip_out = plan->send_all ? 1 : plan->num_recipients;
    size_t n_out_est = n_recip_out + (has_opreturn ? 1 : 0)
                       + (plan->send_all ? 0 : 1 /*change*/);

    /* --- UTXO selection (best-first; caller pre-ranked) --------------------- */
    sel = calloc(num_utxos ? num_utxos : 1, sizeof *sel);
    if (!sel) { rc = bns_fail(err, BNS_ENOMEM, "oom"); goto cleanup; }
    size_t sel_count = 0;
    uint64_t running_in = 0;
    if (plan->send_all) {
        for (size_t i = 0; i < num_utxos; i++) {
            sel[sel_count++] = i;
            rc = add_money_i64(&running_in, utxos[i].satoshis);
            if (rc != BNS_OK)
                { rc = bns_fail(err, BNS_ERANGE, "funding value out of range"); goto cleanup; }
        }
        if (sel_count == 0) { rc = bns_fail(err, BNS_ERANGE, "no UTXOs to sweep"); goto cleanup; }
    } else {
        bool enough = false;
        for (size_t i = 0; i < num_utxos; i++) {
            sel[sel_count++] = i;
            rc = add_money_i64(&running_in, utxos[i].satoshis);
            if (rc != BNS_OK)
                { rc = bns_fail(err, BNS_ERANGE, "funding value out of range"); goto cleanup; }
            uint64_t est_fee = 0;
            rc = fee_for(est_size_by_counts(sel_count, n_out_est,
                                            has_opreturn ? opret_spk.len : 0), rate, &est_fee);
            if (rc != BNS_OK) { bns_fail(err, rc, "fee estimate failed"); goto cleanup; }
            uint64_t need = 0;
            rc = money_sum2(total_recip, est_fee, &need);
            if (rc != BNS_OK)
                { rc = bns_fail(err, BNS_ERANGE, "spend total out of range"); goto cleanup; }
            if (running_in >= need) { enough = true; break; }
        }
        if (!enough) { rc = bns_fail(err, BNS_ERANGE, "insufficient funds"); goto cleanup; }
    }

    /* --- build the tx (empty scriptSigs) ------------------------------------ */
    tx_builder_init(&b); b_init = true;
    for (size_t k = 0; k < sel_count; k++) {
        rc = tx_builder_add_input(&b, utxos[sel[k]].tx_id, utxos[sel[k]].output_index,
                                  NULL, 0, 0xffffffff);
        if (rc != BNS_OK) { bns_fail(err, rc, "add input failed"); goto cleanup; }
    }

    /* recipient outputs (send_all: a single placeholder set after fee) */
    if (plan->send_all) {
        uint8_t h[BONSAI_HASH160_LEN];
        rc = addr_to_h160(plan->recipients[0].address, net, h);
        if (rc != BNS_OK) { bns_fail(err, rc, "bad recipient address"); goto cleanup; }
        byte_buf_t spk; byte_buf_init(&spk);
        rc = build_p2pkh_script(h, &spk);
        if (rc == BNS_OK) rc = tx_builder_add_output(&b, spk.data, spk.len, 0);
        byte_buf_free(&spk);
        if (rc != BNS_OK) { bns_fail(err, rc, "add output failed"); goto cleanup; }
    } else {
        for (size_t i = 0; i < plan->num_recipients; i++) {
            uint8_t h[BONSAI_HASH160_LEN];
            rc = addr_to_h160(plan->recipients[i].address, net, h);
            if (rc != BNS_OK) { bns_fail(err, rc, "bad recipient address"); goto cleanup; }
            byte_buf_t spk; byte_buf_init(&spk);
            rc = build_p2pkh_script(h, &spk);
            if (rc == BNS_OK) rc = tx_builder_add_output(&b, spk.data, spk.len,
                                                         plan->recipients[i].satoshis);
            byte_buf_free(&spk);
            if (rc != BNS_OK) { bns_fail(err, rc, "add output failed"); goto cleanup; }
        }
    }
    /* OP_RETURN (0-sat) */
    if (has_opreturn) {
        rc = tx_builder_add_output(&b, opret_spk.data, opret_spk.len, 0);
        if (rc != BNS_OK) { bns_fail(err, rc, "add OP_RETURN failed"); goto cleanup; }
    }
    /* change output placeholder (normal only); it is the LAST output */
    size_t change_index = (size_t)-1;
    if (!plan->send_all) {
        uint8_t h[BONSAI_HASH160_LEN];
        rc = addr_to_h160(change_addr, net, h);
        if (rc != BNS_OK) { bns_fail(err, rc, "bad change address"); goto cleanup; }
        byte_buf_t spk; byte_buf_init(&spk);
        rc = build_p2pkh_script(h, &spk);
        if (rc == BNS_OK) rc = tx_builder_add_output(&b, spk.data, spk.len, 0);
        byte_buf_free(&spk);
        if (rc != BNS_OK) { bns_fail(err, rc, "add change failed"); goto cleanup; }
        change_index = b.tx.num_outputs - 1;
    }

    /* --- fee + change settle ------------------------------------------------ */
    /* Size the tx as if signed: install worst-case scriptSig stand-ins on every
     * selected input so estimate_size (which serializes the current, still-empty
     * scriptSig) reflects the final signed bytes. Without this the fee is computed
     * over ~41-byte inputs instead of ~148-byte ones and underpays ~2x. The real
     * signatures overwrite these placeholders in the signing loop below; the BIP143
     * sighash uses the explicit scriptCode, not the input scriptSig, so the
     * placeholders do not affect any signature. */
    {
        static const uint8_t sig_placeholder[WALLET_P2PKH_SCRIPTSIG_MAX] = {0};
        for (size_t k = 0; k < sel_count; k++) {
            byte_buf_free(&b.tx.inputs[k].script_sig);
            rc = byte_buf_from(&b.tx.inputs[k].script_sig,
                               sig_placeholder, sizeof sig_placeholder);
            if (rc != BNS_OK) { bns_fail(err, rc, "placeholder scriptSig failed"); goto cleanup; }
        }
    }

    size_t size_bytes = 0;
    rc = estimate_size(&b.tx, &size_bytes);
    if (rc != BNS_OK) { bns_fail(err, rc, "size estimate failed"); goto cleanup; }
    uint64_t fee = 0;
    rc = fee_for(size_bytes, rate, &fee);
    if (rc != BNS_OK) { bns_fail(err, rc, "fee compute failed"); goto cleanup; }
    if (fee > (uint64_t)BONSAI_MAX_MONEY)
        { rc = bns_fail(err, BNS_ERANGE, "fee out of range"); goto cleanup; }

    uint64_t change = 0;
    uint64_t total_out = 0;
    if (plan->send_all) {
        if (running_in <= fee || running_in - fee < WALLET_DUST_THRESHOLD)
            { rc = bns_fail(err, BNS_ERANGE, "sweep amount below dust after fee"); goto cleanup; }
        uint64_t amt = running_in - fee;
        b.tx.outputs[0].satoshis = amt;
        total_out = amt;
    } else {
        uint64_t need = 0;
        rc = money_sum2(total_recip, fee, &need);
        if (rc != BNS_OK)
            { rc = bns_fail(err, BNS_ERANGE, "spend total out of range"); goto cleanup; }
        if (running_in < need)
            { rc = bns_fail(err, BNS_ERANGE, "insufficient funds for fee"); goto cleanup; }
        change = running_in - need;
        if (change < WALLET_DUST_THRESHOLD) {
            /* Drop the (last) change output; the sub-dust remainder folds into
             * the miner fee. */
            byte_buf_free(&b.tx.outputs[change_index].script);
            b.tx.num_outputs--;
            change = 0;
            fee = running_in - total_recip; /* actual miner fee with no change */
            total_out = total_recip;
            /* refresh the reported size for the now-smaller tx; on the (OOM-only)
             * failure path keep the pre-drop size, a safe over-estimate. */
            { size_t s2; if (estimate_size(&b.tx, &s2) == BNS_OK) size_bytes = s2; }
        } else {
            b.tx.outputs[change_index].satoshis = change;
            total_out = running_in - fee;
        }
    }

    /* --- sign every input (BIP143/FORKID over the funder P2PKH scriptCode) --- */
    for (size_t k = 0; k < sel_count; k++) {
        uint8_t digest[BONSAI_SHA256_LEN];
        rc = bip143_sighash(&b.tx, k, funder_spk.data, funder_spk.len,
                            (uint64_t)utxos[sel[k]].satoshis,
                            BONSAI_SIGHASH_ALL_FORKID, digest);
        if (rc != BNS_OK) { bns_fail(err, rc, "sighash failed"); goto cleanup; }

        byte_buf_t der; byte_buf_init(&der);
        rc = ecdsa_sign_low_s(digest, key, &der);
        if (rc != BNS_OK) { byte_buf_free(&der); bns_fail(err, rc, "signing failed"); goto cleanup; }

        byte_buf_t ss; byte_buf_init(&ss);
        size_t sig_push = der.len + 1; /* + sighash type byte */
        rc = byte_buf_append_byte(&ss, (uint8_t)sig_push);
        if (rc == BNS_OK) rc = byte_buf_append(&ss, der.data, der.len);
        if (rc == BNS_OK) rc = byte_buf_append_byte(&ss, BONSAI_SIGHASH_ALL_FORKID);
        if (rc == BNS_OK) rc = byte_buf_append_byte(&ss, (uint8_t)sizeof pub_comp);
        if (rc == BNS_OK) rc = byte_buf_append(&ss, pub_comp, sizeof pub_comp);
        byte_buf_free(&der);
        if (rc != BNS_OK) { byte_buf_free(&ss); bns_fail(err, rc, "scriptSig build failed"); goto cleanup; }

        byte_buf_free(&b.tx.inputs[k].script_sig);
        rc = byte_buf_from(&b.tx.inputs[k].script_sig, ss.data, ss.len);
        byte_buf_free(&ss);
        if (rc != BNS_OK) { bns_fail(err, rc, "scriptSig install failed"); goto cleanup; }
    }

    /* --- serialize + txid --------------------------------------------------- */
    rc = tx_builder_build_hex(&b, &raw);
    if (rc != BNS_OK) { bns_fail(err, rc, "serialize failed"); goto cleanup; }
    rc = tx_id(&b.tx, &txid);
    if (rc != BNS_OK) { bns_fail(err, rc, "txid failed"); goto cleanup; }

    out->raw_hex   = raw;   raw = NULL;
    out->txid      = txid;  txid = NULL;
    out->total_in  = running_in;
    out->total_out = total_out;
    out->fee       = fee;
    out->change    = change;
    out->num_inputs = sel_count;
    out->size_bytes = size_bytes;
    rc = BNS_OK;

cleanup:
    free(raw);
    free(txid);
    if (b_init) tx_builder_free(&b);
    byte_buf_free(&funder_spk);
    byte_buf_free(&opret_spk);
    ecdsa_pubkey_free(pub);
    free(sel);
    return rc;
}
