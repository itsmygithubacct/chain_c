/*
 * txbuilders/arp_tx_builder.c — pinned-output unsigned-tx builders for the ARP-1
 * contracts PublisherTea (announceRelease, activateRelease, cancelPending,
 * invalidateRelease, retire) and AttestorTea (slashEquivocation, stake, withdraw).
 *
 * Port of src/arpTxBuilder.ts. Each PublisherTea builder produces the
 * [state, OP_RETURN receipt, change] shape (stateAndReceiptTx); the receipt
 * preimage is built by the per-method contract receipt builders (different
 * domain-tag lengths / field sets). retire/slash/withdraw pay out the full
 * balance with no state output. The 4-byte `now`/`lockTime` is a SIGNED
 * CScriptNum kept at 4 bytes.
 */
#include "txbuilders/arp_tx_builder.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "crypto/hash.h"
#include "bsv/tx_change.h"
#include "bsv/script_utils.h"

/* 'SLASHED\0' burn data (8 bytes ending NUL). TS: '534c415348454400'. */
static const uint8_t SLASHED_MARKER[8] = {
    0x53, 0x4c, 0x41, 0x53, 0x48, 0x45, 0x44, 0x00 };

/* ---- shared helpers ----------------------------------------------------- */

static int add_funding(tx_builder_t *b, const funding_utxos_t *funding,
                       uint64_t *total_in)
{
    *total_in = 0;
    if (!funding) return BNS_OK;
    for (size_t i = 0; i < funding->count; i++) {
        const funding_utxo_t *u = &funding->items[i];
        int rc = tx_builder_add_input(b, u->tx_id, u->output_index, NULL, 0,
                                      0xffffffffu);
        if (rc != BNS_OK) return rc;
        *total_in += (uint64_t)u->satoshis;
    }
    return BNS_OK;
}

static int append_change(tx_builder_t *b, const uint8_t change_hash160[20],
                         uint64_t total_in)
{
    byte_buf_t script;
    byte_buf_init(&script);
    int rc = build_p2pkh_script(change_hash160, &script);
    if (rc != BNS_OK) { byte_buf_free(&script); return rc; }
    rc = tx_builder_add_output(b, script.data, script.len, total_in);
    byte_buf_free(&script);
    if (rc != BNS_OK) return rc;
    size_t change_index = b->tx.num_outputs - 1;
    return update_change_output(&b->tx, change_index, BONSAI_FEE_PER_KB);
}

static int append_p2pkh_pubkey(tx_builder_t *b, const uint8_t pubkey[33],
                               uint64_t satoshis)
{
    uint8_t h160[20];
    hash160(pubkey, 33, h160);
    byte_buf_t script;
    byte_buf_init(&script);
    int rc = build_p2pkh_script(h160, &script);
    if (rc != BNS_OK) { byte_buf_free(&script); return rc; }
    rc = tx_builder_add_output(b, script.data, script.len, satoshis);
    byte_buf_free(&script);
    return rc;
}

static int append_opreturn(tx_builder_t *b, const byte_buf_t *receipt_preimage)
{
    /* The receipt OP_RETURN carries sha256(preimage). */
    uint8_t h[32];
    sha256(receipt_preimage->data, receipt_preimage->len, h);
    byte_buf_t op;
    byte_buf_init(&op);
    int rc = build_opreturn_script(h, 32, &op);
    if (rc != BNS_OK) { byte_buf_free(&op); return rc; }
    rc = tx_builder_add_output(b, op.data, op.len, 0);
    byte_buf_free(&op);
    return rc;
}

/* Common [state(next), OP_RETURN(receipt), change] builder for PublisherTea.
 * `next` already carries the post-spend state; `receipt_preimage` is the exact
 * preimage the contract single-sha256's. Sets nLockTime=now and input[0].seq=0. */
static int state_and_receipt_tx(const publisher_tea_t *next,
                                const arp_utxo_t *utxo,
                                const byte_buf_t *receipt_preimage,
                                int64_t now, const arp_builder_opts_t *opts,
                                tx_builder_t *b)
{
    /* input[0]: contract UTXO, sequence < 0xffffffff to enable nLocktime. */
    int rc = tx_builder_add_input(b, utxo->txid_display, utxo->vout, NULL, 0, 0u);
    if (rc != BNS_OK) return rc;

    uint64_t funding_total = 0;
    if (opts) {
        rc = add_funding(b, opts->funding, &funding_total);
        if (rc != BNS_OK) return rc;
    }

    /* output[0]: recreated state at constant balance. */
    byte_buf_t script;
    byte_buf_init(&script);
    rc = publisher_tea_locking_script(next, false, &script);
    if (rc != BNS_OK) { byte_buf_free(&script); return rc; }
    rc = tx_builder_add_output(b, script.data, script.len, utxo->value);
    byte_buf_free(&script);
    if (rc != BNS_OK) return rc;

    /* output[1]: OP_RETURN <receiptHash> (0 sat). */
    rc = append_opreturn(b, receipt_preimage);
    if (rc != BNS_OK) return rc;

    /* output[2]: change. */
    if (opts && opts->has_change && opts->change_hash160) {
        rc = append_change(b, opts->change_hash160, funding_total);
        if (rc != BNS_OK) return rc;
    }

    tx_builder_set_locktime(b, (uint32_t)now);
    return BNS_OK;
}

/* ---- PublisherTea builders ---------------------------------------------- */

int build_arp_announce(const publisher_tea_t *c, const arp_utxo_t *utxo,
                       const uint8_t bundle_hash[32],
                       const uint8_t file_set_root[32],
                       int64_t now, const arp_builder_opts_t *opts,
                       tx_builder_t *b)
{
    if (!c || !utxo || !bundle_hash || !file_set_root || !b) return BNS_EINVAL;

    /* ANNOUNCE receipt preimage (commits bundleHash, fileSetRoot, current
     * releaseCount, now). */
    byte_buf_t receipt;
    byte_buf_init(&receipt);
    int rc = publisher_tea_announce_receipt(c, bundle_hash, file_set_root, now,
                                            &receipt);
    if (rc != BNS_OK) { byte_buf_free(&receipt); return rc; }

    /* next state: pending = (bundleHash, fileSetRoot, now). */
    publisher_tea_t next = *c;
    byte_buf_t pbh, pfr;
    byte_buf_init(&pbh);
    byte_buf_init(&pfr);
    bn_t *pat = NULL;
    rc = byte_buf_append(&pbh, bundle_hash, 32);
    if (rc == BNS_OK) rc = byte_buf_append(&pfr, file_set_root, 32);
    if (rc == BNS_OK) {
        char dec[32];
        snprintf(dec, sizeof(dec), "%lld", (long long)now);
        rc = bn_parse_dec(dec, &pat);
    }
    if (rc != BNS_OK) { byte_buf_free(&receipt); byte_buf_free(&pbh);
                        byte_buf_free(&pfr); bn_free(pat); return rc; }
    next.state.pending_bundle_hash = pbh;
    next.state.pending_file_set_root = pfr;
    next.state.pending_announce_time = pat;

    rc = state_and_receipt_tx(&next, utxo, &receipt, now, opts, b);
    byte_buf_free(&receipt);
    byte_buf_free(&pbh);
    byte_buf_free(&pfr);
    bn_free(pat);
    return rc;
}

int build_arp_activate(const publisher_tea_t *c, const arp_utxo_t *utxo,
                       const uint8_t activate_digest[32],
                       int64_t now, const arp_builder_opts_t *opts,
                       tx_builder_t *b)
{
    if (!c || !utxo || !activate_digest || !b) return BNS_EINVAL;

    /* ACTIVATE receipt preimage (commits activateDigest at PRE-increment
     * releaseCount). */
    byte_buf_t receipt;
    byte_buf_init(&receipt);
    int rc = publisher_tea_activate_receipt(c, activate_digest, &receipt);
    if (rc != BNS_OK) { byte_buf_free(&receipt); return rc; }

    /* next state: pending cleared (ZERO), releaseCount++. */
    publisher_tea_t next = *c;
    byte_buf_t zbh, zfr;
    byte_buf_init(&zbh);
    byte_buf_init(&zfr);
    bn_t *zat = NULL, *rc1 = NULL, *new_rc = NULL;
    uint8_t zero32[32] = {0};
    rc = byte_buf_append(&zbh, zero32, 32);
    if (rc == BNS_OK) rc = byte_buf_append(&zfr, zero32, 32);
    if (rc == BNS_OK) rc = bn_parse_dec("0", &zat);
    if (rc == BNS_OK) rc = bn_parse_dec("1", &rc1);
    if (rc == BNS_OK) rc = bn_add(c->state.release_count, rc1, &new_rc);
    if (rc != BNS_OK) goto done;
    next.state.pending_bundle_hash = zbh;
    next.state.pending_file_set_root = zfr;
    next.state.pending_announce_time = zat;
    next.state.release_count = new_rc;

    rc = state_and_receipt_tx(&next, utxo, &receipt, now, opts, b);
done:
    byte_buf_free(&receipt);
    byte_buf_free(&zbh);
    byte_buf_free(&zfr);
    bn_free(zat);
    bn_free(rc1);
    bn_free(new_rc);
    return rc;
}

int build_arp_cancel(const publisher_tea_t *c, const arp_utxo_t *utxo,
                     int64_t now, const arp_builder_opts_t *opts,
                     tx_builder_t *b)
{
    if (!c || !utxo || !b) return BNS_EINVAL;

    /* CANCEL receipt preimage (commits current pendingBundleHash BEFORE clear). */
    byte_buf_t receipt;
    byte_buf_init(&receipt);
    int rc = publisher_tea_cancel_receipt(c, &receipt);
    if (rc != BNS_OK) { byte_buf_free(&receipt); return rc; }

    /* next state: pending cleared. */
    publisher_tea_t next = *c;
    byte_buf_t zbh, zfr;
    byte_buf_init(&zbh);
    byte_buf_init(&zfr);
    bn_t *zat = NULL;
    uint8_t zero32[32] = {0};
    rc = byte_buf_append(&zbh, zero32, 32);
    if (rc == BNS_OK) rc = byte_buf_append(&zfr, zero32, 32);
    if (rc == BNS_OK) rc = bn_parse_dec("0", &zat);
    if (rc != BNS_OK) { byte_buf_free(&receipt); byte_buf_free(&zbh);
                        byte_buf_free(&zfr); bn_free(zat); return rc; }
    next.state.pending_bundle_hash = zbh;
    next.state.pending_file_set_root = zfr;
    next.state.pending_announce_time = zat;

    rc = state_and_receipt_tx(&next, utxo, &receipt, now, opts, b);
    byte_buf_free(&receipt);
    byte_buf_free(&zbh);
    byte_buf_free(&zfr);
    bn_free(zat);
    return rc;
}

int build_arp_invalidate(const publisher_tea_t *c, const arp_utxo_t *utxo,
                         const uint8_t activate_digest[32],
                         int64_t now, const arp_builder_opts_t *opts,
                         tx_builder_t *b)
{
    if (!c || !utxo || !activate_digest || !b) return BNS_EINVAL;

    /* INVALIDATE receipt preimage (commits activateDigest). */
    byte_buf_t receipt;
    byte_buf_init(&receipt);
    int rc = publisher_tea_invalidate_receipt(c, activate_digest, &receipt);
    if (rc != BNS_OK) { byte_buf_free(&receipt); return rc; }

    /* next state: pending unchanged (recreate current state verbatim). */
    rc = state_and_receipt_tx(c, utxo, &receipt, now, opts, b);
    byte_buf_free(&receipt);
    return rc;
}

int build_arp_retire(const publisher_tea_t *c, const arp_utxo_t *utxo,
                     const arp_builder_opts_t *opts, tx_builder_t *b)
{
    if (!c || !utxo || !b) return BNS_EINVAL;
    if (c->params.publisher_key.len != 33) return BNS_EINVAL;

    /* input[0]: contract UTXO. */
    int rc = tx_builder_add_input(b, utxo->txid_display, utxo->vout, NULL, 0,
                                  0xffffffffu);
    if (rc != BNS_OK) return rc;

    uint64_t funding_total = 0;
    if (opts) {
        rc = add_funding(b, opts->funding, &funding_total);
        if (rc != BNS_OK) return rc;
    }

    /* output[0]: full balance payout to the publisher. */
    rc = append_p2pkh_pubkey(b, c->params.publisher_key.data, utxo->value);
    if (rc != BNS_OK) return rc;

    /* change(publisherAddress): seed with funding + utxo value. */
    if (opts && opts->has_change && opts->change_hash160) {
        rc = append_change(b, opts->change_hash160, funding_total + utxo->value);
        if (rc != BNS_OK) return rc;
    }
    return BNS_OK;
}

/* ---- AttestorTea builders ----------------------------------------------- */

int build_arp_attestor_slash(const attestor_tea_t *c, const arp_utxo_t *utxo,
                             const uint8_t reporter[33],
                             const arp_builder_opts_t *opts, tx_builder_t *b)
{
    if (!c || !utxo || !reporter || !b) return BNS_EINVAL;
    (void)c;

    uint64_t total = utxo->value;
    uint64_t bounty = total / 2;       /* INTEGER floor */
    uint64_t burn = total - bounty;    /* odd satoshi goes to burn */

    /* input[0]: contract UTXO. */
    int rc = tx_builder_add_input(b, utxo->txid_display, utxo->vout, NULL, 0,
                                  0xffffffffu);
    if (rc != BNS_OK) return rc;

    uint64_t funding_total = 0;
    if (opts) {
        rc = add_funding(b, opts->funding, &funding_total);
        if (rc != BNS_OK) return rc;
    }

    /* output[0]: P2PKH bounty to reporter. */
    rc = append_p2pkh_pubkey(b, reporter, bounty);
    if (rc != BNS_OK) return rc;

    /* output[1]: OP_RETURN 'SLASHED\0' carrying burn. */
    byte_buf_t op;
    byte_buf_init(&op);
    rc = build_opreturn_script(SLASHED_MARKER, sizeof(SLASHED_MARKER), &op);
    if (rc != BNS_OK) { byte_buf_free(&op); return rc; }
    rc = tx_builder_add_output(b, op.data, op.len, burn);
    byte_buf_free(&op);
    if (rc != BNS_OK) return rc;

    /* change(reporterAddress): seed with funding + utxo value. */
    if (opts && opts->has_change && opts->change_hash160) {
        rc = append_change(b, opts->change_hash160, funding_total + utxo->value);
        if (rc != BNS_OK) return rc;
    }
    return BNS_OK;
}

int build_arp_attestor_stake(const attestor_tea_t *c, const arp_utxo_t *utxo,
                             const bn_t *add_amount,
                             const arp_builder_opts_t *opts, tx_builder_t *b)
{
    if (!c || !utxo || !add_amount || !b) return BNS_EINVAL;

    /* newBalance = utxo.value + addAmount. */
    char dec[32];
    snprintf(dec, sizeof(dec), "%llu", (unsigned long long)utxo->value);
    bn_t *bal = NULL;
    int rc = bn_parse_dec(dec, &bal);
    if (rc != BNS_OK) return rc;
    bn_t *new_bal = NULL;
    rc = bn_add(bal, add_amount, &new_bal);
    bn_free(bal);
    if (rc != BNS_OK) return rc;
    byte_buf_t le;
    byte_buf_init(&le);
    rc = bn_to_le_bytes(new_bal, 8, &le);
    bn_free(new_bal);
    if (rc != BNS_OK) { byte_buf_free(&le); return rc; }
    uint64_t new_balance = 0;
    for (size_t i = 0; i < 8 && i < le.len; i++)
        new_balance |= (uint64_t)le.data[i] << (8 * i);
    byte_buf_free(&le);

    /* input[0]: contract UTXO. */
    rc = tx_builder_add_input(b, utxo->txid_display, utxo->vout, NULL, 0,
                              0xffffffffu);
    if (rc != BNS_OK) return rc;

    uint64_t funding_total = 0;
    if (opts) {
        rc = add_funding(b, opts->funding, &funding_total);
        if (rc != BNS_OK) return rc;
    }

    /* output[0]: recreated (stateless) contract at newBalance. */
    byte_buf_t script;
    byte_buf_init(&script);
    rc = attestor_tea_locking_script(c, &script);
    if (rc != BNS_OK) { byte_buf_free(&script); return rc; }
    rc = tx_builder_add_output(b, script.data, script.len, new_balance);
    byte_buf_free(&script);
    if (rc != BNS_OK) return rc;

    /* change: seed with funding + utxo value. */
    if (opts && opts->has_change && opts->change_hash160) {
        rc = append_change(b, opts->change_hash160, funding_total + utxo->value);
        if (rc != BNS_OK) return rc;
    }
    return BNS_OK;
}

int build_arp_attestor_withdraw(const attestor_tea_t *c, const arp_utxo_t *utxo,
                                int64_t lock_time,
                                const arp_builder_opts_t *opts, tx_builder_t *b)
{
    if (!c || !utxo || !b) return BNS_EINVAL;
    if (c->params.operator_pubkey.len != 33) return BNS_EINVAL;

    /* input[0]: contract UTXO, sequence < 0xffffffff to enable nLocktime. */
    int rc = tx_builder_add_input(b, utxo->txid_display, utxo->vout, NULL, 0, 0u);
    if (rc != BNS_OK) return rc;

    uint64_t funding_total = 0;
    if (opts) {
        rc = add_funding(b, opts->funding, &funding_total);
        if (rc != BNS_OK) return rc;
    }

    /* output[0]: full balance payout to the operator. */
    rc = append_p2pkh_pubkey(b, c->params.operator_pubkey.data, utxo->value);
    if (rc != BNS_OK) return rc;

    /* change(operatorAddress): seed with funding + utxo value. */
    if (opts && opts->has_change && opts->change_hash160) {
        rc = append_change(b, opts->change_hash160, funding_total + utxo->value);
        if (rc != BNS_OK) return rc;
    }

    tx_builder_set_locktime(b, (uint32_t)lock_time);
    return BNS_OK;
}
