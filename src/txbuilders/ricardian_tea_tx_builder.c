/*
 * txbuilders/ricardian_tea_tx_builder.c — unsigned-tx builders bound to the
 * RicardianTea spending methods (executeTea, revoke, slash, updateSlashCheckpoint).
 *
 * Port of src/ricardianTeaTxBuilder.ts. Each builder reproduces the exact
 * input/output layout the contract's assert(hashOutputs == hash256(outputs))
 * pins. The TEA receipt hash at output[2] is recomputed identically to the
 * contract via ricardian_tea_receipt_hash (single sha256). The recreated
 * identity at output[0] carries the post-spend state via
 * ricardian_tea_locking_script with is_genesis=FALSE (golden).
 */
#include "txbuilders/ricardian_tea_tx_builder.h"

#include <string.h>
#include <stdlib.h>

#include "crypto/hash.h"
#include "bsv/tx_change.h"
#include "bsv/script_utils.h"
#include "common/hex.h"

/* ---- shared helpers ----------------------------------------------------- */

/* Convert a non-negative bn_t to a uint64 satoshi value (8-byte LE truncation
 * matching scrypt-ts Number(amount) into the output value field). */
static int bn_to_u64(const bn_t *n, uint64_t *out)
{
    byte_buf_t le;
    byte_buf_init(&le);
    int rc = bn_to_le_bytes(n, 8, &le);
    if (rc != BNS_OK) { byte_buf_free(&le); return rc; }
    uint64_t v = 0;
    for (size_t i = 0; i < 8 && i < le.len; i++)
        v |= (uint64_t)le.data[i] << (8 * i);
    byte_buf_free(&le);
    *out = v;
    return BNS_OK;
}

/* Decode a 64-char display txid hex string. (We re-use it directly as the
 * builder accepts the display txid.) */

/* Append the funding UTXOs as inputs[1..] with default sequence 0xffffffff and
 * accumulate their total satoshi value into *total_in. */
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

/* Append a change output back to change_hash160 seeded with the full input
 * total, then settle it via update_change_output. Returns BNS_OK even if the
 * change is dust (the output is then removed). */
static int append_change(tx_builder_t *b, const uint8_t change_hash160[20],
                         uint64_t total_in, uint64_t fee_per_kb)
{
    byte_buf_t script;
    byte_buf_init(&script);
    int rc = build_p2pkh_script(change_hash160, &script);
    if (rc != BNS_OK) { byte_buf_free(&script); return rc; }
    /* seed change satoshis with the full input total (the C change contract). */
    rc = tx_builder_add_output(b, script.data, script.len, total_in);
    byte_buf_free(&script);
    if (rc != BNS_OK) return rc;
    size_t change_index = b->tx.num_outputs - 1;
    return update_change_output(&b->tx, change_index, fee_per_kb);
}

/* Append output[0]: the recreated identity carrying the post-spend state at the
 * constant identity balance. `c` already holds the post-spend state. */
static int append_state_output(tx_builder_t *b, const ricardian_tea_t *c,
                               uint64_t balance)
{
    byte_buf_t script;
    byte_buf_init(&script);
    int rc = ricardian_tea_locking_script(c, false, &script);
    if (rc != BNS_OK) { byte_buf_free(&script); return rc; }
    rc = tx_builder_add_output(b, script.data, script.len, balance);
    byte_buf_free(&script);
    return rc;
}

/* hash160(33-byte compressed pubkey) -> P2PKH output. */
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

/* ---- executeTea --------------------------------------------------------- */

int build_ricardian_tea_execute(const ricardian_tea_t *c,
                                const ricardian_tea_utxo_t *identity,
                                const uint8_t counterparty[33],
                                const bn_t *amount,
                                const uint8_t invoice_hash[32],
                                const uint8_t provenance_hash[32],
                                int64_t now,
                                const ricardian_tea_builder_opts_t *opts,
                                tx_builder_t *b)
{
    if (!c || !identity || !counterparty || !amount || !invoice_hash ||
        !provenance_hash || !opts || !b)
        return BNS_EINVAL;

    uint64_t fee_per_kb = opts->fee_per_kb ? opts->fee_per_kb : BONSAI_FEE_PER_KB;

    /* Recompute the TEA receipt hash identically to the contract (uses the
     * PRE-spend txCount carried in c->state). */
    char *receipt_hex = NULL;
    int rc = ricardian_tea_receipt_hash(c, counterparty, amount, invoice_hash,
                                        provenance_hash, now, &receipt_hex);
    if (rc != BNS_OK) return rc;
    uint8_t receipt_hash[32];
    rc = hex_decode_fixed(receipt_hex, receipt_hash, sizeof(receipt_hash));
    free(receipt_hex);
    if (rc != BNS_OK) return rc;

    uint64_t amount_sats;
    rc = bn_to_u64(amount, &amount_sats);
    if (rc != BNS_OK) return rc;

    /* input[0]: identity UTXO, sequence < 0xffffffff to enable nLocktime. */
    rc = tx_builder_add_input(b, identity->txid_display, identity->vout, NULL, 0,
                              0u);
    if (rc != BNS_OK) return rc;

    /* input[1..]: agent funding. */
    uint64_t funding_total = 0;
    rc = add_funding(b, opts->funding, &funding_total);
    if (rc != BNS_OK) return rc;

    /* output[0]: recreated identity carrying the POST-spend (advanced) state — txCount+1,
     * spentInWindow/windowStart rolled, tier graduated — so the contract's hashOutputs assert over
     * the advanced state passes. (append_state_output reads c->state, so swap the advanced state in
     * for the build, then restore.) The receipt hash above intentionally used the PRE-spend
     * c->state.tx_count (the contract reads this.txCount before incrementing). Without this advance
     * every executeTea spend is unminable — exactly what the sibling agent_tea builder avoids. */
    {
        ricardian_tea_state_t next;
        rc = ricardian_tea_apply_action(c, amount, now, &next);
        if (rc != BNS_OK) return rc;
        ricardian_tea_t *mc = (ricardian_tea_t *)c;     /* swap, build, restore (state restored immediately) */
        ricardian_tea_state_t saved = mc->state;
        mc->state = next;
        rc = append_state_output(b, c, identity->value);
        mc->state = saved;
        ricardian_tea_state_free(&next);
        if (rc != BNS_OK) return rc;
    }

    /* output[1]: P2PKH payment of `amount` to the counterparty. */
    rc = append_p2pkh_pubkey(b, counterparty, amount_sats);
    if (rc != BNS_OK) return rc;

    /* output[2]: OP_RETURN <receiptHash> (0 sat). */
    byte_buf_t op;
    byte_buf_init(&op);
    rc = build_opreturn_script(receipt_hash, sizeof(receipt_hash), &op);
    if (rc != BNS_OK) { byte_buf_free(&op); return rc; }
    rc = tx_builder_add_output(b, op.data, op.len, 0);
    byte_buf_free(&op);
    if (rc != BNS_OK) return rc;

    /* output[3]: change (if requested and non-dust). Seed change with the FULL
     * input total = funding_total + identity->value (both spent inputs): input[0]
     * is the identity UTXO worth identity->value and input[1..] is funding_total.
     * update_change_output then subtracts every non-change output — including
     * output[0], which recreates identity->value 1:1 — so the net change settles
     * to funding_total - amount - fee. Seeding with funding_total alone omits the
     * recreated-input term and under-funds change by identity->value (BNS_ERANGE
     * when funding < identity->value, else the staked collateral is burned to the
     * miner as fee). Mirrors build_agent_tea_* and bsv.Transaction.change() in
     * ricardianTeaTxBuilder.ts, which sum ALL inputs. */
    if (opts->has_change && opts->change_hash160) {
        rc = append_change(b, opts->change_hash160, funding_total + identity->value, fee_per_kb);
        if (rc != BNS_OK) return rc;
    }

    tx_builder_set_locktime(b, (uint32_t)now);
    /* input[0].sequence is already 0 (set above). */
    return BNS_OK;
}

/* ---- revoke ------------------------------------------------------------- */

/* Full-balance P2PKH payout to a 33-byte pubkey, optional fee funding + change.
 * Shared by revoke/slash (and reused conceptually by agent revoke/slash). */
static int build_payout_to_pubkey(const ricardian_tea_utxo_t *identity,
                                  const uint8_t payee_pubkey[33],
                                  const ricardian_tea_builder_opts_t *opts,
                                  tx_builder_t *b)
{
    uint64_t fee_per_kb = (opts && opts->fee_per_kb) ? opts->fee_per_kb
                                                     : BONSAI_FEE_PER_KB;

    /* input[0]: identity UTXO. */
    int rc = tx_builder_add_input(b, identity->txid_display, identity->vout,
                                  NULL, 0, 0xffffffffu);
    if (rc != BNS_OK) return rc;

    uint64_t funding_total = 0;
    if (opts) {
        rc = add_funding(b, opts->funding, &funding_total);
        if (rc != BNS_OK) return rc;
    }

    /* output[0]: full identity balance paid to the payee. */
    rc = append_p2pkh_pubkey(b, payee_pubkey, identity->value);
    if (rc != BNS_OK) return rc;

    /* change(payeeAddress): establishes the changeAmount context. */
    if (opts && opts->has_change && opts->change_hash160) {
        rc = append_change(b, opts->change_hash160, funding_total + identity->value, fee_per_kb);
        if (rc != BNS_OK) return rc;
    }
    return BNS_OK;
}

int build_ricardian_tea_revoke(const ricardian_tea_t *c,
                               const ricardian_tea_utxo_t *identity,
                               const ricardian_tea_builder_opts_t *opts,
                               tx_builder_t *b)
{
    if (!c || !identity || !b) return BNS_EINVAL;
    /* Owner is the Elder: pay the full balance back to owner. */
    if (c->params.owner.len != 33) return BNS_EINVAL;
    return build_payout_to_pubkey(identity, c->params.owner.data, opts, b);
}

/* ---- slash (SUPERSEDED — test parity only) ------------------------------ */

int build_ricardian_tea_slash(const ricardian_tea_t *c,
                              const ricardian_tea_utxo_t *identity,
                              const uint8_t reporter[33],
                              const ricardian_tea_builder_opts_t *opts,
                              tx_builder_t *b)
{
    if (!c || !identity || !reporter || !b) return BNS_EINVAL;
    return build_payout_to_pubkey(identity, reporter, opts, b);
}

/* ---- updateSlashCheckpoint ---------------------------------------------- */

int build_ricardian_tea_checkpoint(const ricardian_tea_t *c,
                                   const ricardian_tea_utxo_t *identity,
                                   const uint8_t new_checkpoint_hash[32],
                                   const ricardian_tea_builder_opts_t *opts,
                                   tx_builder_t *b)
{
    if (!c || !identity || !new_checkpoint_hash || !opts || !b)
        return BNS_EINVAL;

    uint64_t fee_per_kb = opts->fee_per_kb ? opts->fee_per_kb : BONSAI_FEE_PER_KB;

    /* The recreated identity carries the advanced slashCheckpointHash. Mutate a
     * working copy of the state hash on `c` is not allowed (const); instead the
     * caller is expected to have set c->state.slash_checkpoint_hash to the new
     * value before calling, OR we overwrite into a temporary. The header
     * documents `c` carries the state to recreate; the new hash is provided
     * explicitly, so build the script from a state that uses it. We do this by
     * temporarily swapping the slash_checkpoint_hash byte_buf into a local copy
     * of the instance (shallow — params/state pointers shared, only the 32-byte
     * checkpoint buffer overridden via a stack byte_buf). */
    ricardian_tea_t tmp = *c;
    byte_buf_t cp;
    byte_buf_init(&cp);
    int rc = byte_buf_append(&cp, new_checkpoint_hash, 32);
    if (rc != BNS_OK) { byte_buf_free(&cp); return rc; }
    tmp.state.slash_checkpoint_hash = cp;

    /* input[0]: identity UTXO. */
    rc = tx_builder_add_input(b, identity->txid_display, identity->vout, NULL, 0,
                              0xffffffffu);
    if (rc != BNS_OK) { byte_buf_free(&cp); return rc; }

    uint64_t funding_total = 0;
    rc = add_funding(b, opts->funding, &funding_total);
    if (rc != BNS_OK) { byte_buf_free(&cp); return rc; }

    /* output[0]: recreated identity at constant balance with new checkpoint. */
    rc = append_state_output(b, &tmp, identity->value);
    byte_buf_free(&cp);
    if (rc != BNS_OK) return rc;

    /* change(signer default address). */
    if (opts->has_change && opts->change_hash160) {
        rc = append_change(b, opts->change_hash160, funding_total + identity->value, fee_per_kb);
        if (rc != BNS_OK) return rc;
    }
    return BNS_OK;
}
