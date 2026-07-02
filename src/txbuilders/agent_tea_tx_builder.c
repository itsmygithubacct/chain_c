/*
 * txbuilders/agent_tea_tx_builder.c — unsigned-tx builders for AgentTea
 * (executeAction, stake, slashValidator, recover, revoke).
 *
 * Port of src/agentTeaTxBuilder.ts. Mirrors the RicardianTea builders adapted to
 * AgentTea shapes: actions carry NO settlement output (metered), stake raises the
 * identity value, slashValidator burn-splits collateral 50/50, recover rotates
 * the agent key and emits a recovery receipt. Each reproduces the on-chain
 * hashOutputs-pinned layout; receipts are single sha256, recomputed identically.
 */
#include "txbuilders/agent_tea_tx_builder.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "crypto/hash.h"
#include "bsv/tx_change.h"
#include "bsv/script_utils.h"
#include "bsv/num2bin.h"
#include "common/hex.h"

/* 'SLASHED\0' burn data (8 bytes ending NUL). TS: '534c415348454400'. */
static const uint8_t SLASHED_MARKER[8] = {
    0x53, 0x4c, 0x41, 0x53, 0x48, 0x45, 0x44, 0x00 };

/* 'AGNT_RECOVER_V1' domain tag for the recovery receipt. TS:
 * '41474e545f5245434f5645525f5631'. */
static const uint8_t RECOVER_TAG[] = {
    0x41, 0x47, 0x4e, 0x54, 0x5f, 0x52, 0x45, 0x43, 0x4f,
    0x56, 0x45, 0x52, 0x5f, 0x56, 0x31 };

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
                         uint64_t total_in, uint64_t fee_per_kb)
{
    byte_buf_t script;
    byte_buf_init(&script);
    int rc = build_p2pkh_script(change_hash160, &script);
    if (rc != BNS_OK) { byte_buf_free(&script); return rc; }
    rc = tx_builder_add_output(b, script.data, script.len, total_in);
    byte_buf_free(&script);
    if (rc != BNS_OK) return rc;
    size_t change_index = b->tx.num_outputs - 1;
    return update_change_output(&b->tx, change_index, fee_per_kb);
}

/* Apply an explicit fee override: change satoshis at change_index is reduced by
 * (fee - 0). bsv tx.fee(feeSats) recomputes change = available - feeSats. We
 * mirror that: outputs[change_index] was seeded with the full input total minus
 * the non-change outputs by append_change_seed; here we re-settle with an exact
 * fee instead of the estimator. */
static int append_change_fixed_fee(tx_builder_t *b,
                                    const uint8_t change_hash160[20],
                                    uint64_t total_in, uint64_t fee_sats)
{
    byte_buf_t script;
    byte_buf_init(&script);
    int rc = build_p2pkh_script(change_hash160, &script);
    if (rc != BNS_OK) { byte_buf_free(&script); return rc; }
    rc = tx_builder_add_output(b, script.data, script.len, total_in);
    byte_buf_free(&script);
    if (rc != BNS_OK) return rc;
    size_t ci = b->tx.num_outputs - 1;

    uint64_t out_sum = 0;
    for (size_t i = 0; i < b->tx.num_outputs; i++) {
        if (i == ci) continue;
        out_sum += b->tx.outputs[i].satoshis;
    }
    if (out_sum > total_in) return BNS_ERANGE;
    uint64_t available = total_in - out_sum;
    if (available < fee_sats) return BNS_ERANGE;
    uint64_t change_amount = available - fee_sats;
    if (change_amount >= 1u) {
        b->tx.outputs[ci].satoshis = change_amount;
        return BNS_OK;
    }
    /* dust: remove change output */
    byte_buf_free(&b->tx.outputs[ci].script);
    for (size_t i = ci; i + 1 < b->tx.num_outputs; i++)
        b->tx.outputs[i] = b->tx.outputs[i + 1];
    b->tx.num_outputs -= 1;
    return BNS_OK;
}

/* Append change honoring opts (fee_sats override or estimator). */
static int append_change_opts(tx_builder_t *b,
                              const agent_tea_builder_opts_t *opts,
                              uint64_t total_in)
{
    if (!opts || !opts->has_change || !opts->change_hash160) return BNS_OK;
    if (opts->has_fee_sats)
        return append_change_fixed_fee(b, opts->change_hash160, total_in,
                                       opts->fee_sats);
    return append_change(b, opts->change_hash160, total_in, BONSAI_FEE_PER_KB);
}

static int append_state_output(tx_builder_t *b, const agent_tea_t *c,
                               uint64_t balance)
{
    byte_buf_t script;
    byte_buf_init(&script);
    int rc = agent_tea_locking_script(c, false, &script);
    if (rc != BNS_OK) { byte_buf_free(&script); return rc; }
    rc = tx_builder_add_output(b, script.data, script.len, balance);
    byte_buf_free(&script);
    return rc;
}

static int append_opreturn_hash(tx_builder_t *b, const uint8_t hash[32])
{
    byte_buf_t op;
    byte_buf_init(&op);
    int rc = build_opreturn_script(hash, 32, &op);
    if (rc != BNS_OK) { byte_buf_free(&op); return rc; }
    rc = tx_builder_add_output(b, op.data, op.len, 0);
    byte_buf_free(&op);
    return rc;
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

/* ---- executeAction ------------------------------------------------------ */

int build_agent_tea_action(const agent_tea_t *c,
                           const agent_tea_utxo_t *identity,
                           const uint8_t counterparty[33],
                           const bn_t *amount,
                           const uint8_t action_hash[32],
                           const uint8_t provenance_hash[32],
                           int64_t now,
                           const agent_tea_builder_opts_t *opts,
                           tx_builder_t *b)
{
    if (!c || !identity || !counterparty || !amount || !action_hash ||
        !provenance_hash || !opts || !b)
        return BNS_EINVAL;

    char *receipt_hex = NULL;
    int rc = agent_tea_receipt_hash(c, counterparty, amount, action_hash,
                                    provenance_hash, now, &receipt_hex);
    if (rc != BNS_OK) return rc;
    uint8_t receipt_hash[32];
    rc = hex_decode_fixed(receipt_hex, receipt_hash, sizeof(receipt_hash));
    free(receipt_hex);
    if (rc != BNS_OK) return rc;

    /* input[0]: identity, sequence < 0xffffffff. */
    rc = tx_builder_add_input(b, identity->txid_display, identity->vout, NULL, 0,
                              0u);
    if (rc != BNS_OK) return rc;

    uint64_t funding_total = 0;
    rc = add_funding(b, opts->funding, &funding_total);
    if (rc != BNS_OK) return rc;

    /* output[0]: recreated identity carrying the POST-action (advanced) state — txCount+1,
     * spentInWindow/windowStart rolled, tier graduated — so the contract's hashOutputs check
     * passes. (append_state_output reads c->state, so swap the advanced state in for the build.) */
    {
        agent_tea_state_t next;
        rc = agent_tea_apply_action(c, amount, now, &next);
        if (rc != BNS_OK) return rc;
        agent_tea_t *mc = (agent_tea_t *)c;          /* swap, build, restore (state is restored immediately) */
        agent_tea_state_t saved = mc->state;
        mc->state = next;
        rc = append_state_output(b, c, identity->value);
        mc->state = saved;
        agent_tea_state_free(&next);
        if (rc != BNS_OK) return rc;
    }

    /* output[1]: OP_RETURN <receiptHash> (0 sat). No payment output (metered). */
    rc = append_opreturn_hash(b, receipt_hash);
    if (rc != BNS_OK) return rc;

    /* output[2]: change. Seed with BOTH spent inputs' value: funding_total plus
     * the recreated identity input value (output[0] re-emits it at identity->value,
     * so the identity value is reused, not spent to fees). Mirrors stake/slash/
     * revoke; seeding with funding_total alone under-funds change by identity->value
     * and burns it to fees. */
    rc = append_change_opts(b, opts, funding_total + identity->value);
    if (rc != BNS_OK) return rc;

    tx_builder_set_locktime(b, (uint32_t)now);
    return BNS_OK;
}

/* ---- stake -------------------------------------------------------------- */

int build_agent_tea_stake(const agent_tea_t *c,
                          const agent_tea_utxo_t *identity,
                          const bn_t *add_amount,
                          const agent_tea_builder_opts_t *opts,
                          tx_builder_t *b)
{
    if (!c || !identity || !add_amount || !opts || !b) return BNS_EINVAL;

    /* newBalance = identity.value + addAmount (int64 arithmetic). */
    char dec[32];
    snprintf(dec, sizeof(dec), "%llu", (unsigned long long)identity->value);
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

    /* input[0]: identity. */
    rc = tx_builder_add_input(b, identity->txid_display, identity->vout, NULL, 0,
                              0xffffffffu);
    if (rc != BNS_OK) return rc;

    uint64_t funding_total = 0;
    rc = add_funding(b, opts->funding, &funding_total);
    if (rc != BNS_OK) return rc;

    /* output[0]: recreated identity at newBalance. The collateral that raises
     * the value comes from the funding inputs, so the change path sees
     * funding_total - (newBalance - identity.value) available. We seed change
     * with funding_total; the extra collateral is consumed by output[0]'s value
     * exceeding the recreated identity input value. Account for the recreated
     * identity input value by adding it to the seed so the change math balances:
     * total available to change/fee = funding_total + identity.value (the input
     * value reused) - newBalance (output[0]) - ... handled by update_change. */
    rc = append_state_output(b, c, new_balance);
    if (rc != BNS_OK) return rc;

    /* change: seed with funding_total + identity.value (both inputs' value),
     * minus output[0] (newBalance) handled by update_change_output. */
    if (opts->has_change && opts->change_hash160) {
        uint64_t seed = funding_total + identity->value;
        if (opts->has_fee_sats)
            rc = append_change_fixed_fee(b, opts->change_hash160, seed,
                                         opts->fee_sats);
        else
            rc = append_change(b, opts->change_hash160, seed, BONSAI_FEE_PER_KB);
        if (rc != BNS_OK) return rc;
    }
    return BNS_OK;
}

/* ---- slashValidator ----------------------------------------------------- */

int build_agent_tea_slash_validator(const agent_tea_t *c,
                                    const agent_tea_utxo_t *identity,
                                    const uint8_t reporter[33],
                                    const agent_tea_builder_opts_t *opts,
                                    tx_builder_t *b)
{
    if (!c || !identity || !reporter || !opts || !b) return BNS_EINVAL;

    uint64_t total = identity->value;
    uint64_t bounty = total / 2;           /* INTEGER floor */
    uint64_t burn = total - bounty;        /* >= 50% */

    /* input[0]: identity. */
    int rc = tx_builder_add_input(b, identity->txid_display, identity->vout,
                                  NULL, 0, 0xffffffffu);
    if (rc != BNS_OK) return rc;

    uint64_t funding_total = 0;
    rc = add_funding(b, opts->funding, &funding_total);
    if (rc != BNS_OK) return rc;

    /* output[0]: P2PKH bounty to reporter. */
    rc = append_p2pkh_pubkey(b, reporter, bounty);
    if (rc != BNS_OK) return rc;

    /* output[1]: OP_RETURN 'SLASHED\0' carrying burn satoshis. */
    byte_buf_t op;
    byte_buf_init(&op);
    rc = build_opreturn_script(SLASHED_MARKER, sizeof(SLASHED_MARKER), &op);
    if (rc != BNS_OK) { byte_buf_free(&op); return rc; }
    rc = tx_builder_add_output(b, op.data, op.len, burn);
    byte_buf_free(&op);
    if (rc != BNS_OK) return rc;

    /* change(reporterAddress): seed with funding + identity value; the
     * bounty+burn already consume the identity value, change absorbs the fee. */
    if (opts->has_change && opts->change_hash160) {
        uint64_t seed = funding_total + identity->value;
        if (opts->has_fee_sats)
            rc = append_change_fixed_fee(b, opts->change_hash160, seed,
                                         opts->fee_sats);
        else
            rc = append_change(b, opts->change_hash160, seed, BONSAI_FEE_PER_KB);
        if (rc != BNS_OK) return rc;
    }
    return BNS_OK;
}

/* ---- recover ------------------------------------------------------------ */

int build_agent_tea_recover(const agent_tea_t *c,
                            const agent_tea_utxo_t *identity,
                            const uint8_t new_agent[33],
                            const agent_tea_builder_opts_t *opts,
                            tx_builder_t *b)
{
    if (!c || !identity || !new_agent || !opts || !b) return BNS_EINVAL;

    /* recovery receipt = sha256( AGNT_RECOVER_V1 || ricardianHash(32) ||
     *   newAgent(33) || int2ByteString(recoveryCount,8) ||
     *   int2ByteString(txCount,8) ), recoveryCount/txCount at CURRENT value. */
    if (c->params.ricardian_hash.len != 32) return BNS_EINVAL;
    byte_buf_t pre;
    byte_buf_init(&pre);
    int rc = byte_buf_append(&pre, RECOVER_TAG, sizeof(RECOVER_TAG));
    if (rc == BNS_OK) rc = byte_buf_append(&pre, c->params.ricardian_hash.data, 32);
    if (rc == BNS_OK) rc = byte_buf_append(&pre, new_agent, 33);
    if (rc == BNS_OK) rc = int2bytestring_sized(c->state.recovery_count, 8, &pre);
    if (rc == BNS_OK) rc = int2bytestring_sized(c->state.tx_count, 8, &pre);
    if (rc != BNS_OK) { byte_buf_free(&pre); return rc; }
    uint8_t receipt_hash[32];
    sha256(pre.data, pre.len, receipt_hash);
    byte_buf_free(&pre);

    /* input[0]: identity. */
    rc = tx_builder_add_input(b, identity->txid_display, identity->vout, NULL, 0,
                              0xffffffffu);
    if (rc != BNS_OK) return rc;

    uint64_t funding_total = 0;
    rc = add_funding(b, opts->funding, &funding_total);
    if (rc != BNS_OK) return rc;

    /* output[0]: recreated identity carrying the ROTATED agent key, constant
     * balance. CRITICAL: the agent appears TWICE in the locking script — ctor[1]
     * (the genesis agent, frozen in the immutable code part) and state[0] (the
     * @state copy). The contract's recover() sets only `this.agent` (= state[0])
     * and freezes the code part, so we must rotate ONLY state[0] and keep ctor[1]
     * at the genesis value (c->params.agent). Rotating both — as a naive full
     * rebuild does — corrupts ctor[1] and fails the hashOutputs assertion. tmp is
     * a shallow copy of *c; we override only state.recovery_count and pass the new
     * agent as the state[0] override to agent_tea_locking_script_ex. */
    agent_tea_t tmp = *c;
    byte_buf_t rotated;
    byte_buf_init(&rotated);
    rc = byte_buf_append(&rotated, new_agent, 33);
    if (rc != BNS_OK) { byte_buf_free(&rotated); return rc; }

    /* recoveryCount is incremented AFTER the sig check, so the on-chain post-state
     * commits recoveryCount+1 (the anti-replay nonce). The receipt above binds the
     * CURRENT count (what the recovery quorum signed); output[0] carries count+1.
     * (Same bignum pattern as agent_tea_apply_action.) */
    bn_t *one = NULL, *next_rc = NULL;
    rc = bn_parse_dec("1", &one);
    if (rc == BNS_OK) rc = bn_add(c->state.recovery_count, one, &next_rc);
    bn_free(one);
    if (rc != BNS_OK) { byte_buf_free(&rotated); return rc; }
    tmp.state.recovery_count = next_rc;   /* shallow copy: only this field is freed below */

    {
        byte_buf_t script;
        byte_buf_init(&script);
        rc = agent_tea_locking_script_ex(&tmp, false, &rotated, &script);  /* state[0]=newAgent, ctor[1]=genesis */
        if (rc == BNS_OK)
            rc = tx_builder_add_output(b, script.data, script.len, identity->value);
        byte_buf_free(&script);
    }
    bn_free(next_rc);
    byte_buf_free(&rotated);
    if (rc != BNS_OK) return rc;

    /* output[1]: OP_RETURN <recovery receiptHash> (0 sat). */
    rc = append_opreturn_hash(b, receipt_hash);
    if (rc != BNS_OK) return rc;

    /* change. Seed with both spent inputs' value (funding_total + the recreated
     * identity value re-emitted in output[0]); funding_total alone under-funds
     * change by identity->value. Mirrors stake/slash/revoke. */
    rc = append_change_opts(b, opts, funding_total + identity->value);
    if (rc != BNS_OK) return rc;
    return BNS_OK;
}

/* ---- revoke ------------------------------------------------------------- */

int build_agent_tea_revoke(const agent_tea_t *c,
                           const agent_tea_utxo_t *identity,
                           const agent_tea_builder_opts_t *opts,
                           tx_builder_t *b)
{
    if (!c || !identity || !opts || !b) return BNS_EINVAL;
    if (c->params.owner.len != 33) return BNS_EINVAL;

    /* input[0]: identity. */
    int rc = tx_builder_add_input(b, identity->txid_display, identity->vout,
                                  NULL, 0, 0xffffffffu);
    if (rc != BNS_OK) return rc;

    uint64_t funding_total = 0;
    rc = add_funding(b, opts->funding, &funding_total);
    if (rc != BNS_OK) return rc;

    /* output[0]: full identity balance to owner (Elder). */
    rc = append_p2pkh_pubkey(b, c->params.owner.data, identity->value);
    if (rc != BNS_OK) return rc;

    /* change(ownerAddress): seed with funding + identity value. */
    if (opts->has_change && opts->change_hash160) {
        uint64_t seed = funding_total + identity->value;
        if (opts->has_fee_sats)
            rc = append_change_fixed_fee(b, opts->change_hash160, seed,
                                         opts->fee_sats);
        else
            rc = append_change(b, opts->change_hash160, seed, BONSAI_FEE_PER_KB);
        if (rc != BNS_OK) return rc;
    }
    return BNS_OK;
}
