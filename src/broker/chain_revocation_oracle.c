/*
 * chain_revocation_oracle.c — port of src/broker/chainRevocationOracle.ts.
 *
 * Forward-walks the spend chain of an identity's output (default 0) from genesis.
 * REVOKED iff a terminal spend (revoke/slash: P2PKH at output 0, or no outputs)
 * is observed; else LIVE. Caches REVOKED permanently and resumes LIVE walks from
 * the last seen tip. Fail-closed: chain/hop errors propagate as non-BNS_OK.
 *
 * isTerminalSpend mirrors reputation_indexer.h::is_terminal_identity_spend, which
 * tx_parse.h exposes as is_terminal_spend (output[0] P2PKH or zero outputs).
 */
#include "broker/chain_revocation_oracle.h"

#include <stdlib.h>
#include <string.h>

#include "chain/tx_parse.h"

/* A genesis -> tip mapping (the liveTip Map). */
typedef struct {
    char *genesis; /* owned 64-hex genesis txid */
    char *tip;     /* owned current tip txid    */
} live_tip_entry_t;

struct chain_revocation_oracle_s {
    const chain_source_t *source; /* borrowed */
    uint32_t identity_vout;
    size_t   max_hops;

    /* Permanently revoked identities (a Set<string> of genesis txids). */
    char  **revoked;
    size_t  revoked_count;
    size_t  revoked_cap;

    /* Last known live tip per identity (Map<genesisTxid, tipTxid>). */
    live_tip_entry_t *live_tips;
    size_t            live_tip_count;
    size_t            live_tip_cap;
};

/* ---- revoked-set helpers ------------------------------------------------- */

static bool revoked_has(const chain_revocation_oracle_t *o, const char *genesis)
{
    for (size_t i = 0; i < o->revoked_count; i++) {
        if (strcmp(o->revoked[i], genesis) == 0) return true;
    }
    return false;
}

static int revoked_add(chain_revocation_oracle_t *o, const char *genesis)
{
    if (revoked_has(o, genesis)) return BNS_OK;
    if (o->revoked_count == o->revoked_cap) {
        size_t ncap = o->revoked_cap ? o->revoked_cap * 2 : 4;
        char **n = realloc(o->revoked, ncap * sizeof(*n));
        if (!n) return BNS_ENOMEM;
        o->revoked = n;
        o->revoked_cap = ncap;
    }
    char *dup = strdup(genesis);
    if (!dup) return BNS_ENOMEM;
    o->revoked[o->revoked_count++] = dup;
    return BNS_OK;
}

/* ---- liveTip-map helpers ------------------------------------------------- */

static live_tip_entry_t *live_tip_find(chain_revocation_oracle_t *o,
                                       const char *genesis)
{
    for (size_t i = 0; i < o->live_tip_count; i++) {
        if (strcmp(o->live_tips[i].genesis, genesis) == 0) {
            return &o->live_tips[i];
        }
    }
    return NULL;
}

/* liveTip.set(genesis, tip): upsert. */
static int live_tip_set(chain_revocation_oracle_t *o, const char *genesis,
                        const char *tip)
{
    live_tip_entry_t *e = live_tip_find(o, genesis);
    if (e) {
        char *ntip = strdup(tip);
        if (!ntip) return BNS_ENOMEM;
        free(e->tip);
        e->tip = ntip;
        return BNS_OK;
    }
    if (o->live_tip_count == o->live_tip_cap) {
        size_t ncap = o->live_tip_cap ? o->live_tip_cap * 2 : 4;
        live_tip_entry_t *n = realloc(o->live_tips, ncap * sizeof(*n));
        if (!n) return BNS_ENOMEM;
        o->live_tips = n;
        o->live_tip_cap = ncap;
    }
    char *g = strdup(genesis);
    char *t = strdup(tip);
    if (!g || !t) { free(g); free(t); return BNS_ENOMEM; }
    o->live_tips[o->live_tip_count].genesis = g;
    o->live_tips[o->live_tip_count].tip = t;
    o->live_tip_count++;
    return BNS_OK;
}

/* liveTip.delete(genesis). */
static void live_tip_delete(chain_revocation_oracle_t *o, const char *genesis)
{
    for (size_t i = 0; i < o->live_tip_count; i++) {
        if (strcmp(o->live_tips[i].genesis, genesis) == 0) {
            free(o->live_tips[i].genesis);
            free(o->live_tips[i].tip);
            o->live_tips[i] = o->live_tips[o->live_tip_count - 1];
            o->live_tip_count--;
            return;
        }
    }
}

/* ---- lifecycle ----------------------------------------------------------- */

int chain_revocation_oracle_new(const chain_source_t *source,
                                const chain_revocation_oracle_opts_t *opts,
                                chain_revocation_oracle_t **out)
{
    if (out) *out = NULL;
    if (!source || !out) return BNS_EINVAL;
    /* TS: requires source.getSpendingTxid (a spend index). */
    if (!source->get_spending_txid || !source->get_raw_tx) return BNS_EINVAL;

    chain_revocation_oracle_t *o = calloc(1, sizeof(*o));
    if (!o) return BNS_ENOMEM;

    o->source = source;
    o->identity_vout = (opts && opts->has_identity_vout)
                           ? opts->identity_vout
                           : BONSAI_REVOCATION_DEFAULT_VOUT;
    o->max_hops = (opts && opts->has_max_hops)
                      ? opts->max_hops
                      : BONSAI_REVOCATION_DEFAULT_MAX_HOPS;

    *out = o;
    return BNS_OK;
}

void chain_revocation_oracle_free(chain_revocation_oracle_t *o)
{
    if (!o) return;
    for (size_t i = 0; i < o->revoked_count; i++) free(o->revoked[i]);
    free(o->revoked);
    for (size_t i = 0; i < o->live_tip_count; i++) {
        free(o->live_tips[i].genesis);
        free(o->live_tips[i].tip);
    }
    free(o->live_tips);
    free(o);
}

/* ---- the walk ------------------------------------------------------------ */

int chain_revocation_oracle_is_revoked(chain_revocation_oracle_t *o,
                                       const char *genesis_txid,
                                       bool *out_revoked)
{
    if (out_revoked) *out_revoked = false;
    if (!o || !genesis_txid || !out_revoked) return BNS_EINVAL;

    /* revoked-cache hit => true (no chain call). */
    if (revoked_has(o, genesis_txid)) { *out_revoked = true; return BNS_OK; }

    const chain_source_t *src = o->source;
    const uint32_t vout = o->identity_vout;
    const size_t max_hops = o->max_hops;

    /* Resume from the last live tip if walked before; else start at genesis.
     * `txid` is owned within the loop so we can free intermediates safely. */
    live_tip_entry_t *resume = live_tip_find(o, genesis_txid);
    char *txid = strdup(resume ? resume->tip : genesis_txid);
    if (!txid) return BNS_ENOMEM;

    int rc = BNS_OK;
    bool revoked = false;
    bool decided = false;

    for (size_t hops = 0; hops < max_hops; hops++) {
        char *spender = NULL;
        rc = src->get_spending_txid(src->ctx, txid, vout, &spender);
        if (rc != BNS_OK) { free(spender); goto done; }

        if (spender == NULL) {
            /* Identity output unspent => live at this tip. */
            rc = live_tip_set(o, genesis_txid, txid);
            revoked = false;
            decided = true;
            goto done;
        }

        char *raw = NULL;
        rc = src->get_raw_tx(src->ctx, spender, &raw);
        if (rc != BNS_OK) { free(raw); free(spender); goto done; }
        if (!raw) { free(spender); rc = BNS_ENET; goto done; }

        bool terminal = is_terminal_spend(raw);
        free(raw);

        if (terminal) {
            rc = revoked_add(o, genesis_txid);
            if (rc == BNS_OK) live_tip_delete(o, genesis_txid);
            free(spender);
            revoked = true;
            decided = true;
            goto done;
        }

        /* State recreated at output 0 — the identity continues there. */
        free(txid);
        txid = spender; /* take ownership of the malloc'd spender txid */
    }

    /* Loop exhausted: TS throws 'exceeded N hops'. */
    rc = BNS_EHOPLIMIT;

done:
    free(txid);
    if (rc != BNS_OK) return rc;
    if (decided) *out_revoked = revoked;
    return BNS_OK;
}

/* ---- vtable adapter ------------------------------------------------------ */

static int oracle_is_revoked(void *ctx, const char *identity_id,
                             bool *out_revoked)
{
    return chain_revocation_oracle_is_revoked(
        (chain_revocation_oracle_t *)ctx, identity_id, out_revoked);
}

int chain_revocation_oracle_as_oracle(chain_revocation_oracle_t *o,
                                      revocation_oracle_t *out_vtable)
{
    if (!o || !out_vtable) return BNS_EINVAL;
    out_vtable->ctx = o;
    out_vtable->is_revoked = oracle_is_revoked;
    return BNS_OK;
}
