/*
 * identity_chain_view.c — port of src/broker/identityChainView.ts.
 *
 * ChainSourceIdentityView.getIdentityScriptHex = getRawTx(genesisTxid) ->
 * deserialize -> hex(outputs[vout].scriptPubKey body). verifyIdentityScriptOnChain
 * is fail-closed and total: never longjmps, always sets *out_ok.
 */
#include "broker/identity_chain_view.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "common/hex.h"
#include "bsv/tx.h"

/* ChainSourceIdentityView state: a borrowed chain_source_t. */
struct chain_source_identity_view_s {
    const chain_source_t *source; /* borrowed */
};

/* getIdentityScriptHex(genesisTxid, vout): the lowercase script-body hex (no
 * length prefix) of outputs[vout] of the genesis tx. TS: ChainSourceIdentityView
 * .getIdentityScriptHex. */
static int csiv_get_identity_script_hex(void *ctx, const char *genesis_txid,
                                        uint32_t vout, char **out_hex)
{
    if (out_hex) *out_hex = NULL;
    if (!ctx || !genesis_txid || !out_hex) return BNS_EINVAL;

    const chain_source_identity_view_t *v = ctx;
    const chain_source_t *source = v->source;
    if (!source || !source->get_raw_tx) return BNS_EINVAL;

    char *raw = NULL;
    int rc = source->get_raw_tx(source->ctx, genesis_txid, &raw);
    if (rc != BNS_OK) { free(raw); return rc; }
    if (!raw) return BNS_ENET;

    bsv_tx_t tx;
    tx_init(&tx);
    rc = tx_deserialize(raw, &tx);
    free(raw);
    if (rc != BNS_OK) { tx_free(&tx); return rc; }

    /* tx.outputs[vout] — missing output is an error (TS: `no output ${vout}`). */
    if (vout >= tx.num_outputs) { tx_free(&tx); return BNS_ENOTFOUND; }

    const byte_buf_t *script = &tx.outputs[vout].script;
    char *hex = hex_encode(script->data, script->len);
    tx_free(&tx);
    if (!hex) return BNS_ENOMEM;

    *out_hex = hex;
    return BNS_OK;
}

int chain_source_identity_view_new(const chain_source_t *source,
                                   chain_source_identity_view_t **out)
{
    if (out) *out = NULL;
    if (!source || !out) return BNS_EINVAL;
    if (!source->get_raw_tx) return BNS_EINVAL;

    chain_source_identity_view_t *v = calloc(1, sizeof(*v));
    if (!v) return BNS_ENOMEM;
    v->source = source;
    *out = v;
    return BNS_OK;
}

void chain_source_identity_view_free(chain_source_identity_view_t *v)
{
    free(v); /* does not free the borrowed source */
}

int chain_source_identity_view_as_view(chain_source_identity_view_t *v,
                                       identity_chain_view_t *out_vtable)
{
    if (!v || !out_vtable) return BNS_EINVAL;
    out_vtable->ctx = v;
    out_vtable->get_identity_script_hex = csiv_get_identity_script_hex;
    return BNS_OK;
}

/* Copy a NUL-terminated string into reason (truncated to reason_sz-1 + NUL).
 * No-op when reason is NULL or reason_sz is 0. */
static void copy_reason(char *reason, size_t reason_sz, const char *src)
{
    if (!reason || reason_sz == 0) return;
    size_t n = strlen(src);
    if (n >= reason_sz) n = reason_sz - 1;
    memcpy(reason, src, n);
    reason[n] = '\0';
}

int verify_identity_script_on_chain(const identity_chain_view_t *view,
                                    const char *identity_id, uint32_t vout,
                                    const char *expected_locking_script_hex,
                                    bool *out_ok,
                                    char *reason, size_t reason_sz)
{
    if (out_ok) *out_ok = false;
    if (reason && reason_sz) reason[0] = '\0';
    if (!out_ok) return BNS_OK; /* total: nothing more we can report */

    /* Defensive: a missing view/vtable is a chain-unreachable failure. */
    if (!view || !view->get_identity_script_hex || !identity_id ||
        !expected_locking_script_hex) {
        char buf[256];
        /* Mirror the TS try/catch wrapping any error from the read path. */
        snprintf(buf, sizeof(buf), "%sinvalid identity view",
                 BONSAI_IDVIEW_REASON_UNREACHABLE_PREFIX);
        copy_reason(reason, reason_sz, buf);
        *out_ok = false;
        return BNS_OK;
    }

    char *on_chain = NULL;
    int rc = view->get_identity_script_hex(view->ctx, identity_id, vout,
                                           &on_chain);
    if (rc != BNS_OK || !on_chain) {
        /* try/catch in TS: chain unreachable (fail-closed): <err.message>. */
        free(on_chain);
        char buf[256];
        const char *msg;
        switch (rc) {
        case BNS_ENOTFOUND: msg = "identity output not found"; break;
        case BNS_ENET:      msg = "chain read failed";         break;
        case BNS_EPARSE:    msg = "malformed transaction";     break;
        case BNS_ENOMEM:    msg = "out of memory";             break;
        case BNS_EINVAL:    msg = "invalid argument";          break;
        default:            msg = bns_err_name((bonsai_err_t)rc); break;
        }
        snprintf(buf, sizeof(buf), "%s%s",
                 BONSAI_IDVIEW_REASON_UNREACHABLE_PREFIX, msg);
        copy_reason(reason, reason_sz, buf);
        *out_ok = false;
        return BNS_OK;
    }

    /* onChain.toLowerCase() !== expected.toLowerCase() (case-insensitive). */
    bool equal = (strcasecmp(on_chain, expected_locking_script_hex) == 0);
    free(on_chain);

    if (!equal) {
        copy_reason(reason, reason_sz, BONSAI_IDVIEW_REASON_MISMATCH);
        *out_ok = false;
        return BNS_OK;
    }

    *out_ok = true;
    return BNS_OK;
}
