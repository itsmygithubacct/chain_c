/*
 * identity_chain_view.h — the minimal on-chain read the KeyBroker needs to bind
 * a key to a real deployed identity: fetch the locking-script hex of an output
 * of the genesis tx, plus a fail-closed verify-on-read helper that byte-compares
 * the on-chain locking script to a caller-reconstructed expected script.
 *
 * TS origin: src/broker/identityChainView.ts (IdentityChainView,
 * ChainSourceIdentityView, verifyIdentityScriptOnChain).
 *
 * PINS (module notes):
 *  - getIdentityScriptHex returns the scriptPubKey BODY hex (NO CompactSize
 *    length prefix) of outputs[vout], lowercase. Missing output => error.
 *  - verify is STRICTLY FAIL-CLOSED and TOTAL (never throws/longjmp): every
 *    error path returns ok=false with a reason string; comparison lowercases
 *    BOTH sides (the caller-supplied expected hex may be mixed case).
 *  - reason strings are user-visible/logged; reproduced verbatim below.
 */
#ifndef BONSAI_BROKER_IDENTITY_CHAIN_VIEW_H
#define BONSAI_BROKER_IDENTITY_CHAIN_VIEW_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "reputation_indexer.h"   /* chain_source_t */

/* The verify-on-read fail-closed reason strings (verbatim from the TS). */
#define BONSAI_IDVIEW_REASON_MISMATCH \
    "on-chain locking script does not match the expected script " \
    "(charter/param mismatch)"
/* The chain-unreachable reason is a prefix; the impl appends the error message:
 *   "chain unreachable (fail-closed): <err.message>". */
#define BONSAI_IDVIEW_REASON_UNREACHABLE_PREFIX \
    "chain unreachable (fail-closed): "

/* IdentityChainView abstraction: returns the locking-script hex of output
 * `vout` of the genesis tx. A vtable so the broker can be tested with a stub.
 * TS: identityChainView.ts::IdentityChainView. */
typedef struct identity_chain_view_s identity_chain_view_t;
struct identity_chain_view_s {
    void *ctx; /* implementation-private state (e.g. a ChainSourceIdentityView) */

    /* getIdentityScriptHex(genesisTxid, vout): writes the lowercase script-body
     * hex (no length prefix) of outputs[vout] to *out_hex (freshly malloc'd,
     * caller frees). Errors if the output index is absent.
     * BNS_OK / BNS_ENET / BNS_ENOTFOUND / BNS_EPARSE / BNS_ENOMEM.
     * TS: IdentityChainView.getIdentityScriptHex. */
    int (*get_identity_script_hex)(void *ctx, const char *genesis_txid,
                                   uint32_t vout, char **out_hex);
};

/* ChainSourceIdentityView: an IdentityChainView backed by a chain_source_t.
 * getIdentityScriptHex = getRawTx(genesisTxid) -> deserialize ->
 * hex(outputs[vout].scriptPubKey body). `source` is borrowed (must outlive it).
 * TS: identityChainView.ts::ChainSourceIdentityView. */
typedef struct chain_source_identity_view_s chain_source_identity_view_t;

/* Construct a ChainSourceIdentityView over a borrowed chain_source_t. *out freed
 * via chain_source_identity_view_free. TS: new ChainSourceIdentityView(source).
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int chain_source_identity_view_new(const chain_source_t *source,
                                   chain_source_identity_view_t **out);

/* Release a ChainSourceIdentityView (NULL-safe; does not free the source). */
void chain_source_identity_view_free(chain_source_identity_view_t *v);

/* Populate an identity_chain_view_t vtable backed by `v` (so the broker can
 * consume it). `out_vtable->ctx` borrows `v`. BNS_OK / BNS_EINVAL. */
int chain_source_identity_view_as_view(chain_source_identity_view_t *v,
                                       identity_chain_view_t *out_vtable);

/* Fail-closed binding check (NEVER fails the process — always returns BNS_OK and
 * sets *out_ok): fetches on-chain script via `view`, lowercases BOTH it and
 * `expected_locking_script_hex`, and compares. On equality *out_ok=true and (if
 * `reason`/`reason_sz` given) reason[0]='\0'. On chain error or mismatch
 * *out_ok=false and the verbatim reason is copied into `reason` (truncated to
 * `reason_sz`-1 + NUL; pass NULL/0 to skip). `identity_id` is the genesis txid.
 * TS: identityChainView.ts::verifyIdentityScriptOnChain. Always BNS_OK. */
int verify_identity_script_on_chain(const identity_chain_view_t *view,
                                    const char *identity_id, uint32_t vout,
                                    const char *expected_locking_script_hex,
                                    bool *out_ok,
                                    char *reason, size_t reason_sz);

#endif /* BONSAI_BROKER_IDENTITY_CHAIN_VIEW_H */
