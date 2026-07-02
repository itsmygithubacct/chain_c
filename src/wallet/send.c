/*
 * wallet/send.c — wallet_fund_and_sign (see wallet/send.h).
 */
#include "wallet/send.h"

#include <string.h>

#include "chainSources/utxo_select.h"

int wallet_fund_and_sign(woc_client_t *woc, bsv_network_t net,
                         const ecdsa_key_t *key, const char *funding_address,
                         const spend_plan_t *plan, spend_result_t *out,
                         bonsai_err_ctx *err)
{
    if (!woc || !key || !funding_address || !plan || !out)
        return bns_fail(err, BNS_EINVAL, "invalid fund_and_sign arguments");

    woc_utxos_t u;
    memset(&u, 0, sizeof u);
    int rc = woc_client_list_utxos(woc, funding_address, &u);
    if (rc != BNS_OK) {
        bns_fail(err, rc, "UTXO listing failed for %s", funding_address);
        return rc;
    }

    funding_utxos_t ranked;
    memset(&ranked, 0, sizeof ranked);
    rc = rank_funding_utxos(u.items, u.count, NULL, &ranked);
    woc_utxos_free(&u);
    if (rc != BNS_OK) {
        bns_fail(err, rc, "UTXO ranking failed");
        return rc;
    }

    rc = wallet_build_signed_spend(net, key, funding_address,
                                   ranked.items, ranked.count, plan, out, err);
    funding_utxos_free(&ranked);
    return rc;
}
