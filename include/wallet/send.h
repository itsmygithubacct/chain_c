/*
 * wallet/send.h — fund + sign orchestration: fetch the funding address's UTXOs
 * from a WocClient, rank them, and build+sign a spend plan. Does NOT broadcast
 * (the caller applies the CONFIRM_MAINNET_BROADCAST gate and calls
 * woc_client_broadcast). Shared by the `pay`/`opreturn` CLIs and chain_c_wallet.
 */
#ifndef BONSAI_WALLET_SEND_H
#define BONSAI_WALLET_SEND_H

#include "common/error.h"
#include "bsv/address.h"
#include "crypto/ecdsa.h"
#include "wallet/spend.h"
#include "chainSources/woc_client.h"

/* List + rank `funding_address` UTXOs via `woc`, then build+sign `plan`.
 * `key` must control `funding_address`. *out is filled (caller spend_result_free).
 * BNS_OK / BNS_ENET (UTXO fetch) / BNS_ERANGE (insufficient) / BNS_EINVAL / ... */
int wallet_fund_and_sign(woc_client_t *woc, bsv_network_t net,
                         const ecdsa_key_t *key, const char *funding_address,
                         const spend_plan_t *plan, spend_result_t *out,
                         bonsai_err_ctx *err);

#endif /* BONSAI_WALLET_SEND_H */
