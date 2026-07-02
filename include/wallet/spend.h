/*
 * wallet/spend.h — reusable P2PKH spend builder (the wallet's signing spine).
 *
 * Part of libbonsai_chain. Generalizes the cpfp build->sighash(BIP143/FORKID)->
 * sign->scriptSig->serialize flow into a multi-input / multi-output P2PKH spend
 * with optional OP_RETURN and automatic change + fee. Used by the `pay` and
 * `opreturn` CLIs and by chain_c_wallet (`ccw`) for pay / sweep / send /
 * consolidate / split.
 *
 * It does NOT touch the network: the caller supplies the candidate UTXOs (e.g.
 * from woc_client_list_utxos + rank_funding_utxos) and broadcasts the resulting
 * raw_hex itself (woc_client_broadcast), gated by CONFIRM_MAINNET_BROADCAST.
 *
 * All inputs are spent from a single funding key (`key` controlling
 * `funding_address`); every candidate UTXO must be that address's P2PKH output.
 */
#ifndef BONSAI_WALLET_SPEND_H
#define BONSAI_WALLET_SPEND_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "common/error.h"
#include "bsv/address.h"
#include "crypto/ecdsa.h"
#include "chainSources/utxo_select.h"  /* funding_utxo_t */

/* Dust floor for a P2PKH change/recipient output (sats). Below this an output is
 * uneconomical; change under this folds into the miner fee. */
#define WALLET_DUST_THRESHOLD 546

/* Sanity ceiling for an operator-supplied fee rate (sats per KB). Real BSV rates
 * are a few sats/KB; this cap is ~a billion times that, so it never blocks a
 * legitimate rate but rejects a fat-fingered value before it can convert all
 * change into fee or overflow the double->uint64 fee conversion downstream. */
#define WALLET_MAX_FEE_PER_KB 1000000000000LL  /* 1e12 sats/KB */

/* One P2PKH recipient. `address` is a base58check mainnet '1...' address. */
typedef struct {
    char     address[80];
    uint64_t satoshis;   /* ignored when plan->send_all */
} spend_recipient_t;

/* A spend plan. */
typedef struct {
    const spend_recipient_t *recipients;
    size_t                   num_recipients;
    const uint8_t           *op_return_data;  /* optional; NULL => no data output */
    size_t                   op_return_len;
    const char              *change_address;   /* receives change (defaults to the
                                                * funding address if NULL) */
    uint64_t                 fee_per_kb;        /* 0 => BONSAI_FEE_PER_KB (50) */
    bool                     send_all;          /* sweep: pay (total_in - fee) to
                                                 * recipients[0] (its satoshis
                                                 * field is ignored) */
} spend_plan_t;

/* The build+sign result (caller frees via spend_result_free). */
typedef struct {
    char    *raw_hex;     /* signed raw tx hex (owned) */
    char    *txid;        /* display txid (owned)      */
    uint64_t total_in;
    uint64_t total_out;   /* recipients + change (+ 0-sat OP_RETURN) */
    uint64_t fee;         /* total_in - total_out */
    uint64_t change;      /* change paid (0 if none / folded into fee) */
    size_t   num_inputs;
    size_t   size_bytes;
} spend_result_t;

void spend_result_free(spend_result_t *r);

/* Build and SIGN (does not broadcast) a P2PKH spend.
 *
 * `net`            : network (BSV_MAINNET for live).
 * `key`            : the funding private key (controls `funding_address`).
 * `funding_address`: the P2PKH address every `utxos` entry belongs to; also the
 *                    default change address.
 * `utxos`/`num_utxos`: candidate funding UTXOs, best-first (confirmed, largest).
 * `plan`           : recipients / OP_RETURN / change / fee policy.
 * `out`            : the signed result.
 * `err`            : optional verbatim message capture.
 *
 * BNS_OK / BNS_EINVAL (bad args/address) / BNS_ERANGE (insufficient funds) /
 * BNS_ECRYPTO (sign) / BNS_ENOMEM. */
int wallet_build_signed_spend(bsv_network_t net,
                              const ecdsa_key_t *key,
                              const char *funding_address,
                              const funding_utxo_t *utxos, size_t num_utxos,
                              const spend_plan_t *plan,
                              spend_result_t *out,
                              bonsai_err_ctx *err);

#endif /* BONSAI_WALLET_SPEND_H */
