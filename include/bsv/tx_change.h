/*
 * tx_change.h — fee estimation and change-output adjustment.
 *
 * TS origin: bsv.Transaction fee math + src/chainSources/bsvFees.ts
 * (sendTimeFeeWindow / feeForSize / cpfpChildFee). The default FEE_PER_KB used
 * by bsv.Transaction here is 50 sats/KB (BONSAI_FEE_PER_KB); note the live
 * scripts (agentd/liveSmoke) OVERRIDE bsv.Transaction.FEE_PER_KB to 100 before
 * building — callers that must match those scripts pass their own rate.
 *
 * OPERATOR-ORDER TRAP (plan.risks — preserve each expression's order exactly,
 * no long double, no reassociation): bsvFees feeForSize divides by 1000 BEFORE
 * the multiply; cpfpChildFee multiplies BEFORE dividing. Math.ceil at the
 * boundary is decisive for the [min, 3*min] fee window.
 */
#ifndef BONSAI_BSV_TX_CHANGE_H
#define BONSAI_BSV_TX_CHANGE_H

#include <stddef.h>
#include <stdint.h>
#include "common/error.h"
#include "bsv/tx.h"

/* Default bsv.Transaction.FEE_PER_KB (sats per 1000 bytes). */
#define BONSAI_FEE_PER_KB 50

/* BSV money supply cap (2.1e15 sats). Mirrors the canonical definition in
 * chainSources/utxo_select.h; defined here too (ifndef-guarded, identical value)
 * so update_change_output can bound its uint64 output-sum / seeded-total
 * accumulators without a chainSources<-bsv layering dependency, and so a TU that
 * includes both headers sees one consistent value. */
#ifndef BONSAI_MAX_MONEY
#define BONSAI_MAX_MONEY (21000000LL * 100000000LL)  /* 2,100,000,000,000,000 sats */
#endif

/* The sendTimeFeeWindow result: a [min, max=3*min] acceptable fee window plus a
 * recommended value, for a given signed size and fee rate.
 * TS: bsvFees.sendTimeFeeWindow -> {signedBytes, feePerKb, min, max, recommended}. */
typedef struct {
    size_t   signed_bytes; /* estimated signed tx size in bytes */
    uint64_t fee_per_kb;   /* rate used                         */
    uint64_t min;          /* minimum acceptable fee            */
    uint64_t max;          /* 3 * min                           */
    uint64_t recommended;  /* recommended fee within the window */
} fee_window_t;

/* Estimate the signed size in bytes of `tx` (accounts for unlocking-script
 * sizes the signer will add). TS: bsv tx _estimateSize / size accounting.
 * BNS_OK. Result via *out_bytes. */
int estimate_size(const bsv_tx_t *tx, size_t *out_bytes);

/* Compute the fee window for `signed_bytes` at `fee_per_kb`. Mirrors
 * bsvFees.sendTimeFeeWindow EXACTLY including operator order and Math.ceil.
 * TS: sendTimeFeeWindow(signedBytes, feePerKb). BNS_OK / BNS_EINVAL. */
int sendtime_fee_window(size_t signed_bytes, uint64_t fee_per_kb,
                        fee_window_t *out);

/* Recompute the fee for `tx` at `fee_per_kb` and set the change output at index
 * `change_index` to (totalIn - totalOut(non-change) - fee), or remove it if the
 * change would be dust. TS: tx.change(addr) + tx.fee(...) settle.
 * BNS_OK / BNS_EINVAL (bad index) / BNS_ERANGE (insufficient funds). */
int update_change_output(bsv_tx_t *tx, size_t change_index, uint64_t fee_per_kb);

#endif /* BONSAI_BSV_TX_CHANGE_H */
