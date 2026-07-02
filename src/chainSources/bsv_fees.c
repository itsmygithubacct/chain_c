/*
 * bsv_fees.c — pure BSV fee arithmetic. Port of src/chainSources/bsvFees.ts.
 *
 * Floating-point ORDER is load-bearing (see bsv_fees.h):
 *   feeForSize  : ceil( (sizeBytes / 1000.0) * feePerKb )   DIVIDE FIRST
 *   cpfpChildFee: ceil( ((parentBytes+childBytes)*targetFeerate) / 1000.0 ) MUL FIRST
 *   recommended : min( max(min, ceil(min*1.3)), max )
 * All inputs are integer satoshis/bytes < 2^53 so doubles are exact; the only
 * rounding is the explicit ceil(). Negative inputs are BNS_EINVAL (TS throws).
 */
#include "chainSources/bsv_fees.h"

#include <math.h>

int fee_for_size(int64_t size_bytes, int64_t fee_per_kb, int64_t *out)
{
    if (size_bytes < 0 || fee_per_kb < 0)
        return BNS_EINVAL;
    if (out == NULL)
        return BNS_EINVAL;
    /* DIVIDE-FIRST: ceil((sizeBytes / 1000) * feePerKb) */
    double fee = ceil(((double)size_bytes / (double)BONSAI_FEE_PER_KB_DIVISOR) *
                      (double)fee_per_kb);
    *out = (int64_t)fee;
    return BNS_OK;
}

int send_time_fee_window(int64_t signed_size_bytes, int64_t fee_per_kb,
                         fee_window_t *out)
{
    if (out == NULL)
        return BNS_EINVAL;

    int64_t min_fee;
    int rc = fee_for_size(signed_size_bytes, fee_per_kb, &min_fee);
    if (rc != BNS_OK)
        return rc;

    int64_t max_fee = min_fee * BONSAI_FEE_WINDOW_MULTIPLIER;

    /* recommended = min( max(min, ceil(min * 1.3)), max ) */
    int64_t bumped = (int64_t)ceil((double)min_fee * BONSAI_FEE_RECOMMENDED_FACTOR);
    int64_t lower = (min_fee > bumped) ? min_fee : bumped; /* Math.max */
    int64_t recommended = (lower < max_fee) ? lower : max_fee; /* Math.min */

    out->min = min_fee;
    out->max = max_fee;
    out->recommended = recommended;
    return BNS_OK;
}

int is_fee_in_send_window(int64_t fee, int64_t signed_size_bytes,
                          int64_t fee_per_kb, bool *out_ok)
{
    if (out_ok == NULL)
        return BNS_EINVAL;

    fee_window_t w;
    int rc = send_time_fee_window(signed_size_bytes, fee_per_kb, &w);
    if (rc != BNS_OK)
        return rc; /* leave *out_ok unset on error, per header */

    *out_ok = (fee >= w.min && fee <= w.max);
    return BNS_OK;
}

bool needs_fee_bump(int64_t parent_feerate, int64_t floor)
{
    return parent_feerate < floor;
}

int cpfp_child_fee(int64_t parent_bytes, int64_t parent_fee_paid,
                   int64_t child_bytes, int64_t target_feerate, int64_t *out)
{
    if (out == NULL)
        return BNS_EINVAL;
    if (parent_bytes < 0 || child_bytes < 0 || target_feerate < 0)
        return BNS_EINVAL;

    /* MULTIPLY-FIRST: ceil(((parentBytes + childBytes) * targetFeerate) / 1000) */
    double want = ceil(((double)(parent_bytes + child_bytes) *
                        (double)target_feerate) /
                       (double)BONSAI_FEE_PER_KB_DIVISOR);
    int64_t want_total = (int64_t)want;

    int64_t child = want_total - parent_fee_paid;
    if (child < BONSAI_FEE_DUST_FLOOR)
        child = BONSAI_FEE_DUST_FLOOR; /* Math.max(..., 546) */

    *out = child;
    return BNS_OK;
}
