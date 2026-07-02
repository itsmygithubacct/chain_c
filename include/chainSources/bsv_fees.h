/*
 * bsv_fees.h — pure BSV fee arithmetic: the scrypt-ts send-time fee-window rule
 * and the CPFP fee-bump math. No I/O, no env, no crypto.
 *
 * TS origin: src/chainSources/bsvFees.ts (feeForSize, FeeWindow,
 * sendTimeFeeWindow, isFeeInSendWindow, needsFeeBump, cpfpChildFee).
 *
 * =====================  FLOATING-POINT ORDER TRAPS  =========================
 * Determinism risk is ENTIRELY in floating-point evaluation order. JS uses
 * IEEE-754 doubles for all arithmetic; reproduce with C `double` + ceil() from
 * <math.h> and PRESERVE THE EXACT operator/parenthesization order (plan.risks):
 *
 *  - feeForSize: ceil( (sizeBytes / 1000.0) * feePerKb )
 *      DIVIDE BY 1000 FIRST, then multiply. Do NOT reorder to
 *      ceil(sizeBytes*feePerKb/1000) — rounding could shift the ceil boundary
 *      and push a fee one sat outside the window.
 *
 *  - cpfpChildFee: ceil( ((parentBytes + childBytes) * targetFeerate) / 1000 )
 *      MULTIPLY FIRST, then divide by 1000 — the OPPOSITE order from feeForSize.
 *
 *  - sendTimeFeeWindow.recommended: min( max(min, ceil(min * 1.3)), max )
 *      exact nested clamp order; 1.3 and the 3x ceiling are load-bearing.
 *
 * Magic constants (hardcode): 3 (upper window multiplier), 1.3 (recommended
 * multiplier), default floor 50 (needsFeeBump), dust floor 546 (cpfpChildFee),
 * divisor 1000. All inputs are conceptually integer satoshis/bytes < 2^53 (so
 * doubles are exact); the only rounding is the explicit ceil. Negative inputs
 * are an error (the TS throws). Results are returned as int64 satoshis.
 * ============================================================================
 */
#ifndef BONSAI_CHAINSOURCES_BSV_FEES_H
#define BONSAI_CHAINSOURCES_BSV_FEES_H

#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"

/* Load-bearing fee constants. TS: bsvFees.ts literals. */
#define BONSAI_FEE_WINDOW_MULTIPLIER   3      /* max = 3 * min                    */
#define BONSAI_FEE_RECOMMENDED_FACTOR  1.3    /* ceil(min * 1.3)                  */
#define BONSAI_FEE_BUMP_FLOOR_DEFAULT  50     /* needsFeeBump default (sats/KB)   */
#define BONSAI_FEE_DUST_FLOOR          546    /* cpfpChildFee floor (sats)        */
#define BONSAI_FEE_PER_KB_DIVISOR      1000   /* sats-per-1000-bytes divisor      */

/* Send-time fee bounds. TS: FeeWindow {min, max, recommended}. */
typedef struct {
    int64_t min;          /* feeForSize lower bound                              */
    int64_t max;          /* 3 * min upper bound                                */
    int64_t recommended;  /* min(max(min, ceil(min*1.3)), max)                  */
} fee_window_t;

/* fee = ceil((sizeBytes / 1000.0) * feePerKb) (DIVIDE-FIRST order). Writes the
 * satoshi fee to *out. TS: feeForSize. BNS_OK / BNS_EINVAL (negative input). */
int fee_for_size(int64_t size_bytes, int64_t fee_per_kb, int64_t *out);

/* Compute the accepted fee window [min, 3*min] for a fully-signed tx of
 * signed_size_bytes at fee_per_kb, plus the recommended in-window fee.
 * TS: sendTimeFeeWindow. BNS_OK / BNS_EINVAL. */
int send_time_fee_window(int64_t signed_size_bytes, int64_t fee_per_kb,
                         fee_window_t *out);

/* True iff fee is within [min, max] INCLUSIVE of the send-time window.
 * TS: isFeeInSendWindow (>= and <=, not strict). Errors via *out_ok unset on
 * BNS_EINVAL. BNS_OK / BNS_EINVAL. */
int is_fee_in_send_window(int64_t fee, int64_t signed_size_bytes,
                          int64_t fee_per_kb, bool *out_ok);

/* True iff parent_feerate (sats/KB) < floor (strict less-than). Pure predicate.
 * Pass BONSAI_FEE_BUMP_FLOOR_DEFAULT for the TS default. TS: needsFeeBump. */
bool needs_fee_bump(int64_t parent_feerate, int64_t floor);

/* Size a CPFP child fee so the {parent,child} package meets target_feerate:
 *   wantTotal = ceil(((parentBytes + childBytes) * targetFeerate) / 1000.0)
 *   childFee  = max(wantTotal - parentFeePaid, 546)   (MULTIPLY-FIRST order)
 * Writes the satoshi child fee to *out. TS: cpfpChildFee. BNS_OK / BNS_EINVAL. */
int cpfp_child_fee(int64_t parent_bytes, int64_t parent_fee_paid,
                   int64_t child_bytes, int64_t target_feerate, int64_t *out);

#endif /* BONSAI_CHAINSOURCES_BSV_FEES_H */
