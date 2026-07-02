/*
 * tx_change.c — fee estimation and change-output adjustment.
 *
 * TS origin: bsv.Transaction fee math + src/chainSources/bsvFees.ts
 * (sendTimeFeeWindow / feeForSize / cpfpChildFee).
 *
 * Default bsv.Transaction.FEE_PER_KB = 50 (BONSAI_FEE_PER_KB). Live scripts
 * override to 100 and pass their own rate.
 *
 * OPERATOR-ORDER TRAP (plan.risks): bsvFees.feeForSize / bsv.Transaction
 * _estimateFee both compute Math.ceil((size / 1000) * feePerKb) — the divide by
 * 1000 happens BEFORE the multiply, in double precision (NOT integer, NOT long
 * double, no reassociation). Math.ceil at the boundary is decisive for the
 * [min, 3*min] window. We reproduce that with C `double` + ceil().
 */
#include "bsv/tx_change.h"

#include <math.h>

#include "bsv/varint.h"

/* bsv.js Transaction.DUST_AMOUNT (this build of @scrypt-inc/bsv). */
#define BONSAI_DUST_AMOUNT 1u

/* ---- size estimation ---------------------------------------------------- */

/* Serialized size of one input as bsv Input.toBufferWriter would produce:
 *   32 (prevTxId) + 4 (outputIndex) + varint(scriptLen) + scriptLen + 4 (seq).
 * bsv's base Input._estimateSize serializes the input's CURRENT script buffer,
 * so for the contract spends the (huge, dummy-signed) unlocking script already
 * attached is what determines the fee — we serialize it verbatim. */
static int input_size(const bsv_txin_t *in, size_t *out)
{
    byte_buf_t vi;
    byte_buf_init(&vi);
    int rc = write_varint(in->script_sig.len, &vi);
    if (rc != BNS_OK) {
        byte_buf_free(&vi);
        return rc;
    }
    *out = 32 + 4 + vi.len + in->script_sig.len + 4;
    byte_buf_free(&vi);
    return BNS_OK;
}

/* Serialized size of one output: 8 (satoshis) + varint(scriptLen) + scriptLen.
 * Mirrors bsv Output.getSize. */
static int output_size(const bsv_txout_t *out, size_t *sz)
{
    byte_buf_t vi;
    byte_buf_init(&vi);
    int rc = write_varint(out->script.len, &vi);
    if (rc != BNS_OK) {
        byte_buf_free(&vi);
        return rc;
    }
    *sz = 8 + vi.len + out->script.len;
    byte_buf_free(&vi);
    return BNS_OK;
}

/* bsv Transaction._estimateSize:
 *   8 (version+locktime) + varint(nIn) + varint(nOut)
 *   + sum(input._estimateSize()) + sum(output.getSize()). */
int estimate_size(const bsv_tx_t *tx, size_t *out_bytes)
{
    if (!tx || !out_bytes) return BNS_EINVAL;

    size_t result = 8; /* version (4) + locktime (4) */

    byte_buf_t vi;
    byte_buf_init(&vi);

    int rc = write_varint(tx->num_inputs, &vi);
    if (rc != BNS_OK) { byte_buf_free(&vi); return rc; }
    result += vi.len;

    byte_buf_clear(&vi);
    rc = write_varint(tx->num_outputs, &vi);
    if (rc != BNS_OK) { byte_buf_free(&vi); return rc; }
    result += vi.len;
    byte_buf_free(&vi);

    for (size_t i = 0; i < tx->num_inputs; i++) {
        size_t s;
        rc = input_size(&tx->inputs[i], &s);
        if (rc != BNS_OK) return rc;
        result += s;
    }
    for (size_t i = 0; i < tx->num_outputs; i++) {
        size_t s;
        rc = output_size(&tx->outputs[i], &s);
        if (rc != BNS_OK) return rc;
        result += s;
    }

    *out_bytes = result;
    return BNS_OK;
}

/* ---- fee math ----------------------------------------------------------- */

/* feeForSize(sizeBytes, feePerKb) = Math.ceil((sizeBytes / 1000) * feePerKb).
 * Operator order preserved: divide BEFORE multiply, in double precision. */
static uint64_t fee_for_size(size_t size_bytes, uint64_t fee_per_kb)
{
    double f = ceil(((double)size_bytes / 1000.0) * (double)fee_per_kb);
    if (f < 0.0) f = 0.0;
    return (uint64_t)f;
}

/* sendTimeFeeWindow(signedSizeBytes, feePerKb):
 *   min = feeForSize(signedSizeBytes, feePerKb)
 *   max = min * 3
 *   recommended = min(max(min, ceil(min * 1.3)), max)   [JS Math on doubles]. */
int sendtime_fee_window(size_t signed_bytes, uint64_t fee_per_kb,
                        fee_window_t *out)
{
    if (!out) return BNS_EINVAL;

    uint64_t min = fee_for_size(signed_bytes, fee_per_kb);
    uint64_t max = min * 3;

    /* recommended: JS computes ceil(min * 1.3) in double, then Math.max with
     * min, then Math.min with max. Reproduce the same float path. */
    double rec_d = ceil((double)min * 1.3);
    uint64_t rec = (rec_d < (double)min) ? min : (uint64_t)rec_d;
    if (rec > max) rec = max;

    out->signed_bytes = signed_bytes;
    out->fee_per_kb = fee_per_kb;
    out->min = min;
    out->max = max;
    out->recommended = rec;
    return BNS_OK;
}

/* ---- change adjustment -------------------------------------------------- */

/* Sum of input.output.satoshis. The model does not carry prevout values on the
 * txin, so the caller is responsible for ensuring funding covers the spend;
 * here we compute totalIn from a parallel convention is impossible — instead we
 * mirror bsv getUnspentValue using output satoshis ONLY when inputs carry no
 * value. Since bsv_txin_t has no satoshis field, totalIn must be supplied by the
 * tx having been assembled with known funding. We therefore treat totalIn as the
 * sum the caller pre-encoded into the change slot before calling: see below. */

/* update_change_output: recompute the fee for `tx` at `fee_per_kb` and settle
 * the change output at `change_index`.
 *
 * Mirrors bsv _updateChangeOutput:
 *   available  = totalIn - totalOut(excluding the change output)
 *   fee        = ceil(estimateSize(tx with change present) / 1000 * feePerKb)
 *   changeAmt  = available - fee
 *   if changeAmt >= DUST_AMOUNT: outputs[change_index].satoshis = changeAmt
 *   else: remove the change output.
 *
 * totalIn is taken from outputs[change_index].satoshis BEFORE adjustment used as
 * a sentinel is NOT how bsv works; the bsv_txin_t model lacks prevout values, so
 * totalIn is carried as the change output's pre-seeded satoshis PLUS all other
 * output satoshis: i.e. the caller seeds outputs[change_index].satoshis with the
 * full unspent input total and we subtract the non-change outputs + fee. This is
 * the deterministic contract used by the C builders. */
int update_change_output(bsv_tx_t *tx, size_t change_index, uint64_t fee_per_kb)
{
    if (!tx) return BNS_EINVAL;
    if (change_index >= tx->num_outputs) return BNS_EINVAL;

    /* available = totalIn - sum(non-change outputs).
     * totalIn is seeded by the caller into outputs[change_index].satoshis. */
    uint64_t total_in = tx->outputs[change_index].satoshis;
    /* Fail-closed money-supply bound on the seeded funding total: a legitimate
     * totalIn (the sum of the spent UTXO values) can never exceed BONSAI_MAX_MONEY.
     * Reject an inflated seed rather than carry it into the subtraction below. */
    if (total_in > BONSAI_MAX_MONEY) return BNS_ERANGE;
    uint64_t out_sum = 0;
    for (size_t i = 0; i < tx->num_outputs; i++) {
        if (i == change_index) continue;
        uint64_t s = tx->outputs[i].satoshis;
        /* Overflow-safe running sum: each legitimate output value AND the total
         * are <= BONSAI_MAX_MONEY. Fail CLOSED (rather than wrap the uint64
         * accumulator) if a malicious/buggy tx carries inflated output values.
         * Checked BEFORE the add so out_sum can never wrap past the supply cap. */
        if (s > BONSAI_MAX_MONEY || s > (uint64_t)BONSAI_MAX_MONEY - out_sum)
            return BNS_ERANGE;
        out_sum += s;
    }
    if (out_sum > total_in) return BNS_ERANGE; /* insufficient funds */
    uint64_t available = total_in - out_sum;

    /* Fee is estimated over the tx WITH the change output present (bsv adds it before
     * _estimateFee). The change output is already at change_index; the satoshi VALUE
     * is a fixed 8-byte field, so the serialized size is identical regardless of it —
     * we therefore do NOT overwrite the slot before sizing. Writing `available` early
     * would, on the insufficient-fee error path below, leave the slot holding a partial
     * value instead of the caller's seed; deferring the write keeps the seed intact on
     * every error path (a caller that inspects/retries the tx after BNS_ERANGE sees it
     * unmodified). */
    size_t sz;
    int rc = estimate_size(tx, &sz);
    if (rc != BNS_OK) return rc;
    uint64_t fee = fee_for_size(sz, fee_per_kb);

    if (available < fee) return BNS_ERANGE; /* cannot cover fee — slot left at the seed */
    uint64_t change_amount = available - fee;

    if (change_amount >= BONSAI_DUST_AMOUNT) {
        tx->outputs[change_index].satoshis = change_amount;
        return BNS_OK;
    }

    /* Dust: remove the change output (bsv _removeOutput at change_index). */
    byte_buf_free(&tx->outputs[change_index].script);
    for (size_t i = change_index; i + 1 < tx->num_outputs; i++) {
        tx->outputs[i] = tx->outputs[i + 1];
    }
    tx->num_outputs -= 1;
    return BNS_OK;
}
