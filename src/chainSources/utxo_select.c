/*
 * utxo_select.c — pure, deterministic UTXO ranking.
 * Port of src/chainSources/utxoSelect.ts (rankFundingUtxos).
 *
 * Pipeline (faithful to TS .filter().filter().map().sort()):
 *   1. keep value >= minSats   (minSats default 0; explicit 0 honored)
 *   2. if confirmedOnly: keep height > 0
 *   3. map -> funding_utxo_t (confirmed = height > 0)
 *   4. STABLE sort: confirmed-first, then descending satoshis.
 *
 * V8 Array.sort is STABLE, so ties (same confirmed AND same satoshis) keep
 * input order. qsort() is NOT guaranteed stable, so we use a bottom-up stable
 * merge sort.
 */
#include "chainSources/utxo_select.h"

#include <stdlib.h>
#include <string.h>

void funding_utxos_free(funding_utxos_t *f)
{
    if (f == NULL)
        return;
    free(f->items);
    f->items = NULL;
    f->count = 0;
}

int funding_utxos_total(const funding_utxo_t *items, size_t count,
                        uint64_t *out_total)
{
    if (out_total == NULL || (items == NULL && count > 0))
        return BNS_EINVAL;

    uint64_t total = 0;
    for (size_t i = 0; i < count; i++) {
        int64_t v = items[i].satoshis;
        /* Reject an out-of-range single value (negative or above the money
         * supply) before it can poison the sum. */
        if (v < 0 || v > BONSAI_MAX_MONEY)
            return BNS_ERANGE;
        /* Overflow-safe: total <= BONSAI_MAX_MONEY is an invariant here, so
         * (BONSAI_MAX_MONEY - total) cannot underflow; check BEFORE adding so the
         * accumulator never wraps past the supply cap. */
        if ((uint64_t)v > (uint64_t)BONSAI_MAX_MONEY - total)
            return BNS_ERANGE;
        total += (uint64_t)v;
    }

    *out_total = total;
    return BNS_OK;
}

/* TS comparator semantics:
 *   if (a.confirmed !== b.confirmed) return a.confirmed ? -1 : 1
 *   return b.satoshis - a.satoshis
 * Returns <0 if a should come before b, >0 if after, 0 if equal-key.
 * Note: only the SIGN is used (we never collapse via tiebreak so the merge
 * keeps input order on equal keys -> stability). */
static int cmp_funding(const funding_utxo_t *a, const funding_utxo_t *b)
{
    if (a->confirmed != b->confirmed)
        return a->confirmed ? -1 : 1;
    if (b->satoshis > a->satoshis)
        return 1;
    if (b->satoshis < a->satoshis)
        return -1;
    return 0;
}

/* Bottom-up stable merge sort over funding_utxo_t. */
static int stable_sort(funding_utxo_t *arr, size_t n)
{
    if (n < 2)
        return BNS_OK;

    funding_utxo_t *tmp = malloc(n * sizeof(*tmp));
    if (tmp == NULL)
        return BNS_ENOMEM;

    for (size_t width = 1; width < n; width *= 2) {
        for (size_t i = 0; i < n; i += 2 * width) {
            size_t left = i;
            size_t mid = i + width;
            size_t right = i + 2 * width;
            if (mid > n)
                mid = n;
            if (right > n)
                right = n;

            size_t l = left, r = mid, k = left;
            while (l < mid && r < right) {
                /* <= keeps the left (earlier input) element first on ties =>
                 * stable. */
                if (cmp_funding(&arr[l], &arr[r]) <= 0)
                    tmp[k++] = arr[l++];
                else
                    tmp[k++] = arr[r++];
            }
            while (l < mid)
                tmp[k++] = arr[l++];
            while (r < right)
                tmp[k++] = arr[r++];
        }
        memcpy(arr, tmp, n * sizeof(*arr));
    }

    free(tmp);
    return BNS_OK;
}

int rank_funding_utxos(const woc_utxo_t *utxos, size_t n,
                       const rank_opts_t *opts, funding_utxos_t *out)
{
    if (out == NULL)
        return BNS_EINVAL;

    out->items = NULL;
    out->count = 0;

    /* RankOpts defaults (header presence flags model JS optional/nullish). */
    int64_t min_sats = 0;
    bool confirmed_only = false;
    if (opts != NULL) {
        if (opts->has_min_sats)
            min_sats = opts->min_sats; /* explicit 0 honored */
        if (opts->has_confirmed_only)
            confirmed_only = opts->confirmed_only;
    }

    if (n == 0)
        return BNS_OK;

    funding_utxo_t *items = malloc(n * sizeof(*items));
    if (items == NULL)
        return BNS_ENOMEM;

    size_t count = 0;
    for (size_t i = 0; i < n; i++) {
        const woc_utxo_t *u = &utxos[i];

        /* (0) Fail-closed money-supply bound: a single funding value can never
         * legitimately exceed BONSAI_MAX_MONEY. The WoC parse layer already
         * clamps via woc_json_money, but rank_funding_utxos is a public API that
         * may be fed directly, so drop an out-of-range entry here too — it must
         * never reach a downstream funding-sum accumulator. (Does NOT alter the
         * happy path: every legitimate value is <= BONSAI_MAX_MONEY.) */
        if (u->value > BONSAI_MAX_MONEY)
            continue;
        /* (1) value >= minSats */
        if (u->value < min_sats)
            continue;
        /* (2) confirmedOnly => height > 0 */
        if (confirmed_only && !(u->height > 0))
            continue;

        /* (3) map */
        funding_utxo_t *f = &items[count];
        memcpy(f->tx_id, u->tx_hash, sizeof(f->tx_id));
        f->tx_id[sizeof(f->tx_id) - 1] = '\0';
        f->output_index = u->tx_pos;
        f->satoshis = u->value;
        f->confirmed = (u->height > 0);
        count++;
    }

    /* (4) stable sort */
    int rc = stable_sort(items, count);
    if (rc != BNS_OK) {
        free(items);
        return rc;
    }

    out->items = items;
    out->count = count;
    return BNS_OK;
}
