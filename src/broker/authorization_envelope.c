/*
 * authorization_envelope.c — off-chain authorization envelope + WindowAccountant.
 *
 * Port of src/broker/authorizationEnvelope.ts (envelopeFromIdentity,
 * WindowAccountant.charge/snapshot). The window arithmetic is kept byte-for-byte
 * identical to the on-chain rolling-window logic (ricardianTea.ts:231-239) so the
 * broker's off-chain decisions match what a miner would accept on-chain.
 *
 * Bigint modelling: TS uses arbitrary-precision BigInt for amounts/limits/now;
 * we model them as int64_t (realistic satoshi caps fit). The two places where TS
 * BigInt could exceed int64_t are computed in __int128 to stay faithful:
 *   - now - windowStart (the roll comparison)
 *   - spent + amount    (the per-window accumulation)
 * Both intermediate values are reduced to int64_t only after the comparisons,
 * and a value that survives the `next <= perWindow` check is in range (perWindow
 * is int64_t), so the committed counters never overflow.
 */
#include "broker/authorization_envelope.h"

#include <stdlib.h>
#include <string.h>

/* ---- envelope ----------------------------------------------------------- */

int envelope_from_identity(const identity_params_t *params,
                           const char *const *scopes, size_t num_scopes,
                           authorization_envelope_t *out)
{
    /* Map params, then deep-copy scopes ([...scopes]) so callers cannot mutate
     * the envelope's scope set. */
    out->per_call        = params->per_tx_limit;
    out->per_window      = params->daily_limit;
    out->window_duration = params->window_duration;
    out->scopes          = NULL;
    out->num_scopes      = 0;

    if (num_scopes == 0) {
        return BNS_OK;
    }

    char **copy = calloc(num_scopes, sizeof(*copy));
    if (copy == NULL) {
        return BNS_ENOMEM;
    }

    for (size_t i = 0; i < num_scopes; i++) {
        const char *src = scopes[i];
        size_t n = strlen(src) + 1;
        char *dup = malloc(n);
        if (dup == NULL) {
            /* Unwind everything allocated so far; leave *out clean. */
            for (size_t j = 0; j < i; j++) {
                free(copy[j]);
            }
            free(copy);
            return BNS_ENOMEM;
        }
        memcpy(dup, src, n);
        copy[i] = dup;
    }

    out->scopes     = copy;
    out->num_scopes = num_scopes;
    return BNS_OK;
}

void authorization_envelope_free(authorization_envelope_t *env)
{
    if (env == NULL || env->scopes == NULL) {
        if (env != NULL) {
            env->scopes     = NULL;
            env->num_scopes = 0;
        }
        return;
    }
    for (size_t i = 0; i < env->num_scopes; i++) {
        free(env->scopes[i]);
    }
    free(env->scopes);
    env->scopes     = NULL;
    env->num_scopes = 0;
}

/* ---- WindowAccountant ---------------------------------------------------- */

void window_accountant_init(window_accountant_t *acc,
                            const authorization_envelope_t *envelope)
{
    acc->envelope         = envelope;
    acc->spent_in_window  = 0;
    acc->window_start     = 0;
    acc->started          = false;
}

/* private deny(): reports current counters; windowStart is the un-rolled tracked
 * start, or `now` when the accountant has never started. */
static void accountant_deny(const window_accountant_t *acc, const char *reason,
                            int64_t now, charge_result_t *out)
{
    out->allowed         = false;
    out->reason          = reason;
    out->spent_in_window = acc->spent_in_window;
    out->window_start    = acc->started ? acc->window_start : now;
}

void window_accountant_charge(window_accountant_t *acc,
                              int64_t amount, int64_t now,
                              charge_result_t *out)
{
    const authorization_envelope_t *env = acc->envelope;

    /* (1) amount <= 0 -> deny('amount must be positive') */
    if (amount <= 0) {
        accountant_deny(acc, "amount must be positive", now, out);
        return;
    }
    /* (2) amount > perCall -> deny('exceeds per-call limit') */
    if (amount > env->per_call) {
        accountant_deny(acc, "exceeds per-call limit", now, out);
        return;
    }

    /* (3) load windowStart/spent */
    int64_t window_start = acc->window_start;
    int64_t spent        = acc->spent_in_window;

    /* (4) roll on first charge or on expiry. The expiry comparison uses >= and
     * is evaluated in 128-bit to match TS BigInt (now - windowStart can exceed
     * int64_t range for adversarial inputs). */
    if (!acc->started ||
        ((__int128)now - (__int128)window_start) >= (__int128)env->window_duration) {
        window_start = now;
        spent        = 0;
    }

    /* (5) next = spent + amount (128-bit; spent>=0 and amount<=perCall here). */
    __int128 next = (__int128)spent + (__int128)amount;

    /* (6) next > perWindow -> deny WITHOUT mutating; reports pre-charge spent and
     * the ROLLED-FORWARD windowStart. */
    if (next > (__int128)env->per_window) {
        out->allowed         = false;
        out->reason          = "exceeds rolling window limit";
        out->spent_in_window = spent;
        out->window_start    = window_start;
        return;
    }

    /* (7) commit. next <= perWindow (int64_t), so it fits int64_t. */
    acc->spent_in_window = (int64_t)next;
    acc->window_start    = window_start;
    acc->started         = true;

    out->allowed         = true;
    out->reason          = NULL;
    out->spent_in_window = (int64_t)next;
    out->window_start    = window_start;
}

void window_accountant_snapshot(const window_accountant_t *acc,
                                int64_t *out_spent_in_window,
                                int64_t *out_window_start)
{
    *out_spent_in_window = acc->spent_in_window;
    *out_window_start    = acc->window_start;
}
