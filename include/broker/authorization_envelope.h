/*
 * authorization_envelope.h — the off-chain authorization envelope (per-call /
 * per-window / window-duration caps + capability scopes) mirroring an agent
 * identity's immutable on-chain Ricardian parameters, plus a WindowAccountant
 * reproducing the contract's rolling-window spend arithmetic so the broker's
 * off-chain decisions match what a miner would accept on-chain.
 *
 * TS origin: src/broker/authorizationEnvelope.ts (IdentityParams,
 * AuthorizationEnvelope, ChargeResult, WindowAccountant, envelopeFromIdentity).
 *
 * BYTE/ARITHMETIC-EXACTNESS PINS (module notes — mirrors ricardianTea.ts:231-239):
 *  - charge() order is load-bearing: (1) amount<=0 -> deny('amount must be
 *    positive'); (2) amount>perCall -> deny('exceeds per-call limit'); (3) load
 *    windowStart/spent; (4) if NOT started OR (now - windowStart >=
 *    windowDuration) roll: windowStart=now, spent=0; (5) next=spent+amount;
 *    (6) next>perWindow -> deny('exceeds rolling window limit') WITHOUT mutating
 *    (reports pre-charge spent + the ROLLED windowStart); (7) else commit.
 *  - Window-roll comparison uses >= (a charge exactly windowDuration seconds
 *    after windowStart starts a NEW window).
 *  - Denial asymmetry: a per-call/positive denial reports the CURRENT (un-rolled)
 *    windowStart (or `now` when never started); a per-window denial reports the
 *    ROLLED-FORWARD windowStart. Reproduce exactly.
 *  - State mutates ONLY on an allowed charge.
 *  - All amounts/limits/now are TS arbitrary-precision bigint; modelled here as
 *    int64_t (realistic satoshi caps fit; callers must guard the spent+amount
 *    add for overflow as the impl does).
 */
#ifndef BONSAI_BROKER_AUTHORIZATION_ENVELOPE_H
#define BONSAI_BROKER_AUTHORIZATION_ENVELOPE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"

/* The immutable on-chain Ricardian numeric parameters: per-tx cap, per-window
 * cap, window length in seconds. TS: authorizationEnvelope.ts::IdentityParams. */
typedef struct {
    int64_t per_tx_limit;    /* perTxLimit  -> envelope.perCall    */
    int64_t daily_limit;     /* dailyLimit  -> envelope.perWindow  */
    int64_t window_duration; /* windowDuration (seconds)           */
} identity_params_t;

/* The authorisation envelope a key is bound to. `scopes` is an OWNED array of
 * OWNED NUL-terminated capability scope strings (deep-copied from the source).
 * TS: authorizationEnvelope.ts::AuthorizationEnvelope. */
typedef struct {
    int64_t per_call;        /* == IdentityParams.perTxLimit            */
    int64_t per_window;      /* == IdentityParams.dailyLimit            */
    int64_t window_duration; /* window length in seconds                */
    char  **scopes;          /* owned array of owned scope strings      */
    size_t  num_scopes;      /* length of `scopes`                      */
} authorization_envelope_t;

/* Result of charging a request: allow/deny, optional reason (borrowed static
 * string literal — NOT owned; NULL when allowed), cumulative spend in window
 * after the (possible) charge, and the tracked window start.
 * TS: authorizationEnvelope.ts::ChargeResult. */
typedef struct {
    bool        allowed;
    const char *reason;          /* NULL when allowed; static literal otherwise */
    int64_t     spent_in_window; /* cumulative spend reported after charge      */
    int64_t     window_start;    /* tracked window start (see denial asymmetry) */
} charge_result_t;

/* Stateful rolling-window meter. Mutates `spent_in_window`/`window_start`/
 * `started` ONLY on an allowed charge. Borrows `envelope` (must outlive it).
 * TS: authorizationEnvelope.ts::WindowAccountant. */
typedef struct {
    const authorization_envelope_t *envelope; /* borrowed                       */
    int64_t spent_in_window;                  /* initial 0                      */
    int64_t window_start;                     /* initial 0                      */
    bool    started;                          /* initial false (distinct from   */
                                              /* window_start==0)               */
} window_accountant_t;

/* ---- envelope ----------------------------------------------------------- */

/* Map on-chain IdentityParams + charter-derived scopes into an envelope:
 * perTxLimit->perCall, dailyLimit->perWindow, windowDuration passthrough, and a
 * DEEP COPY of `scopes` ([...scopes]) so callers cannot mutate envelope scopes.
 * `out->scopes` is freshly allocated; release with authorization_envelope_free.
 * TS: authorizationEnvelope.ts::envelopeFromIdentity.
 * BNS_OK / BNS_ENOMEM. */
int envelope_from_identity(const identity_params_t *params,
                           const char *const *scopes, size_t num_scopes,
                           authorization_envelope_t *out);

/* Release the owned scopes array of an envelope and zero it (NULL-safe). Does
 * NOT free the envelope struct itself. */
void authorization_envelope_free(authorization_envelope_t *env);

/* ---- WindowAccountant ---------------------------------------------------- */

/* Initialise a meter over `envelope` (borrowed): spent=0, windowStart=0,
 * started=false. TS: new WindowAccountant(envelope). */
void window_accountant_init(window_accountant_t *acc,
                            const authorization_envelope_t *envelope);

/* Charge `amount` at time `now` (unix seconds). Reproduces the exact TS decision
 * order (see header note); mutates the accountant only on an allowed charge.
 * Writes the outcome to *out. TS: WindowAccountant.charge(amount, now). */
void window_accountant_charge(window_accountant_t *acc,
                              int64_t amount, int64_t now,
                              charge_result_t *out);

/* Read the current counters without mutating. TS: WindowAccountant.snapshot(). */
void window_accountant_snapshot(const window_accountant_t *acc,
                                int64_t *out_spent_in_window,
                                int64_t *out_window_start);

#endif /* BONSAI_BROKER_AUTHORIZATION_ENVELOPE_H */
