/*
 * sandboxed_agent.c — SandboxedAgent: the capability-mediation / credential-
 * containment seam of Pillar B. Holds exactly one brokered key secret; its only
 * egress is act(), which authorizes through the KeyBroker BEFORE sealing the
 * payload in the PrivateEnclave and invoking the single scoped
 * CapabilityProvider.
 *
 * Faithful port of src/sandbox/sandboxedAgent.ts. Pure orchestration — the
 * byte-exactness lives in the dependencies (enclave actionHash, provenance,
 * broker charge). The ONE thing not to get wrong: the strict, fail-closed order
 * authorize -> seal -> invoke, and the early return that runs NO effect and
 * produces NO receipt on a deny.
 */
#include "sandbox/sandboxed_agent.h"

#include <stdlib.h>
#include <string.h>

/* ---- small owned-string helper ------------------------------------------ */

static char *dup_str(const char *s)
{
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

/* ---- AgentActionResult management --------------------------------------- */

void agent_action_result_free(agent_action_result_t *r)
{
    if (!r) return;
    free(r->action_hash);
    free(r->provenance_hash);
    if (r->has_sealed) {
        sealed_record_free(&r->sealed);
    }
    /* `reason` is a borrowed static literal (from the broker decision); do not
     * free. `result` is provider-owned; do not free. */
    memset(r, 0, sizeof(*r));
}

/* ---- SandboxedAgent ----------------------------------------------------- */

struct sandboxed_agent_s {
    char                        *secret;       /* owned copy (the one credential) */
    key_broker_t                *broker;       /* borrowed */
    private_enclave_t           *enclave;      /* borrowed */
    char                        *identity_id;  /* owned copy */
    const capability_provider_t *capabilities; /* borrowed */
};

int sandboxed_agent_new(const char *secret, key_broker_t *broker,
                        private_enclave_t *enclave, const char *identity_id,
                        const capability_provider_t *capabilities,
                        sandboxed_agent_t **out)
{
    if (!secret || !broker || !enclave || !identity_id || !capabilities || !out)
        return BNS_EINVAL;

    sandboxed_agent_t *a = calloc(1, sizeof(*a));
    if (!a) return BNS_ENOMEM;

    a->secret = dup_str(secret);
    a->identity_id = dup_str(identity_id);
    if (!a->secret || !a->identity_id) {
        sandboxed_agent_free(a);
        return BNS_ENOMEM;
    }
    a->broker = broker;
    a->enclave = enclave;
    a->capabilities = capabilities;
    *out = a;
    return BNS_OK;
}

void sandboxed_agent_free(sandboxed_agent_t *agent)
{
    if (!agent) return;
    if (agent->secret) {
        /* cleanse the held secret */
        memset(agent->secret, 0, strlen(agent->secret));
        free(agent->secret);
    }
    free(agent->identity_id);
    free(agent);
}

int sandboxed_agent_act(sandboxed_agent_t *agent,
                        const agent_action_request_t *req,
                        agent_action_result_t *out)
{
    if (!agent || !req || !out) return BNS_EINVAL;
    memset(out, 0, sizeof(*out));

    /* 1. Authorise: scope + per-call/window caps + on-chain revocation, all
     *    fail-closed, metered on the broker's own clock (the agent is the
     *    adversary, so its clock is never trusted). */
    authorization_request_t areq = {
        .secret = agent->secret,
        .scope  = req->scope,
        .amount = req->amount,
    };
    authorization_decision_t decision;
    int rc = key_broker_authorize(agent->broker, &areq, &decision);
    if (rc != BNS_OK) return rc;

    if (!decision.allowed) {
        /* DO NOTHING ELSE — no seal, no effect, no receipt. `reason` is a
         * borrowed static literal from the broker (lives for the program). */
        out->allowed = false;
        out->reason = decision.reason;
        return BNS_OK;
    }

    /* 2. Seal the payload off-chain and derive the on-chain receipt commitment.
     *    The seal MUST happen before the effect so every effect that ran has a
     *    receipt. */
    sealed_record_t sealed;
    char *action_hash = NULL;
    char *provenance_hash = NULL;
    rc = private_enclave_seal_action(agent->enclave, agent->identity_id,
                                     req->payload, req->payload_len,
                                     req->provenance, &sealed,
                                     &action_hash, &provenance_hash);
    if (rc != BNS_OK) return rc;

    /* 3. ONLY NOW perform the single scoped outbound effect. The payload bytes
     *    are identical to the ones just sealed (same buffer). */
    void *result = NULL;
    rc = agent->capabilities->invoke(agent->capabilities->ctx, req->scope,
                                     req->payload, req->payload_len, &result);
    if (rc != BNS_OK) {
        /* The effect failed. The seal already happened (a receipt exists), but
         * we surface the provider error to the caller. Release what we own. */
        sealed_record_free(&sealed);
        free(action_hash);
        free(provenance_hash);
        return rc;
    }

    out->allowed = true;
    out->reason = NULL;
    out->action_hash = action_hash;
    out->provenance_hash = provenance_hash;
    out->sealed = sealed;
    out->has_sealed = true;
    out->result = result;
    return BNS_OK;
}

/* ---- RecordingCapabilityProvider (test/example) ------------------------- */

typedef struct {
    recording_call_t  *calls;
    size_t             count;
    size_t             cap;
    recording_reply_fn reply;
    void              *reply_user;
} recording_store_t;

static int recording_invoke(void *ctx, const char *scope,
                            const uint8_t *payload, size_t payload_len,
                            void **out_result)
{
    recording_store_t *s = ctx;

    /* record (scope, payload-as-utf8) */
    if (s->count == s->cap) {
        size_t nc = (s->cap == 0) ? 4 : s->cap * 2;
        recording_call_t *na = realloc(s->calls, nc * sizeof(recording_call_t));
        if (!na) return BNS_ENOMEM;
        s->calls = na;
        s->cap = nc;
    }
    char *scope_copy = dup_str(scope);
    char *payload_copy = malloc(payload_len + 1);
    if (!scope_copy || !payload_copy) {
        free(scope_copy);
        free(payload_copy);
        return BNS_ENOMEM;
    }
    if (payload_len) memcpy(payload_copy, payload, payload_len);
    payload_copy[payload_len] = '\0';
    s->calls[s->count].scope = scope_copy;
    s->calls[s->count].payload_utf8 = payload_copy;
    s->count++;

    /* reply: default returns the literal string "ok" */
    if (s->reply) {
        return s->reply(s->reply_user, scope, payload, payload_len, out_result);
    }
    if (out_result) *out_result = (void *)"ok";
    return BNS_OK;
}

int recording_capability_provider_new(recording_reply_fn reply, void *reply_user,
                                      capability_provider_t *out_vtable)
{
    if (!out_vtable) return BNS_EINVAL;

    recording_store_t *s = calloc(1, sizeof(*s));
    if (!s) return BNS_ENOMEM;
    s->reply = reply;
    s->reply_user = reply_user;

    out_vtable->ctx = s;
    out_vtable->invoke = recording_invoke;
    return BNS_OK;
}

void recording_capability_provider_free(capability_provider_t *provider)
{
    if (!provider || !provider->ctx) return;
    recording_store_t *s = provider->ctx;
    for (size_t i = 0; i < s->count; i++) {
        free(s->calls[i].scope);
        free(s->calls[i].payload_utf8);
    }
    free(s->calls);
    free(s);
    provider->ctx = NULL;
    provider->invoke = NULL;
}

void recording_capability_provider_calls(const capability_provider_t *provider,
                                         const recording_call_t **out_calls,
                                         size_t *out_count)
{
    if (!provider || !provider->ctx) {
        if (out_calls) *out_calls = NULL;
        if (out_count) *out_count = 0;
        return;
    }
    const recording_store_t *s = provider->ctx;
    if (out_calls) *out_calls = s->calls;
    if (out_count) *out_count = s->count;
}
