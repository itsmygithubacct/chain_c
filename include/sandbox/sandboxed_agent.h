/*
 * sandboxed_agent.h — SandboxedAgent: the capability-mediation / credential-
 * containment seam of Pillar B. It runs untrusted agent logic holding exactly
 * one brokered key secret, and its only egress is act(), which authorizes
 * through the KeyBroker (scope + caps + fail-closed on-chain revocation) BEFORE
 * sealing the payload in the PrivateEnclave and invoking the single scoped
 * CapabilityProvider.
 *
 * TS origin: src/sandbox/sandboxedAgent.ts (CapabilityProvider,
 * AgentActionRequest, AgentActionResult, SandboxedAgent,
 * RecordingCapabilityProvider) over broker/key_broker.h + privacy/enclave.h +
 * provenance.h.
 *
 * PINS (module notes — pure orchestration; the ONLY things to not get wrong):
 *  - act() STRICT ORDER, fail-closed: (1) broker.authorize({secret,scope,amount});
 *    if !allowed return {allowed:false, reason} and DO NOTHING ELSE (no seal, no
 *    effect, no receipt). (2) enclave.sealAction(identityId, payload, provenance).
 *    (3) ONLY THEN capabilities.invoke(scope, payloadBuf). The seal MUST happen
 *    before the effect so every effect that ran has a receipt.
 *  - string payload -> UTF-8 bytes for BOTH the seal and the invoke buffer
 *    (identical bytes in both paths).
 *  - The agent's clock is never trusted; amount is metered on the broker's clock.
 */
#ifndef BONSAI_SANDBOX_SANDBOXED_AGENT_H
#define BONSAI_SANDBOX_SANDBOXED_AGENT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "broker/key_broker.h"
#include "privacy/enclave.h"
#include "provenance.h"

/* The single, scoped outbound effect an agent is allowed to perform. A callback
 * struct (vtable). `invoke` receives the raw payload bytes; its return value is
 * an opaque, caller-owned pointer surfaced as AgentActionResult.result.
 * TS: sandboxedAgent.ts::CapabilityProvider. */
typedef struct capability_provider_s capability_provider_t;
struct capability_provider_s {
    void *ctx;
    /* invoke(scope, payload, payload_len) -> opaque result via *out_result.
     * TS: CapabilityProvider.invoke. BNS_OK / impl-defined errors. */
    int (*invoke)(void *ctx, const char *scope,
                  const uint8_t *payload, size_t payload_len,
                  void **out_result);
};

/* One action: capability scope, metered cost, payload (sealed off-chain),
 * optional provenance (NULL => none). `payload` is the raw bytes (caller
 * pre-UTF-8-encodes a string). TS: sandboxedAgent.ts::AgentActionRequest. */
typedef struct {
    const char                *scope;
    int64_t                    amount;
    const uint8_t             *payload;
    size_t                     payload_len;
    const provenance_record_t *provenance;  /* NULL => none */
} agent_action_request_t;

/* Outcome: allowed flag, deny reason (borrowed static literal or NULL), the
 * on-chain actionHash/provenanceHash (owned hex, NULL on deny), the sealed
 * off-chain record (valid iff has_sealed), and the provider's return value
 * (only when allowed). TS: sandboxedAgent.ts::AgentActionResult. */
typedef struct {
    bool            allowed;
    const char     *reason;            /* NULL when allowed */
    char           *action_hash;       /* owned hex; NULL on deny */
    char           *provenance_hash;   /* owned hex; NULL on deny */
    sealed_record_t sealed;            /* valid iff has_sealed */
    bool            has_sealed;
    void           *result;            /* opaque provider return (only when allowed) */
} agent_action_result_t;

/* Release the owned members of an agent_action_result_t and zero it (NULL-safe).
 * Does NOT free the opaque `result` (provider-owned). */
void agent_action_result_free(agent_action_result_t *r);

/* Opaque sandboxed agent handle: holds the one secret + borrowed broker/enclave/
 * capabilities + identityId. TS: sandboxedAgent.ts::SandboxedAgent. */
typedef struct sandboxed_agent_s sandboxed_agent_t;

/* Construct: hold a copy of `secret`, borrow broker/enclave/capabilities (must
 * outlive it) and copy identity_id. *out freed via sandboxed_agent_free.
 * TS: new SandboxedAgent(secret, broker, enclave, identityId, capabilities).
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int sandboxed_agent_new(const char *secret, key_broker_t *broker,
                        private_enclave_t *enclave, const char *identity_id,
                        const capability_provider_t *capabilities,
                        sandboxed_agent_t **out);

/* Release the agent (cleanses the held secret; does not free the borrowed
 * broker/enclave/capabilities). NULL-safe. */
void sandboxed_agent_free(sandboxed_agent_t *agent);

/* act(req): authorize -> (on deny) return {allowed:false,reason} doing nothing
 * else; else seal -> invoke -> return {allowed:true,...}. Writes the outcome to
 * *out (owned; release via agent_action_result_free). TS: SandboxedAgent.act.
 * BNS_OK / BNS_ECRYPTO / BNS_ENOMEM (or a provider error from invoke). */
int sandboxed_agent_act(sandboxed_agent_t *agent,
                        const agent_action_request_t *req,
                        agent_action_result_t *out);

/* ---- RecordingCapabilityProvider (test/example) ------------------------- */

/* A recorded invocation: scope + UTF-8 payload (owned copies). TS: the
 * RecordingCapabilityProvider.calls element. */
typedef struct {
    char   *scope;        /* owned */
    char   *payload_utf8; /* owned NUL-terminated UTF-8 view of the payload */
} recording_call_t;

/* Optional reply hook: produce the opaque result for a recorded call. NULL =>
 * default returns the literal string "ok". TS: the reply constructor arg. */
typedef int (*recording_reply_fn)(void *user, const char *scope,
                                   const uint8_t *payload, size_t payload_len,
                                   void **out_result);

/* Construct a RecordingCapabilityProvider: populates `out_vtable` (ctx holds the
 * recorded-calls store). Release via recording_capability_provider_free.
 * TS: new RecordingCapabilityProvider(reply). BNS_OK / BNS_ENOMEM. */
int recording_capability_provider_new(recording_reply_fn reply, void *reply_user,
                                      capability_provider_t *out_vtable);

/* Release a RecordingCapabilityProvider's store (and its recorded calls). NULL-safe. */
void recording_capability_provider_free(capability_provider_t *provider);

/* Access the recorded calls (borrowed; valid until the provider is freed).
 * Sets *out_calls / *out_count. TS: RecordingCapabilityProvider.calls. */
void recording_capability_provider_calls(const capability_provider_t *provider,
                                         const recording_call_t **out_calls,
                                         size_t *out_count);

#endif /* BONSAI_SANDBOX_SANDBOXED_AGENT_H */
