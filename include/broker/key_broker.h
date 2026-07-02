/*
 * key_broker.h — the core of Pillar B: issues scoped, revocable API keys bound
 * to an agent's on-chain Ricardian-TEA identity, metered by that identity's
 * authorisation envelope. Stores only SHA-256 of issued secrets.
 *
 * TS origin: src/broker/keyBroker.ts (IssuedKey, RevocationOracle,
 * AuthorizationRequest, AuthorizationDecision, KeyBrokerOpts, KeyBroker,
 * IdentityBindingError).
 *
 * SECURITY/BYTE-EXACTNESS PINS (module notes — do not reorder):
 *  - secret = literal ASCII "pk_" + 48 lowercase hex (24 CSPRNG bytes); keyId =
 *    32 lowercase hex (16 CSPRNG bytes). secretHash = SHA256(UTF-8 of the secret
 *    STRING, i.e. the "pk_..." ASCII — not decoded hex). Plaintext never stored.
 *  - issueFromChain ordered fail-closed checks: (1) binding via
 *    verify_identity_script_on_chain; (2) ricardianHash well-formed (EXACTLY 64
 *    hex) [BEFORE includes]; (3) agentPubKey well-formed (0[23] + 64 hex = 66)
 *    [BEFORE includes]; (4) script includes ricardianHash (ci substring);
 *    (5) script includes agentPubKey (ci substring); (6) oracle->is_revoked
 *    (throw => fail-closed); (7) revoked => refuse. The two well-formedness
 *    checks MUST run before the includes() checks (includes("") is vacuously
 *    true — empty bypass).
 *  - authorize ordered fail-closed checks: (1) lookupBySecret null => deny
 *    'unknown or invalid key' with NO keyId; (2) revokedLocally => deny;
 *    (3) oracle->is_revoked (throw => deny fail-closed); (4) revoked => latch
 *    revokedLocally=true + deny; (5) scope not in envelope.scopes => deny;
 *    (6) accountant.charge.
 *  - NO caller-supplied timestamp ever reaches the accountant; the only clock is
 *    the broker's now() (injectable, defaults to wall-clock seconds).
 *  - lookupBySecret: map by SHA256(secret) hex THEN constant-time compare
 *    (CRYPTO_memcmp) after a length-equality guard (defence-in-depth).
 *  - getKey returns a deep-ish copy (fresh envelope + fresh scopes array).
 */
#ifndef BONSAI_BROKER_KEY_BROKER_H
#define BONSAI_BROKER_KEY_BROKER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "broker/authorization_envelope.h"
#include "broker/identity_chain_view.h"

/* On-chain revocation lookup; the broker fails closed (treats unknown/error as
 * revoked) when this errors. A vtable satisfied by ChainRevocationOracle.
 * TS: keyBroker.ts::RevocationOracle. */
typedef struct revocation_oracle_s revocation_oracle_t;
struct revocation_oracle_s {
    void *ctx; /* implementation-private state */

    /* isRevoked(identityId): sets *out_revoked. Errors (non-BNS_OK) propagate so
     * the broker can fail closed. BNS_OK / BNS_ENET / BNS_EHOPLIMIT / ...
     * TS: RevocationOracle.isRevoked. */
    int (*is_revoked)(void *ctx, const char *identity_id, bool *out_revoked);
};

/* Public credential record returned at issue. `envelope` is OWNED by the record
 * (deep copy). createdAt is unix seconds. TS: keyBroker.ts::IssuedKey. */
typedef struct {
    char                     key_id[33];       /* 32 hex + NUL                  */
    char                    *agent_pub_key;    /* owned 66-hex compressed pubkey */
    char                    *ricardian_hash;   /* owned 64-hex                  */
    char                    *identity_id;      /* owned genesis txid            */
    authorization_envelope_t envelope;         /* owned (deep copy)             */
    int64_t                  created_at;       /* unix seconds                  */
} issued_key_t;

/* Release the owned members of an IssuedKey and zero it (NULL-safe). */
void issued_key_free(issued_key_t *key);

/* A request: opaque secret, capability scope, cost charged against the rolling
 * window. Deliberately carries NO caller timestamp.
 * TS: keyBroker.ts::AuthorizationRequest. */
typedef struct {
    const char *secret;  /* the "pk_..." opaque secret */
    const char *scope;   /* capability scope            */
    int64_t     amount;  /* metered cost                */
} authorization_request_t;

/* Result of authorize(): allow/deny, reason (borrowed static literal or NULL),
 * the matched keyId (empty string when none — e.g. unknown-key branch), and the
 * ChargeResult when metering ran (valid iff has_charge).
 * TS: keyBroker.ts::AuthorizationDecision. */
typedef struct {
    bool            allowed;
    const char     *reason;       /* NULL when allowed; static literal otherwise  */
    char            key_id[33];   /* matched keyId (32 hex + NUL); "" when none    */
    bool            has_key_id;   /* false mirrors omitted keyId                   */
    charge_result_t charge;       /* valid iff has_charge                          */
    bool            has_charge;
} authorization_decision_t;

/* Injectable clock returning unix seconds. NULL => wall-clock seconds.
 * TS: KeyBrokerOpts.now. */
typedef int64_t (*key_broker_clock_fn)(void *user);

/* Opaque in-memory broker handle. TS: keyBroker.ts::KeyBroker. */
typedef struct key_broker_s key_broker_t;

/* Arguments to issue() (raw mint). `envelope` is borrowed for the duration of
 * the call (the broker deep-copies it into the stored/issued key). */
typedef struct {
    const char                     *agent_pub_key; /* 66-hex compressed pubkey   */
    const char                     *ricardian_hash;/* 64-hex                     */
    const char                     *identity_id;   /* genesis txid               */
    const authorization_envelope_t *envelope;      /* borrowed                   */
} key_broker_issue_args_t;

/* Arguments to issueFromChain (chain-bound mint). `params`/`scopes` build the
 * envelope; the binding is verified against `expected_locking_script_hex`. */
typedef struct {
    const char              *identity_id;                /* genesis txid          */
    uint32_t                 identity_vout;              /* default 0             */
    const char              *expected_locking_script_hex;
    const char              *agent_pub_key;              /* 66-hex                */
    const char              *ricardian_hash;             /* 64-hex                */
    identity_params_t        params;                     /* on-chain caps         */
    const char *const       *scopes;                     /* capability scopes     */
    size_t                   num_scopes;
} key_broker_issue_from_chain_args_t;

/* ---- lifecycle ---------------------------------------------------------- */

/* Construct a broker over a borrowed RevocationOracle (must outlive it) and an
 * optional injected clock (clock NULL => wall-clock seconds). *out freed via
 * key_broker_free. TS: new KeyBroker(oracle, opts). BNS_OK / BNS_ENOMEM. */
int key_broker_new(const revocation_oracle_t *oracle,
                   key_broker_clock_fn clock, void *clock_user,
                   key_broker_t **out);

/* Release a broker and all stored keys (NULL-safe; does not free the oracle). */
void key_broker_free(key_broker_t *broker);

/* ---- issue / authorize -------------------------------------------------- */

/* Mint a key (raw, no chain binding). Writes the public IssuedKey to *out_key
 * (owned; release via issued_key_free) and the freshly minted secret to
 * *out_secret (freshly malloc'd "pk_..." string, caller frees). The secret is
 * returned ONLY here and never again. TS: KeyBroker.issue.
 * BNS_OK / BNS_ECRYPTO (CSPRNG) / BNS_ENOMEM. */
int key_broker_issue(key_broker_t *broker,
                     const key_broker_issue_args_t *args,
                     issued_key_t *out_key, char **out_secret);

/* Mint a key bound to a verified on-chain identity, running the ordered
 * fail-closed checks (see header note). On any binding failure mints NOTHING and
 * returns BNS_EBINDING (the IdentityBindingError equivalent); if `reason`/
 * `reason_sz` given, the verbatim refusal detail is copied in (truncated + NUL).
 * The full thrown message is "key-broker: refused to issue for identity
 * <id>: <reason>". On success same outputs as key_broker_issue.
 * TS: KeyBroker.issueFromChain.
 * BNS_OK / BNS_EBINDING / BNS_ECRYPTO / BNS_ENOMEM. */
int key_broker_issue_from_chain(key_broker_t *broker,
                                const key_broker_issue_from_chain_args_t *args,
                                const identity_chain_view_t *view,
                                issued_key_t *out_key, char **out_secret,
                                char *reason, size_t reason_sz);

/* Authorize a request with the ordered fail-closed checks (see header note).
 * Writes the decision to *out. Uses the broker's own clock for metering. Always
 * returns BNS_OK (oracle errors are folded into a fail-closed deny, not an error
 * return). TS: KeyBroker.authorize. */
int key_broker_authorize(key_broker_t *broker,
                         const authorization_request_t *req,
                         authorization_decision_t *out);

/* Latch a key revoked locally. Returns true if the keyId was known, false
 * otherwise (C bool predicate). TS: KeyBroker.revokeLocally. */
bool key_broker_revoke_locally(key_broker_t *broker, const char *key_id);

/* Return a sanitized public copy of a stored key (fresh envelope + fresh scopes
 * array) via *out_key (owned; release via issued_key_free). Sets *out_found
 * false when the keyId is unknown (the TS null). TS: KeyBroker.getKey.
 * BNS_OK / BNS_ENOMEM. */
int key_broker_get_key(const key_broker_t *broker, const char *key_id,
                       issued_key_t *out_key, bool *out_found);

#endif /* BONSAI_BROKER_KEY_BROKER_H */
