/*
 * key_broker.c — port of src/broker/keyBroker.ts (KeyBroker, IssuedKey,
 * RevocationOracle consumer, IdentityBindingError).
 *
 * Pillar B: issues scoped, revocable API keys bound to an agent's on-chain
 * Ricardian-TEA identity, metered by that identity's authorisation envelope.
 * Only SHA-256 of issued secrets is stored; the plaintext is shown once.
 *
 * SECURITY/BYTE-EXACTNESS (see key_broker.h header note — do not reorder):
 *  - secret = ASCII "pk_" + 48 lowercase hex (24 CSPRNG bytes); keyId = 32
 *    lowercase hex (16 CSPRNG bytes). secretHash = SHA256(UTF-8 of the "pk_..."
 *    STRING, not decoded hex). Plaintext never stored.
 *  - issueFromChain ordered fail-closed checks: (1) binding via
 *    verify_identity_script_on_chain; (2) ricardianHash well-formed (64 hex)
 *    BEFORE includes; (3) agentPubKey well-formed (02/03 + 64 hex) BEFORE
 *    includes; (4) script includes ricardianHash (ci substring); (5) script
 *    includes agentPubKey (ci substring); (6) oracle->is_revoked (error =>
 *    fail-closed); (7) revoked => refuse.
 *  - authorize ordered fail-closed checks: (1) lookup null => deny 'unknown or
 *    invalid key' with NO keyId; (2) revokedLocally => deny; (3) oracle error
 *    => deny fail-closed; (4) revoked => latch revokedLocally + deny; (5) scope
 *    not in envelope.scopes => deny; (6) accountant.charge.
 *  - No caller-supplied timestamp ever reaches the accountant; the only clock is
 *    the broker's now() (injectable; defaults to wall-clock seconds).
 *  - lookupBySecret: map by SHA256(secret) hex THEN constant-time compare
 *    (CRYPTO_memcmp) after a length-equality guard.
 */
#include "broker/key_broker.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <openssl/crypto.h>

#include "common/hex.h"
#include "crypto/hash.h"
#include "crypto/rand.h"

/* A stored key: the public IssuedKey fields plus the secret hash, accountant,
 * and the local revocation latch. Mirrors keyBroker.ts::StoredKey. */
typedef struct stored_key_s {
    issued_key_t        pub;            /* owns agent_pub_key/ricardian_hash/   */
                                        /* identity_id/envelope                 */
    uint8_t             secret_hash[BONSAI_SHA256_LEN]; /* SHA256(secret string)*/
    char                secret_hash_hex[2 * BONSAI_SHA256_LEN + 1];
    window_accountant_t accountant;     /* borrows pub.envelope                 */
    bool                revoked_locally;
} stored_key_t;

struct key_broker_s {
    const revocation_oracle_t *oracle;   /* borrowed                            */
    key_broker_clock_fn        clock;    /* NULL => wall-clock                  */
    void                      *clock_user;

    stored_key_t             **keys;     /* owned array of owned stored_key_t*  */
    size_t                     num_keys;
    size_t                     cap_keys;

    /* Backing store for a decision's dynamic 'scope not authorised: <scope>'
     * reason (the AuthorizationDecision.reason is a borrowed const char*; for
     * the one dynamic message TS produces we keep it here so the pointer the
     * caller reads stays valid until the next authorize() call). */
    char                       scope_reason[512];
};

/* ---- small helpers ------------------------------------------------------- */

static int64_t broker_now(const key_broker_t *broker)
{
    if (broker->clock) {
        return broker->clock(broker->clock_user);
    }
    return (int64_t)time(NULL); /* Math.floor(Date.now()/1000) */
}

/* sha256(s) over the UTF-8 bytes of the C string (the "pk_..." ASCII). */
static void sha256_str(const char *s, uint8_t out[BONSAI_SHA256_LEN])
{
    sha256((const uint8_t *)s, strlen(s), out);
}

/* Find a stored key by its 32-hex keyId (linear scan; map equivalent). */
static stored_key_t *find_by_key_id(const key_broker_t *broker,
                                     const char *key_id)
{
    if (!key_id) return NULL;
    for (size_t i = 0; i < broker->num_keys; i++) {
        if (strcmp(broker->keys[i]->pub.key_id, key_id) == 0) {
            return broker->keys[i];
        }
    }
    return NULL;
}

/* lookupBySecret: map by SHA256(secret) hex, then constant-time confirm. */
static stored_key_t *lookup_by_secret(const key_broker_t *broker,
                                       const char *secret)
{
    if (!secret) return NULL;

    uint8_t h[BONSAI_SHA256_LEN];
    char    h_hex[2 * BONSAI_SHA256_LEN + 1];
    sha256_str(secret, h);
    if (hex_encode_to(h, sizeof(h), h_hex, sizeof(h_hex)) != BNS_OK) {
        return NULL;
    }

    for (size_t i = 0; i < broker->num_keys; i++) {
        stored_key_t *k = broker->keys[i];
        if (strcmp(k->secret_hash_hex, h_hex) != 0) {
            continue;
        }
        /* Constant-time confirm (defence-in-depth; the hex map already matched).
         * Length-equality guard then CRYPTO_memcmp == constantTimeEqual. */
        if (CRYPTO_memcmp(k->secret_hash, h, sizeof(h)) != 0) {
            return NULL;
        }
        return k;
    }
    return NULL;
}

/* ---- IssuedKey copy / free ----------------------------------------------- */

void issued_key_free(issued_key_t *key)
{
    if (!key) return;
    free(key->agent_pub_key);
    free(key->ricardian_hash);
    free(key->identity_id);
    authorization_envelope_free(&key->envelope);
    memset(key, 0, sizeof(*key));
}

/* Deep-copy an envelope (fresh scopes array + fresh scope strings). */
static int envelope_copy(const authorization_envelope_t *src,
                         authorization_envelope_t *dst)
{
    return envelope_from_identity(
        &(identity_params_t){ .per_tx_limit    = src->per_call,
                              .daily_limit     = src->per_window,
                              .window_duration = src->window_duration },
        (const char *const *)src->scopes, src->num_scopes, dst);
}

/* Fill an issued_key_t with deep copies of the borrowed inputs. On failure
 * frees whatever it allocated and zeroes *out. */
static int issued_key_build(issued_key_t *out,
                            const char *key_id,
                            const char *agent_pub_key,
                            const char *ricardian_hash,
                            const char *identity_id,
                            const authorization_envelope_t *envelope,
                            int64_t created_at)
{
    memset(out, 0, sizeof(*out));

    snprintf(out->key_id, sizeof(out->key_id), "%s", key_id);
    out->created_at = created_at;

    out->agent_pub_key = agent_pub_key ? strdup(agent_pub_key) : strdup("");
    out->ricardian_hash = ricardian_hash ? strdup(ricardian_hash) : strdup("");
    out->identity_id = identity_id ? strdup(identity_id) : strdup("");
    if (!out->agent_pub_key || !out->ricardian_hash || !out->identity_id) {
        issued_key_free(out);
        return BNS_ENOMEM;
    }

    if (envelope_copy(envelope, &out->envelope) != BNS_OK) {
        issued_key_free(out);
        return BNS_ENOMEM;
    }
    return BNS_OK;
}

/* ---- lifecycle ----------------------------------------------------------- */

int key_broker_new(const revocation_oracle_t *oracle,
                   key_broker_clock_fn clock, void *clock_user,
                   key_broker_t **out)
{
    if (out) *out = NULL;
    if (!oracle || !out) return BNS_EINVAL;

    key_broker_t *b = calloc(1, sizeof(*b));
    if (!b) return BNS_ENOMEM;

    b->oracle     = oracle;
    b->clock      = clock;
    b->clock_user = clock_user;
    b->keys       = NULL;
    b->num_keys   = 0;
    b->cap_keys   = 0;

    *out = b;
    return BNS_OK;
}

void key_broker_free(key_broker_t *broker)
{
    if (!broker) return;
    for (size_t i = 0; i < broker->num_keys; i++) {
        stored_key_t *k = broker->keys[i];
        if (k) {
            issued_key_free(&k->pub);
            free(k);
        }
    }
    free(broker->keys);
    free(broker);
}

/* ---- issue --------------------------------------------------------------- */

/* Append a freshly built stored key to the broker. Takes ownership of *sk's
 * heap members on success; on failure leaves the broker untouched. */
static int broker_store(key_broker_t *broker, stored_key_t *sk)
{
    if (broker->num_keys == broker->cap_keys) {
        size_t new_cap = broker->cap_keys ? broker->cap_keys * 2 : 8;
        stored_key_t **grown = realloc(broker->keys,
                                       new_cap * sizeof(*grown));
        if (!grown) return BNS_ENOMEM;
        broker->keys     = grown;
        broker->cap_keys = new_cap;
    }
    broker->keys[broker->num_keys++] = sk;
    return BNS_OK;
}

int key_broker_issue(key_broker_t *broker,
                     const key_broker_issue_args_t *args,
                     issued_key_t *out_key, char **out_secret)
{
    if (out_secret) *out_secret = NULL;
    if (out_key) memset(out_key, 0, sizeof(*out_key));
    if (!broker || !args || !args->envelope || !out_key || !out_secret) {
        return BNS_EINVAL;
    }

    /* keyId = randomBytes(16).toString('hex') -> 32 lowercase hex. */
    uint8_t id_raw[16];
    if (rand_bytes(id_raw, sizeof(id_raw)) != BNS_OK) return BNS_ECRYPTO;
    char key_id[2 * sizeof(id_raw) + 1];
    if (hex_encode_to(id_raw, sizeof(id_raw), key_id, sizeof(key_id)) != BNS_OK) {
        return BNS_ECRYPTO;
    }

    /* secret = `pk_${randomBytes(24).toString('hex')}` -> "pk_" + 48 hex. */
    uint8_t sec_raw[24];
    if (rand_bytes_secure(sec_raw, sizeof(sec_raw)) != BNS_OK) return BNS_ECRYPTO;  /* long-term broker secret: bypass test RNG override (review-2 #7) */
    char sec_hex[2 * sizeof(sec_raw) + 1];
    if (hex_encode_to(sec_raw, sizeof(sec_raw), sec_hex, sizeof(sec_hex)) != BNS_OK) {
        return BNS_ECRYPTO;
    }
    char *secret = malloc(3 + sizeof(sec_hex)); /* "pk_" + hex + NUL */
    if (!secret) return BNS_ENOMEM;
    memcpy(secret, "pk_", 3);
    memcpy(secret + 3, sec_hex, sizeof(sec_hex)); /* includes NUL */
    /* The cleartext secret now lives in `secret`; scrub the raw + hex stack copies. */
    OPENSSL_cleanse(sec_raw, sizeof(sec_raw));
    OPENSSL_cleanse(sec_hex, sizeof(sec_hex));

    /* secretHash = SHA256(secret string). */
    uint8_t secret_hash[BONSAI_SHA256_LEN];
    char    secret_hash_hex[2 * BONSAI_SHA256_LEN + 1];
    sha256_str(secret, secret_hash);
    if (hex_encode_to(secret_hash, sizeof(secret_hash),
                      secret_hash_hex, sizeof(secret_hash_hex)) != BNS_OK) {
        (OPENSSL_cleanse(secret, 3 + sizeof(sec_hex)), free(secret));
        return BNS_ECRYPTO;
    }

    int64_t created_at = broker_now(broker);

    /* Build the stored key (its public part is also what we hand back). */
    stored_key_t *sk = calloc(1, sizeof(*sk));
    if (!sk) { (OPENSSL_cleanse(secret, 3 + sizeof(sec_hex)), free(secret)); return BNS_ENOMEM; }

    int rc = issued_key_build(&sk->pub, key_id, args->agent_pub_key,
                              args->ricardian_hash, args->identity_id,
                              args->envelope, created_at);
    if (rc != BNS_OK) { free(sk); (OPENSSL_cleanse(secret, 3 + sizeof(sec_hex)), free(secret)); return rc; }

    memcpy(sk->secret_hash, secret_hash, sizeof(secret_hash));
    memcpy(sk->secret_hash_hex, secret_hash_hex, sizeof(secret_hash_hex));
    /* WindowAccountant borrows the STORED envelope (must outlive it). */
    window_accountant_init(&sk->accountant, &sk->pub.envelope);
    sk->revoked_locally = false;

    rc = broker_store(broker, sk);
    if (rc != BNS_OK) {
        issued_key_free(&sk->pub);
        free(sk);
        (OPENSSL_cleanse(secret, 3 + sizeof(sec_hex)), free(secret));
        return rc;
    }

    /* Hand back a fresh public copy (caller owns) + the one-time secret. */
    rc = issued_key_build(out_key, key_id, args->agent_pub_key,
                          args->ricardian_hash, args->identity_id,
                          args->envelope, created_at);
    if (rc != BNS_OK) {
        /* The key is stored; we just cannot copy it out. Surface OOM but keep
         * the stored key consistent (the secret was never returned). */
        (OPENSSL_cleanse(secret, 3 + sizeof(sec_hex)), free(secret));
        return rc;
    }

    *out_secret = secret;
    return BNS_OK;
}

/* ---- issueFromChain ------------------------------------------------------ */

/* Emit the IdentityBindingError detail into reason (verbatim refusal detail —
 * the TS message wraps it as "key-broker: refused to issue for identity
 * <id>: <reason>", but the header documents `reason` as the verbatim DETAIL). */
static int binding_fail(char *reason, size_t reason_sz, const char *detail)
{
    if (reason && reason_sz > 0) {
        snprintf(reason, reason_sz, "%s", detail);
    }
    return BNS_EBINDING;
}

int key_broker_issue_from_chain(key_broker_t *broker,
                                const key_broker_issue_from_chain_args_t *args,
                                const identity_chain_view_t *view,
                                issued_key_t *out_key, char **out_secret,
                                char *reason, size_t reason_sz)
{
    if (out_secret) *out_secret = NULL;
    if (out_key) memset(out_key, 0, sizeof(*out_key));
    if (reason && reason_sz > 0) reason[0] = '\0';
    if (!broker || !args || !view || !out_key || !out_secret) {
        return BNS_EINVAL;
    }

    /* (1) Verify-on-read: the script we mint for must be the one on chain.
     * verify is total + fail-closed (always BNS_OK; sets ok + reason). */
    bool ok = false;
    char vreason[256];
    verify_identity_script_on_chain(view, args->identity_id,
                                    args->identity_vout,
                                    args->expected_locking_script_hex,
                                    &ok, vreason, sizeof(vreason));
    if (!ok) {
        return binding_fail(reason, reason_sz, vreason);
    }

    /* (2) ricardianHash well-formed (64 hex) — BEFORE includes(). */
    if (!is_sha256_hex(args->ricardian_hash)) {
        return binding_fail(reason, reason_sz,
            "ricardianHash is malformed (expected 64 hex chars / 32 bytes)");
    }
    /* (3) agentPubKey well-formed (02/03 + 64 hex = 66) — BEFORE includes(). */
    if (!is_pubkey_hex(args->agent_pub_key)) {
        return binding_fail(reason, reason_sz,
            "agentPubKey is malformed (expected a 33-byte compressed pubkey: "
            "66 hex chars, 02/03 prefix)");
    }

    /* (4)/(5) the verified script must contain both pushes (ci substring).
     * Lowercase both sides: scriptLc + the (already-validated) hex inputs. */
    char *script_lc = hex_to_lower(args->expected_locking_script_hex
                                       ? args->expected_locking_script_hex : "");
    char *rh_lc = hex_to_lower(args->ricardian_hash);
    char *pk_lc = hex_to_lower(args->agent_pub_key);
    if (!script_lc || !rh_lc || !pk_lc) {
        free(script_lc); free(rh_lc); free(pk_lc);
        return BNS_ENOMEM;
    }

    if (strstr(script_lc, rh_lc) == NULL) {
        free(script_lc); free(rh_lc); free(pk_lc);
        return binding_fail(reason, reason_sz,
            "ricardianHash is not present in the verified identity script");
    }
    if (strstr(script_lc, pk_lc) == NULL) {
        free(script_lc); free(rh_lc); free(pk_lc);
        return binding_fail(reason, reason_sz,
            "agentPubKey is not present in the verified identity script");
    }
    free(script_lc); free(rh_lc); free(pk_lc);

    /* (6) on-chain revocation (error => fail-closed). */
    bool revoked = false;
    int orc = broker->oracle->is_revoked(broker->oracle->ctx,
                                         args->identity_id, &revoked);
    if (orc != BNS_OK) {
        char buf[256];
        snprintf(buf, sizeof(buf),
                 "revocation state unavailable (fail-closed): %s",
                 bns_err_name((bonsai_err_t)orc));
        return binding_fail(reason, reason_sz, buf);
    }
    /* (7) revoked => refuse. */
    if (revoked) {
        return binding_fail(reason, reason_sz,
            "identity is revoked/dissolved on-chain");
    }

    /* Envelope caps from the on-chain-verified params; scopes from the charter. */
    authorization_envelope_t envelope;
    if (envelope_from_identity(&args->params, args->scopes,
                               args->num_scopes, &envelope) != BNS_OK) {
        return BNS_ENOMEM;
    }

    key_broker_issue_args_t iargs = {
        .agent_pub_key  = args->agent_pub_key,
        .ricardian_hash = args->ricardian_hash,
        .identity_id    = args->identity_id,
        .envelope       = &envelope,
    };
    int rc = key_broker_issue(broker, &iargs, out_key, out_secret);
    authorization_envelope_free(&envelope);
    return rc;
}

/* ---- authorize ----------------------------------------------------------- */

/* Helper: fill a deny decision with a borrowed reason + optional keyId. */
static void decision_deny(authorization_decision_t *out, const char *reason,
                          const stored_key_t *sk)
{
    out->allowed    = false;
    out->reason     = reason;
    out->has_charge = false;
    memset(&out->charge, 0, sizeof(out->charge));
    if (sk) {
        out->has_key_id = true;
        snprintf(out->key_id, sizeof(out->key_id), "%s", sk->pub.key_id);
    } else {
        out->has_key_id = false;
        out->key_id[0] = '\0';
    }
}

int key_broker_authorize(key_broker_t *broker,
                         const authorization_request_t *req,
                         authorization_decision_t *out)
{
    if (!out) return BNS_EINVAL;
    memset(out, 0, sizeof(*out));
    if (!broker || !req) {
        decision_deny(out, "unknown or invalid key", NULL);
        return BNS_OK;
    }

    /* (1) key exists & secret matches (constant-time). null => deny, NO keyId. */
    stored_key_t *sk = lookup_by_secret(broker, req->secret);
    if (!sk) {
        decision_deny(out, "unknown or invalid key", NULL);
        return BNS_OK;
    }

    /* (2) revoked locally (latched). Short-circuits without re-consulting the
     * oracle — the kill switch must not silently un-latch. */
    if (sk->revoked_locally) {
        decision_deny(out, "key revoked", sk);
        return BNS_OK;
    }

    /* (3) on-chain revocation; oracle error => deny fail-closed. */
    bool revoked = false;
    int orc = broker->oracle->is_revoked(broker->oracle->ctx,
                                         sk->pub.identity_id, &revoked);
    if (orc != BNS_OK) {
        decision_deny(out, "on-chain revocation state unavailable (fail-closed)",
                      sk);
        return BNS_OK;
    }
    /* (4) revoked => latch revokedLocally=true + deny. */
    if (revoked) {
        sk->revoked_locally = true;
        decision_deny(out, "identity revoked on-chain", sk);
        return BNS_OK;
    }

    /* (5) scope must be in envelope.scopes. */
    bool in_scope = false;
    for (size_t i = 0; i < sk->pub.envelope.num_scopes; i++) {
        if (req->scope && strcmp(sk->pub.envelope.scopes[i], req->scope) == 0) {
            in_scope = true;
            break;
        }
    }
    if (!in_scope) {
        /* TS: `scope not authorised: ${req.scope}`. Stored in the broker so the
         * borrowed const char* the caller reads stays valid until next call. */
        snprintf(broker->scope_reason, sizeof(broker->scope_reason),
                 "scope not authorised: %s", req->scope ? req->scope : "");
        decision_deny(out, broker->scope_reason, sk);
        return BNS_OK;
    }

    /* (6) meter against the BROKER's clock (never a caller-supplied time). */
    charge_result_t charge;
    window_accountant_charge(&sk->accountant, req->amount, broker_now(broker),
                             &charge);
    if (!charge.allowed) {
        out->allowed    = false;
        out->reason     = charge.reason; /* static literal from accountant */
        out->has_key_id = true;
        snprintf(out->key_id, sizeof(out->key_id), "%s", sk->pub.key_id);
        out->charge     = charge;
        out->has_charge = true;
        return BNS_OK;
    }

    out->allowed    = true;
    out->reason     = NULL;
    out->has_key_id = true;
    snprintf(out->key_id, sizeof(out->key_id), "%s", sk->pub.key_id);
    out->charge     = charge;
    out->has_charge = true;
    return BNS_OK;
}

/* ---- revokeLocally / getKey ---------------------------------------------- */

bool key_broker_revoke_locally(key_broker_t *broker, const char *key_id)
{
    if (!broker) return false;
    stored_key_t *sk = find_by_key_id(broker, key_id);
    if (!sk) return false;
    sk->revoked_locally = true;
    return true;
}

int key_broker_get_key(const key_broker_t *broker, const char *key_id,
                       issued_key_t *out_key, bool *out_found)
{
    if (out_found) *out_found = false;
    if (out_key) memset(out_key, 0, sizeof(*out_key));
    if (!broker || !out_key || !out_found) return BNS_EINVAL;

    stored_key_t *sk = find_by_key_id(broker, key_id);
    if (!sk) {
        *out_found = false; /* TS null */
        return BNS_OK;
    }

    /* Sanitized public copy: fresh envelope + fresh scopes array (so a caller
     * cannot mutate the live caps/scopes). No secret material is exposed. */
    int rc = issued_key_build(out_key, sk->pub.key_id, sk->pub.agent_pub_key,
                              sk->pub.ricardian_hash, sk->pub.identity_id,
                              &sk->pub.envelope, sk->pub.created_at);
    if (rc != BNS_OK) return rc;

    *out_found = true;
    return BNS_OK;
}
