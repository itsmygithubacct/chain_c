/*
 * key_vault.h — the KeyVault contract plus an in-memory implementation: the
 * store of per-identity 32-byte AES-256 symmetric keys that makes
 * crypto-shredding possible. Destroying a key renders that identity's ciphertext
 * irrecoverable. Production replaces the in-memory vault with an HSM/KMS-backed
 * implementation of the same vtable.
 *
 * TS origin: src/privacy/keyVault.ts (KeyVault interface, InMemoryKeyVault).
 *
 * PINS (module notes):
 *  - KEY_LEN = 32 (AES-256). ensureKey is idempotent: returns the SAME existing
 *    key bytes if present (stable per-identity key across seal/sealAction).
 *  - shred zero-fills the 32 key bytes (OPENSSL_cleanse, not memset) BEFORE
 *    removal; returns whether a key was present.
 *  - getKey returns "absent" (not an error) when missing/shredded — the enclave
 *    distinguishes this as the erasure state.
 */
#ifndef BONSAI_PRIVACY_KEY_VAULT_H
#define BONSAI_PRIVACY_KEY_VAULT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"

/* AES-256 key length in bytes. TS: keyVault.ts KEY_LEN. */
#define BONSAI_KEY_VAULT_KEY_LEN 32

/* The key-store vtable: idempotent create-or-get, fetch-or-absent, destroy-
 * returns-had, existence check. A vtable so a KMS-backed C impl is a drop-in.
 * TS: keyVault.ts::KeyVault. */
typedef struct key_vault_s key_vault_t;
struct key_vault_s {
    void *ctx; /* implementation-private state */

    /* ensureKey(identityId): idempotent — create 32 CSPRNG bytes on first use,
     * else return the existing key, copied into out_key[32].
     * TS: KeyVault.ensureKey. BNS_OK / BNS_ECRYPTO / BNS_ENOMEM. */
    int (*ensure_key)(void *ctx, const char *identity_id,
                      uint8_t out_key[BONSAI_KEY_VAULT_KEY_LEN]);

    /* getKey(identityId): copy the existing key into out_key[32] and set
     * *out_found=true; set *out_found=false (BNS_OK) when absent/shredded (the
     * nullable). TS: KeyVault.getKey. BNS_OK. */
    int (*get_key)(void *ctx, const char *identity_id,
                   uint8_t out_key[BONSAI_KEY_VAULT_KEY_LEN], bool *out_found);

    /* shred(identityId): OPENSSL_cleanse the key bytes then remove; returns
     * (via *out_had) whether a key was present. TS: KeyVault.shred. BNS_OK. */
    int (*shred)(void *ctx, const char *identity_id, bool *out_had);

    /* has(identityId): existence check. Pure predicate. TS: KeyVault.has. */
    bool (*has)(void *ctx, const char *identity_id);
};

/* Construct an in-memory KeyVault (process-memory map<identityId,32-byte key>;
 * NOT for production). Populates `out_vtable` and stores private state behind
 * out_vtable->ctx. Release via in_memory_key_vault_free.
 * TS: new InMemoryKeyVault(). BNS_OK / BNS_ENOMEM. */
int in_memory_key_vault_new(key_vault_t *out_vtable);

/* Release an in-memory KeyVault's private state (cleanses all live keys first).
 * NULL-safe. */
void in_memory_key_vault_free(key_vault_t *vault);

#endif /* BONSAI_PRIVACY_KEY_VAULT_H */
