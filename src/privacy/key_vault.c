/*
 * key_vault.c — in-memory KeyVault: a process-memory map<identityId, 32-byte
 * AES-256 key>. The crypto-shred root: destroying a key renders that identity's
 * ciphertext irrecoverable. NOT for production (keys live in the heap).
 *
 * TS origin: src/privacy/keyVault.ts (InMemoryKeyVault).
 */
#include "privacy/key_vault.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h> /* OPENSSL_cleanse */

#include "crypto/rand.h"

/* A single map entry: identityId -> 32 key bytes. The map is a flat singly
 * linked list — identity counts here are tiny (per-agent) and order does not
 * affect any byte-exact output, so a list keeps the shred/cleanse semantics
 * obvious. */
typedef struct kv_entry_s {
    char              *identity_id;                         /* owned */
    uint8_t            key[BONSAI_KEY_VAULT_KEY_LEN];
    struct kv_entry_s *next;
} kv_entry_t;

typedef struct {
    kv_entry_t *head;
} kv_state_t;

/* Find the entry for identity_id, or NULL. */
static kv_entry_t *kv_find(kv_state_t *st, const char *identity_id)
{
    for (kv_entry_t *e = st->head; e; e = e->next) {
        if (strcmp(e->identity_id, identity_id) == 0) return e;
    }
    return NULL;
}

/* ensureKey: idempotent. Return the existing key bytes if present; else mint 32
 * CSPRNG bytes, store, and return those. TS: InMemoryKeyVault.ensureKey. */
static int kv_ensure_key(void *ctx, const char *identity_id,
                         uint8_t out_key[BONSAI_KEY_VAULT_KEY_LEN])
{
    kv_state_t *st = (kv_state_t *)ctx;
    if (!st || !identity_id || !out_key) return BNS_EINVAL;

    kv_entry_t *existing = kv_find(st, identity_id);
    if (existing) {
        memcpy(out_key, existing->key, BONSAI_KEY_VAULT_KEY_LEN);
        return BNS_OK;
    }

    kv_entry_t *e = calloc(1, sizeof(*e));
    if (!e) return BNS_ENOMEM;

    size_t idlen = strlen(identity_id);
    e->identity_id = malloc(idlen + 1);
    if (!e->identity_id) {
        free(e);
        return BNS_ENOMEM;
    }
    memcpy(e->identity_id, identity_id, idlen + 1);

    int rc = rand_bytes(e->key, BONSAI_KEY_VAULT_KEY_LEN);
    if (rc != BNS_OK) {
        OPENSSL_cleanse(e->key, BONSAI_KEY_VAULT_KEY_LEN);
        free(e->identity_id);
        free(e);
        return rc; /* BNS_ECRYPTO */
    }

    e->next = st->head;
    st->head = e;
    memcpy(out_key, e->key, BONSAI_KEY_VAULT_KEY_LEN);
    return BNS_OK;
}

/* getKey: copy the key and set *out_found=true; *out_found=false (BNS_OK) when
 * absent/shredded — the nullable. TS: InMemoryKeyVault.getKey. */
static int kv_get_key(void *ctx, const char *identity_id,
                      uint8_t out_key[BONSAI_KEY_VAULT_KEY_LEN], bool *out_found)
{
    kv_state_t *st = (kv_state_t *)ctx;
    if (!st || !identity_id || !out_key || !out_found) return BNS_EINVAL;

    kv_entry_t *e = kv_find(st, identity_id);
    if (!e) {
        *out_found = false;
        return BNS_OK;
    }
    memcpy(out_key, e->key, BONSAI_KEY_VAULT_KEY_LEN);
    *out_found = true;
    return BNS_OK;
}

/* shred: OPENSSL_cleanse the key bytes BEFORE removal; report whether a key was
 * present via *out_had. TS: InMemoryKeyVault.shred. */
static int kv_shred(void *ctx, const char *identity_id, bool *out_had)
{
    kv_state_t *st = (kv_state_t *)ctx;
    if (!st || !identity_id || !out_had) return BNS_EINVAL;

    kv_entry_t *prev = NULL;
    for (kv_entry_t *e = st->head; e; prev = e, e = e->next) {
        if (strcmp(e->identity_id, identity_id) == 0) {
            /* Best-effort zeroisation before drop (mirrors key.fill(0)). */
            OPENSSL_cleanse(e->key, BONSAI_KEY_VAULT_KEY_LEN);
            if (prev) prev->next = e->next;
            else st->head = e->next;
            free(e->identity_id);
            free(e);
            *out_had = true;
            return BNS_OK;
        }
    }
    *out_had = false;
    return BNS_OK;
}

/* has: existence check. TS: InMemoryKeyVault.has. */
static bool kv_has(void *ctx, const char *identity_id)
{
    kv_state_t *st = (kv_state_t *)ctx;
    if (!st || !identity_id) return false;
    return kv_find(st, identity_id) != NULL;
}

int in_memory_key_vault_new(key_vault_t *out_vtable)
{
    if (!out_vtable) return BNS_EINVAL;

    kv_state_t *st = calloc(1, sizeof(*st));
    if (!st) return BNS_ENOMEM;

    out_vtable->ctx        = st;
    out_vtable->ensure_key = kv_ensure_key;
    out_vtable->get_key    = kv_get_key;
    out_vtable->shred      = kv_shred;
    out_vtable->has        = kv_has;
    return BNS_OK;
}

void in_memory_key_vault_free(key_vault_t *vault)
{
    if (!vault || !vault->ctx) return;
    kv_state_t *st = (kv_state_t *)vault->ctx;

    kv_entry_t *e = st->head;
    while (e) {
        kv_entry_t *next = e->next;
        OPENSSL_cleanse(e->key, BONSAI_KEY_VAULT_KEY_LEN);
        free(e->identity_id);
        free(e);
        e = next;
    }
    free(st);
    vault->ctx = NULL;
}
