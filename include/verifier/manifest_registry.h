/*
 * manifest_registry.h — append-only, replay-on-boot manifest registry enforcing
 * PERSIST-THEN-COMMIT: the durable JSONL log line is written and fsync'd to disk
 * BEFORE the in-memory store is mutated, so a write failure can never leave a
 * failed-but-active install. Authoritative install/uninstall store for verified
 * release manifests.
 *
 * TS origin: src/verifier/manifestRegistry.ts (ManifestRecord,
 * DuplicateExtensionError, NotFoundError, PersistError, ManifestRegistryOpts,
 * ManifestRegistry).
 *
 * BYTE-EXACTNESS PINS (module notes — JSONL must byte-match the TS producer):
 *  - LOG LINE: persist() writes JSON.stringify(record) + '\n' in a SINGLE
 *    write(2) (no torn-line window). install record key ORDER:
 *    {"op":"install","extensionId":...,"version":...,"source":...,
 *     "signerPubkey":...,"publishRef":...,"installedAt":<number>,
 *     "manifest":<manifestJson string>}. signerPubkey/publishRef keys are
 *    OMITTED entirely when absent (JSON.stringify drops undefined — emit NOTHING,
 *    not null). installedAt is a JSON NUMBER. uninstall record:
 *    {"op":"uninstall","extensionId":...}.
 *  - PERSIST-THEN-COMMIT: persist() (open|write|fsync|close) MUST fully succeed
 *    BEFORE the in-memory map is mutated. fsync is non-negotiable.
 *  - REPLAY: read whole file utf8, split on '\n', skip empty lines, JSON.parse
 *    each (malformed lines silently skipped). install sets entry only if id is a
 *    string AND not already present (first surviving line wins); uninstall
 *    deletes. ENOENT => empty registry (first boot, NOT an error).
 *  - DUPLICATE/NOTFOUND precheck against the in-memory map BEFORE persist.
 *  - list() iteration order is INSERTION order.
 */
#ifndef BONSAI_VERIFIER_MANIFEST_REGISTRY_H
#define BONSAI_VERIFIER_MANIFEST_REGISTRY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"

/* One installed manifest entry. Optional fields (signer_pubkey/publish_ref) are
 * NULL when absent (omitted from the JSONL line). All strings OWNED by the
 * record when returned via get()/list(). TS: manifestRegistry.ts::ManifestRecord. */
typedef struct {
    char   *extension_id;  /* owned */
    char   *version;       /* owned */
    char   *source;        /* owned */
    char   *manifest_json; /* owned canonical stringified manifest */
    char   *signer_pubkey; /* owned or NULL (optional)             */
    char   *publish_ref;   /* owned or NULL (optional)             */
    int64_t installed_at;  /* unix seconds                         */
} manifest_record_t;

/* Input to install(): like manifest_record_t but installed_at is optional
 * (has_installed_at=false => default to now()). Strings borrowed (the registry
 * deep-copies into its owned record). TS: Omit<ManifestRecord,'installedAt'> &
 * {installedAt?}. */
typedef struct {
    const char *extension_id;
    const char *version;
    const char *source;
    const char *manifest_json;
    const char *signer_pubkey;          /* NULL => omitted */
    const char *publish_ref;            /* NULL => omitted */
    int64_t     installed_at; bool has_installed_at;
} manifest_install_args_t;

/* Free the owned members of a manifest_record_t and zero it (NULL-safe). Used to
 * release records returned by manifest_registry_get / _list. */
void manifest_record_free(manifest_record_t *rec);

/* Free a list of records returned by manifest_registry_list (NULL-safe). */
void manifest_records_free(manifest_record_t *recs, size_t count);

/* Injectable clock returning unix seconds. NULL => Math.floor(Date.now()/1000).
 * TS: ManifestRegistryOpts.now. */
typedef int64_t (*manifest_registry_clock_fn)(void *user);

/* Construction options. `log_path` NULL => pure in-memory mode (no replay, no
 * persist). TS: manifestRegistry.ts::ManifestRegistryOpts. */
typedef struct {
    const char                *log_path;     /* NULL => in-memory only        */
    manifest_registry_clock_fn clock;        /* NULL => wall-clock seconds    */
    void                      *clock_user;
} manifest_registry_opts_t;

/* Opaque registry handle (replays the log on construction when log_path set).
 * TS: manifestRegistry.ts::ManifestRegistry. */
typedef struct manifest_registry_s manifest_registry_t;

/* Construct a registry; replays log_path if set. `opts` may be NULL (in-memory,
 * wall clock). *out freed via manifest_registry_free.
 * TS: new ManifestRegistry(opts). BNS_OK / BNS_EPERSIST / BNS_ENOMEM. */
int manifest_registry_new(const manifest_registry_opts_t *opts,
                          manifest_registry_t **out);

/* Release the registry and its in-memory store (NULL-safe). */
void manifest_registry_free(manifest_registry_t *reg);

/* Install: precheck duplicate against the in-memory map (=> BNS_EINVAL, the
 * DuplicateExtensionError equivalent), persist-then-commit (fsync before
 * mutate), then return the stored record via *out_rec (owned; release via
 * manifest_record_free). installed_at defaults to now() when not provided.
 * TS: ManifestRegistry.install.
 * BNS_OK / BNS_EINVAL (duplicate) / BNS_EPERSIST / BNS_ENOMEM. */
int manifest_registry_install(manifest_registry_t *reg,
                              const manifest_install_args_t *args,
                              manifest_record_t *out_rec);

/* Uninstall: precheck presence (=> BNS_ENOTFOUND, the NotFoundError equivalent),
 * persist-then-commit, then delete from the map. TS: ManifestRegistry.uninstall.
 * BNS_OK / BNS_ENOTFOUND / BNS_EPERSIST. */
int manifest_registry_uninstall(manifest_registry_t *reg,
                                const char *extension_id);

/* Get a copy of an installed record via *out_rec (owned; release via
 * manifest_record_free); *out_found=false when absent (TS null).
 * TS: ManifestRegistry.get. BNS_OK / BNS_ENOMEM. */
int manifest_registry_get(const manifest_registry_t *reg,
                          const char *extension_id,
                          manifest_record_t *out_rec, bool *out_found);

/* List all records in INSERTION order via *out_recs (owned array of `*out_count`
 * records; release via manifest_records_free). TS: ManifestRegistry.list.
 * BNS_OK / BNS_ENOMEM. */
int manifest_registry_list(const manifest_registry_t *reg,
                           manifest_record_t **out_recs, size_t *out_count);

/* Number of installed records. TS: ManifestRegistry.count. */
size_t manifest_registry_count(const manifest_registry_t *reg);

#endif /* BONSAI_VERIFIER_MANIFEST_REGISTRY_H */
