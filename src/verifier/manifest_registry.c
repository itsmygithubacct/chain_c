/*
 * manifest_registry.c — append-only, replay-on-boot manifest registry enforcing
 * PERSIST-THEN-COMMIT. Faithful port of src/verifier/manifestRegistry.ts.
 *
 * BYTE-EXACTNESS: the JSONL log line is JSON.stringify(record) + '\n' — a
 * COMPACT (no-whitespace) object in V8 insertion order. The TS source uses a
 * bare JSON.stringify(record) (NOT the ...,null,2 pretty form), so this emits
 * compact JSON via cJSON_PrintUnformatted (insertion order, ECMA-262 escaping).
 * installedAt is a JSON number; signerPubkey/publishRef keys are OMITTED when
 * absent (JSON.stringify drops undefined). The line+'\n' is written in a SINGLE
 * write(2) then fsync'd, BEFORE the in-memory store is mutated.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "verifier/manifest_registry.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "cJSON.h"

/* ---- in-memory store: insertion-ordered list (Map iteration order) ------- */

struct manifest_registry_s {
    manifest_record_t        *entries; /* owned records, insertion order */
    size_t                    count;
    size_t                    cap;
    char                     *log_path; /* owned, NULL => in-memory only */
    manifest_registry_clock_fn clock;
    void                     *clock_user;
};

/* ---- small helpers ------------------------------------------------------- */

static char *dup_str(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

/* Default clock: Math.floor(Date.now()/1000) == unix seconds. */
static int64_t default_now(void) { return (int64_t)time(NULL); }

static int64_t reg_now(const manifest_registry_t *reg) {
    if (reg->clock) return reg->clock(reg->clock_user);
    return default_now();
}

/* Locate an entry by id; returns index or -1. */
static long find_idx(const manifest_registry_t *reg, const char *id) {
    if (!id) return -1;
    for (size_t i = 0; i < reg->count; i++) {
        if (strcmp(reg->entries[i].extension_id, id) == 0) return (long)i;
    }
    return -1;
}

void manifest_record_free(manifest_record_t *rec) {
    if (!rec) return;
    free(rec->extension_id);
    free(rec->version);
    free(rec->source);
    free(rec->manifest_json);
    free(rec->signer_pubkey);
    free(rec->publish_ref);
    memset(rec, 0, sizeof(*rec));
}

void manifest_records_free(manifest_record_t *recs, size_t count) {
    if (!recs) return;
    for (size_t i = 0; i < count; i++) manifest_record_free(&recs[i]);
    free(recs);
}

/* Deep-copy src into dst (dst assumed zero/uninitialized). Returns BNS_ENOMEM
 * on failure (dst left partially populated; caller frees). */
static int record_copy(manifest_record_t *dst, const manifest_record_t *src) {
    dst->installed_at = src->installed_at;
    dst->extension_id  = dup_str(src->extension_id);
    dst->version       = dup_str(src->version);
    dst->source        = dup_str(src->source);
    dst->manifest_json = dup_str(src->manifest_json);
    /* optional fields: NULL stays NULL */
    dst->signer_pubkey = src->signer_pubkey ? dup_str(src->signer_pubkey) : NULL;
    dst->publish_ref   = src->publish_ref   ? dup_str(src->publish_ref)   : NULL;
    if (!dst->extension_id || !dst->version || !dst->source || !dst->manifest_json ||
        (src->signer_pubkey && !dst->signer_pubkey) ||
        (src->publish_ref && !dst->publish_ref)) {
        return BNS_ENOMEM;
    }
    return BNS_OK;
}

/* Append a record into the store by deep copy (preserving insertion order). */
static int store_push(manifest_registry_t *reg, const manifest_record_t *src) {
    if (reg->count == reg->cap) {
        size_t ncap = reg->cap ? reg->cap * 2 : 8;
        manifest_record_t *ne =
            (manifest_record_t *)realloc(reg->entries, ncap * sizeof(*ne));
        if (!ne) return BNS_ENOMEM;
        reg->entries = ne;
        reg->cap = ncap;
    }
    manifest_record_t *dst = &reg->entries[reg->count];
    memset(dst, 0, sizeof(*dst));
    int rc = record_copy(dst, src);
    if (rc != BNS_OK) {
        manifest_record_free(dst);
        return rc;
    }
    reg->count++;
    return BNS_OK;
}

/* Delete entry at idx, shifting to keep insertion order (Map.delete). */
static void store_delete_idx(manifest_registry_t *reg, size_t idx) {
    manifest_record_free(&reg->entries[idx]);
    for (size_t i = idx + 1; i < reg->count; i++) {
        reg->entries[i - 1] = reg->entries[i];
    }
    reg->count--;
}

/* ---- JSONL line building (byte-exact JSON.stringify) --------------------- */

/* Build the compact JSON line for an install record. Key order matches the TS
 * persist() object-literal:
 *   op, extensionId, version, source, [signerPubkey], [publishRef],
 *   installedAt(number), manifest(string).
 * Returns a malloc'd string (caller free) or NULL on OOM. */
static char *build_install_line(const manifest_record_t *rec) {
    cJSON *o = cJSON_CreateObject();
    if (!o) return NULL;
    cJSON *v;
    int ok;

    v = cJSON_CreateString("install");
    ok = v && cJSON_AddItemToObject(o, "op", v);

    if (ok) { v = cJSON_CreateString(rec->extension_id);
              ok = v && cJSON_AddItemToObject(o, "extensionId", v); }
    if (ok) { v = cJSON_CreateString(rec->version);
              ok = v && cJSON_AddItemToObject(o, "version", v); }
    if (ok) { v = cJSON_CreateString(rec->source);
              ok = v && cJSON_AddItemToObject(o, "source", v); }
    if (ok && rec->signer_pubkey) {
        v = cJSON_CreateString(rec->signer_pubkey);
        ok = v && cJSON_AddItemToObject(o, "signerPubkey", v);
    }
    if (ok && rec->publish_ref) {
        v = cJSON_CreateString(rec->publish_ref);
        ok = v && cJSON_AddItemToObject(o, "publishRef", v);
    }
    if (ok) {
        /* installedAt: emit an exact integer via Raw so int64 magnitudes that
         * exceed cJSON's int formatting still render byte-exactly. */
        char num[32];
        snprintf(num, sizeof(num), "%lld", (long long)rec->installed_at);
        v = cJSON_CreateRaw(num);
        ok = v && cJSON_AddItemToObject(o, "installedAt", v);
    }
    if (ok) { v = cJSON_CreateString(rec->manifest_json);
              ok = v && cJSON_AddItemToObject(o, "manifest", v); }

    char *out = NULL;
    if (ok) out = cJSON_PrintUnformatted(o);
    cJSON_Delete(o);
    return out;
}

/* {"op":"uninstall","extensionId":<id>} */
static char *build_uninstall_line(const char *extension_id) {
    cJSON *o = cJSON_CreateObject();
    if (!o) return NULL;
    int ok = 1;
    cJSON *v = cJSON_CreateString("uninstall");
    ok = v && cJSON_AddItemToObject(o, "op", v);
    if (ok) { v = cJSON_CreateString(extension_id);
              ok = v && cJSON_AddItemToObject(o, "extensionId", v); }
    char *out = NULL;
    if (ok) out = cJSON_PrintUnformatted(o);
    cJSON_Delete(o);
    return out;
}

/* ---- persist (open|write|fsync|close) ------------------------------------ */

/* Recursively mkdir the parent directory of `path` (mkdirSync recursive). */
static int mkdir_parents(const char *path) {
    char *copy = dup_str(path);
    if (!copy) return BNS_ENOMEM;
    /* strip to dirname */
    char *slash = strrchr(copy, '/');
    if (!slash) { free(copy); return BNS_OK; } /* no dir component */
    if (slash == copy) { free(copy); return BNS_OK; } /* root */
    *slash = '\0';
    /* walk components, creating each */
    for (char *p = copy + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(copy, 0777) != 0 && errno != EEXIST) { free(copy); return BNS_EPERSIST; }
            *p = '/';
        }
    }
    if (mkdir(copy, 0777) != 0 && errno != EEXIST) { free(copy); return BNS_EPERSIST; }
    free(copy);
    return BNS_OK;
}

/* persist(line): single combined write of `line`+'\n', then fsync, then close.
 * Mirrors TS persist(): mkdir parents, open 'a', write line+'\n', fsync, close;
 * any failure => BNS_EPERSIST. No-op (BNS_OK) when log_path is NULL. */
static int persist_line(manifest_registry_t *reg, const char *line) {
    if (!reg->log_path) return BNS_OK; /* in-memory mode */

    int rc = mkdir_parents(reg->log_path);
    if (rc != BNS_OK) return BNS_EPERSIST;

    /* Build line + '\n' into one buffer for a single write(2). */
    size_t llen = strlen(line);
    char *buf = (char *)malloc(llen + 2);
    if (!buf) return BNS_EPERSIST; /* persist failure surface */
    memcpy(buf, line, llen);
    buf[llen] = '\n';
    buf[llen + 1] = '\0';

    int fd = open(reg->log_path, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd < 0) { free(buf); return BNS_EPERSIST; }

    int err = 0;
    size_t total = llen + 1;
    size_t off = 0;
    while (off < total) {
        ssize_t w = write(fd, buf + off, total - off);
        if (w < 0) { if (errno == EINTR) continue; err = 1; break; }
        off += (size_t)w;
    }
    if (!err && fsync(fd) != 0) err = 1;
    if (close(fd) != 0) err = 1;
    free(buf);
    return err ? BNS_EPERSIST : BNS_OK;
}

/* ---- replay -------------------------------------------------------------- */

/* Read the whole file into a malloc'd NUL-terminated buffer. *out=NULL & BNS_OK
 * on ENOENT (first boot). BNS_EPERSIST on any other read error. */
static int read_whole_file(const char *path, char **out, size_t *out_len) {
    *out = NULL; *out_len = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) return BNS_OK; /* first boot, not an error */
        return BNS_EPERSIST;
    }
    size_t cap = 4096, len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) { close(fd); return BNS_EPERSIST; }
    for (;;) {
        if (len + 4096 + 1 > cap) {
            size_t ncap = cap * 2;
            char *nb = (char *)realloc(buf, ncap);
            if (!nb) { free(buf); close(fd); return BNS_EPERSIST; }
            buf = nb; cap = ncap;
        }
        ssize_t r = read(fd, buf + len, 4096);
        if (r < 0) { if (errno == EINTR) continue; free(buf); close(fd); return BNS_EPERSIST; }
        if (r == 0) break;
        len += (size_t)r;
    }
    close(fd);
    buf[len] = '\0';
    *out = buf; *out_len = len;
    return BNS_OK;
}

/* Apply one parsed log line to the store (replay semantics). Malformed/parse
 * failures are silently skipped by the caller. Returns BNS_ENOMEM only on OOM. */
static int apply_log_line(manifest_registry_t *reg, const char *line) {
    cJSON *rec = cJSON_Parse(line);
    if (!rec) return BNS_OK; /* malformed: skip (caller treats as skip) */
    int rc = BNS_OK;

    cJSON *op = cJSON_GetObjectItemCaseSensitive(rec, "op");
    const char *ops = cJSON_IsString(op) ? op->valuestring : NULL;

    if (ops && strcmp(ops, "install") == 0) {
        cJSON *id = cJSON_GetObjectItemCaseSensitive(rec, "extensionId");
        if (!cJSON_IsString(id)) goto done;            /* id must be a string */
        if (find_idx(reg, id->valuestring) >= 0) goto done; /* dedupe: first wins */

        cJSON *ver = cJSON_GetObjectItemCaseSensitive(rec, "version");
        cJSON *src = cJSON_GetObjectItemCaseSensitive(rec, "source");
        cJSON *sp  = cJSON_GetObjectItemCaseSensitive(rec, "signerPubkey");
        cJSON *pr  = cJSON_GetObjectItemCaseSensitive(rec, "publishRef");
        cJSON *man = cJSON_GetObjectItemCaseSensitive(rec, "manifest");
        cJSON *iat = cJSON_GetObjectItemCaseSensitive(rec, "installedAt");

        /* manifestJson = rec.manifest if string else JSON.stringify(rec.manifest). */
        char *man_json = NULL;
        int man_owned = 0;
        if (cJSON_IsString(man)) {
            man_json = man->valuestring;
        } else if (man) {
            man_json = cJSON_PrintUnformatted(man);
            man_owned = 1;
            if (!man_json) { rc = BNS_ENOMEM; goto done; }
        } else {
            man_json = (char *)""; /* JSON.stringify(undefined) is undefined; TS would
                                    * store the string "undefined" only if non-string &
                                    * present. Absent => empty stringification path. */
        }

        /* signerPubkey/publishRef: (x as string) || undefined — empty string
         * becomes undefined (omitted). */
        const char *sps = (cJSON_IsString(sp) && sp->valuestring[0]) ? sp->valuestring : NULL;
        const char *prs = (cJSON_IsString(pr) && pr->valuestring[0]) ? pr->valuestring : NULL;

        /* installedAt = Number(rec.installedAt) || 0 */
        int64_t iat_v = 0;
        if (cJSON_IsNumber(iat)) iat_v = (int64_t)iat->valuedouble;

        manifest_record_t tmp;
        memset(&tmp, 0, sizeof(tmp));
        tmp.extension_id  = id->valuestring;
        tmp.version       = cJSON_IsString(ver) ? ver->valuestring : NULL;
        tmp.source        = cJSON_IsString(src) ? src->valuestring : NULL;
        tmp.manifest_json = man_json;
        tmp.signer_pubkey = (char *)sps;
        tmp.publish_ref   = (char *)prs;
        tmp.installed_at  = iat_v;

        /* record_copy requires non-NULL version/source/manifest; coerce NULL to
         * "" so a partial line still replays (TS would set them to undefined,
         * which stringifies away — but our record stores owned strings). */
        if (!tmp.version) tmp.version = (char *)"";
        if (!tmp.source) tmp.source = (char *)"";
        if (!tmp.manifest_json) tmp.manifest_json = (char *)"";

        rc = store_push(reg, &tmp);
        if (man_owned) free(man_json);
    } else if (ops && strcmp(ops, "uninstall") == 0) {
        cJSON *id = cJSON_GetObjectItemCaseSensitive(rec, "extensionId");
        if (cJSON_IsString(id)) {
            long idx = find_idx(reg, id->valuestring);
            if (idx >= 0) store_delete_idx(reg, (size_t)idx);
        }
    }
done:
    cJSON_Delete(rec);
    return rc;
}

/* Replay the append-only log into memory. ENOENT => empty (first boot). */
static int replay(manifest_registry_t *reg) {
    char *buf = NULL;
    size_t len = 0;
    int rc = read_whole_file(reg->log_path, &buf, &len);
    if (rc != BNS_OK) return BNS_EPERSIST;
    if (!buf) return BNS_OK; /* ENOENT */

    /* split on '\n', skip zero-length lines, parse each. */
    char *p = buf;
    while (*p) {
        char *nl = strchr(p, '\n');
        size_t llen = nl ? (size_t)(nl - p) : strlen(p);
        if (llen > 0) {
            char *line = (char *)malloc(llen + 1);
            if (!line) { free(buf); return BNS_ENOMEM; }
            memcpy(line, p, llen);
            line[llen] = '\0';
            rc = apply_log_line(reg, line);
            free(line);
            if (rc == BNS_ENOMEM) { free(buf); return BNS_ENOMEM; }
        }
        if (!nl) break;
        p = nl + 1;
    }
    free(buf);
    return BNS_OK;
}

/* ---- public API ---------------------------------------------------------- */

int manifest_registry_new(const manifest_registry_opts_t *opts,
                          manifest_registry_t **out) {
    if (!out) return BNS_EINVAL;
    *out = NULL;
    manifest_registry_t *reg = (manifest_registry_t *)calloc(1, sizeof(*reg));
    if (!reg) return BNS_ENOMEM;

    if (opts) {
        reg->clock = opts->clock;
        reg->clock_user = opts->clock_user;
        if (opts->log_path) {
            reg->log_path = dup_str(opts->log_path);
            if (!reg->log_path) { free(reg); return BNS_ENOMEM; }
        }
    }

    if (reg->log_path) {
        int rc = replay(reg);
        if (rc != BNS_OK) {
            manifest_registry_free(reg);
            return rc;
        }
    }
    *out = reg;
    return BNS_OK;
}

void manifest_registry_free(manifest_registry_t *reg) {
    if (!reg) return;
    for (size_t i = 0; i < reg->count; i++) manifest_record_free(&reg->entries[i]);
    free(reg->entries);
    free(reg->log_path);
    free(reg);
}

int manifest_registry_install(manifest_registry_t *reg,
                              const manifest_install_args_t *args,
                              manifest_record_t *out_rec) {
    if (!reg || !args) return BNS_EINVAL;

    /* DUPLICATE precheck against in-memory map BEFORE persist. */
    if (find_idx(reg, args->extension_id) >= 0) return BNS_EINVAL;

    /* full record: installedAt defaults to now() when not provided. */
    manifest_record_t full;
    memset(&full, 0, sizeof(full));
    full.extension_id  = (char *)args->extension_id;
    full.version       = (char *)args->version;
    full.source        = (char *)args->source;
    full.manifest_json = (char *)args->manifest_json;
    full.signer_pubkey = (char *)args->signer_pubkey;
    full.publish_ref   = (char *)args->publish_ref;
    full.installed_at  = args->has_installed_at ? args->installed_at : reg_now(reg);

    /* PERSIST-THEN-COMMIT: write+fsync the log line BEFORE mutating memory. */
    char *line = build_install_line(&full);
    if (!line) return BNS_ENOMEM;
    int rc = persist_line(reg, line);
    free(line);
    if (rc != BNS_OK) return rc; /* failed-but-active install never happens */

    /* Only after a durable write do we make it visible. */
    rc = store_push(reg, &full);
    if (rc != BNS_OK) return rc;

    if (out_rec) {
        memset(out_rec, 0, sizeof(*out_rec));
        rc = record_copy(out_rec, &reg->entries[reg->count - 1]);
        if (rc != BNS_OK) { manifest_record_free(out_rec); return rc; }
    }
    return BNS_OK;
}

int manifest_registry_uninstall(manifest_registry_t *reg,
                                const char *extension_id) {
    if (!reg) return BNS_EINVAL;

    /* NOTFOUND precheck against in-memory map BEFORE persist. */
    long idx = find_idx(reg, extension_id);
    if (idx < 0) return BNS_ENOTFOUND;

    /* PERSIST-THEN-COMMIT: log the removal BEFORE mutating memory. */
    char *line = build_uninstall_line(extension_id);
    if (!line) return BNS_ENOMEM;
    int rc = persist_line(reg, line);
    free(line);
    if (rc != BNS_OK) return rc; /* durable removal failed => still installed */

    store_delete_idx(reg, (size_t)idx);
    return BNS_OK;
}

int manifest_registry_get(const manifest_registry_t *reg,
                          const char *extension_id,
                          manifest_record_t *out_rec, bool *out_found) {
    if (out_found) *out_found = false;
    if (!reg || !out_rec) return BNS_EINVAL;
    memset(out_rec, 0, sizeof(*out_rec));

    long idx = find_idx(reg, extension_id);
    if (idx < 0) return BNS_OK; /* absent => found=false (TS null) */

    int rc = record_copy(out_rec, &reg->entries[idx]);
    if (rc != BNS_OK) { manifest_record_free(out_rec); return rc; }
    if (out_found) *out_found = true;
    return BNS_OK;
}

int manifest_registry_list(const manifest_registry_t *reg,
                           manifest_record_t **out_recs, size_t *out_count) {
    if (!reg || !out_recs || !out_count) return BNS_EINVAL;
    *out_recs = NULL;
    *out_count = 0;
    if (reg->count == 0) return BNS_OK;

    manifest_record_t *arr =
        (manifest_record_t *)calloc(reg->count, sizeof(*arr));
    if (!arr) return BNS_ENOMEM;

    for (size_t i = 0; i < reg->count; i++) {
        int rc = record_copy(&arr[i], &reg->entries[i]);
        if (rc != BNS_OK) {
            manifest_records_free(arr, i + 1);
            return rc;
        }
    }
    *out_recs = arr;
    *out_count = reg->count;
    return BNS_OK;
}

size_t manifest_registry_count(const manifest_registry_t *reg) {
    return reg ? reg->count : 0;
}
