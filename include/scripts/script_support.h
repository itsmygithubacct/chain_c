/*
 * script_support.h — shared helpers for the chain_c CLI scripts under bin/.
 *
 * Centralises the env-var / key-file / dry-run conventions the TS scripts repeat
 * (deploy.ts, cpfp.ts, agentd.ts, ...) so every C CLI behaves identically:
 *   - $BONSAI_NOTARY_HOME resolution (default $HOME/.local/trinote)
 *   - required/optional env vars with verbatim "Set <NAME>" errors
 *   - key files: JSON {wif, address}, with WIF<->address verification
 *   - the CONFIRM_MAINNET_BROADCAST=yes dry-run safety gate
 */
#ifndef BONSAI_SCRIPTS_SCRIPT_SUPPORT_H
#define BONSAI_SCRIPTS_SCRIPT_SUPPORT_H

#include <stdbool.h>
#include "common/error.h"
#include "bsv/address.h"   /* bsv_network_t */

/* $BONSAI_NOTARY_HOME, or "$HOME/.local/trinote" (or "./.local/trinote" if no
 * $HOME). Returns a pointer to a static buffer (not thread-safe; fine for CLIs). */
const char *bonsai_home(void);

/* getenv(name) (may be NULL). */
const char *env_get(const char *name);

/* getenv(name) or dflt if unset/empty. */
const char *env_or(const char *name, const char *dflt);

/* Required env var. On missing/empty: bns_fail(err, BNS_EINVAL, "Set %s", name)
 * (mirrors the TS `Set <NAME>` throw) and returns that code; else *out is set
 * to the value and returns BNS_OK. */
int env_require(const char *name, const char **out, bonsai_err_ctx *err);

/* The mainnet broadcast safety gate: true iff CONFIRM_MAINNET_BROADCAST == "yes"
 * exactly. Every script DRY-RUNS unless this returns true. */
bool confirm_mainnet_broadcast(void);

/* A funded key file: JSON object {"wif": "...", "address": "..."}. */
typedef struct {
    char *wif;       /* owned */
    char *address;   /* owned */
} key_file_t;

/* Load + parse a key file. BNS_OK / BNS_EPERSIST (read) / BNS_EPARSE (json or
 * missing fields). On success the caller owns *kf and must key_file_free it. */
int key_file_load(const char *path, key_file_t *kf, bonsai_err_ctx *err);

/* Free owned strings (safe on a zeroed struct). */
void key_file_free(key_file_t *kf);

/* Verify kf->wif derives kf->address on `net`. On mismatch:
 * bns_fail(err, BNS_EBINDING, "WIF/address mismatch") and returns it. */
int key_file_verify(const key_file_t *kf, bsv_network_t net, bonsai_err_ctx *err);

#endif /* BONSAI_SCRIPTS_SCRIPT_SUPPORT_H */
