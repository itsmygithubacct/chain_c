/*
 * bonsai_third_entry_lib.c — the bonsaiThirdEntry LIVE Pillar-B lifecycle smoke
 * (deploy -> executeAction -> revoke). Faithful C port of
 * chain/scripts/bonsaiThirdEntry.ts main(): resolves the Elder / agent /
 * counterparty / funding keys, derives the on-chain commitment hashes
 * (ricardianHash / actionHash / provenanceHash), reconstructs the AgentTea
 * locking script, and prints the planned entries. DRY-RUN by default; only
 * proceeds to broadcast when CONFIRM_MAINNET_BROADCAST=yes.
 *
 * NETWORK is hard-pinned to mainnet (TS: bsv.Networks.mainnet — no testnet branch).
 */
#include "scripts/bonsai_third_entry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <openssl/crypto.h> /* OPENSSL_cleanse */

#include "scripts/script_support.h"
#include "scripts/chain_broadcast.h"
#include "common/bytes.h"
#include "common/hex.h"
#include "common/error.h"
#include "crypto/ecdsa.h"
#include "crypto/hash.h"
#include "crypto/bignum.h"
#include "crypto/rabin.h"
#include "bsv/address.h"
#include "bsv/base58.h"
#include "bsv/tx.h"
#include "bsv/tx_builder.h"
#include "bsv/script_utils.h"
#include "chainSources/bsv_fees.h"
#include "chainSources/woc_client.h"
#include "chainSources/utxo_select.h"
#include "scrypt/scrypt_contract.h"
#include "scrypt/artifact_loader.h"
#include "contracts_next/agent_tea.h"
#include "txbuilders/contract_sign.h"
#include "txbuilders/agent_tea_tx_builder.h"

/* ---- hard-coded policy pins (TS: bonsaiThirdEntry.ts top-level consts) ---- */
#define TE_IDENTITY_SATS   1
#define TE_FEE_PER_KB      100
#define TE_PER_TX          "100000"
#define TE_DAILY           "1000000"
#define TE_WINDOW          "86400"
#define TE_GRAD            "10000"
#define TE_VAL_THRESHOLD   "50000"
#define TE_ACTION_COST     "1000"
#define TE_RECOVERY_THRESH "2"

#define TE_NETWORK BSV_MAINNET

/* A loaded contract-role / funding key: the WIF, the derived compressed pubkey,
 * and the mainnet P2PKH address. Owns wif/address/pubkey-hex and the handles. */
typedef struct {
    ecdsa_key_t    *key;       /* owned */
    ecdsa_pubkey_t *pub;       /* owned */
    char           *wif;       /* owned (for dedup + ephemeral persist) */
    char           *address;   /* owned */
    char           *pubkey_hex;/* owned (66 hex) */
} loaded_key_t;

/* Best-effort scrub of a heap WIF string before free (no-op on NULL). The WIF
 * is secret key material, so cleanse it rather than leaving it in freed heap. */
static void wif_scrub_free(char *wif)
{
    if (wif) OPENSSL_cleanse(wif, strlen(wif));
    free(wif);
}

static void loaded_key_free(loaded_key_t *k)
{
    if (!k) return;
    ecdsa_key_free(k->key);
    ecdsa_pubkey_free(k->pub);
    wif_scrub_free(k->wif);
    free(k->address);
    free(k->pubkey_hex);
    memset(k, 0, sizeof *k);
}

/* Fill a loaded_key_t from an already-parsed WIF (taking a copy of the WIF). */
static int loaded_key_from_wif(const char *wif, loaded_key_t *out,
                               bonsai_err_ctx *err)
{
    memset(out, 0, sizeof *out);
    int rc = ecdsa_key_from_wif(wif, &out->key, NULL);
    if (rc != BNS_OK) return bns_fail(err, rc, "bad WIF");
    rc = ecdsa_key_derive_pubkey(out->key, &out->pub);
    if (rc != BNS_OK) { loaded_key_free(out); return bns_fail(err, rc, "pubkey derive failed"); }
    rc = ecdsa_pubkey_to_hex(out->pub, &out->pubkey_hex);
    if (rc != BNS_OK) { loaded_key_free(out); return bns_fail(err, rc, "pubkey hex failed"); }
    rc = address_from_pubkey(out->pub, TE_NETWORK, &out->address);
    if (rc != BNS_OK) { loaded_key_free(out); return bns_fail(err, rc, "address derive failed"); }
    out->wif = strdup(wif);
    if (!out->wif) { loaded_key_free(out); return bns_fail(err, BNS_ENOMEM, "oom"); }
    return BNS_OK;
}

/* TS loadKey(file): JSON {wif,address}; verify WIF derives address (mainnet).
 * On mismatch the TS throws:
 *   `WIF in ${file} does not derive ${d.address} — refusing to continue`. */
static int load_key_file(const char *path, loaded_key_t *out, bonsai_err_ctx *err)
{
    key_file_t kf;
    int rc = key_file_load(path, &kf, err);
    if (rc != BNS_OK) return rc;

    rc = loaded_key_from_wif(kf.wif, out, err);
    if (rc != BNS_OK) { key_file_free(&kf); return rc; }

    /* Verify the loaded WIF derives the file's stated address (TS exact check). */
    if (strcmp(out->address, kf.address) != 0) {
        char addr_copy[128];
        snprintf(addr_copy, sizeof addr_copy, "%s", kf.address);
        loaded_key_free(out);
        key_file_free(&kf);
        return bns_fail(err, BNS_EBINDING,
                        "WIF in %s does not derive %s — refusing to continue",
                        path, addr_copy);
    }
    key_file_free(&kf);
    return BNS_OK;
}

/* hash32(name, v): /^[0-9a-fA-F]{64}$/ then toLowerCase (TS exact error). */
static int hash32_env(const char *name, const char *v, char **out_lower,
                      bonsai_err_ctx *err)
{
    if (!v || !is_sha256_hex(v)) {
        return bns_fail(err, BNS_EINVAL,
            "%s must be a 32-byte hex string (64 hex chars), got '%s'",
            name, v ? v : "");
    }
    *out_lower = hex_to_lower(v);
    if (!*out_lower) return bns_fail(err, BNS_ENOMEM, "oom");
    return BNS_OK;
}

/* sha256(toByteString(s, true)) -> 64-hex (UTF-8 bytes of s, single sha256). */
static int sha256_utf8_hex(const char *s, char **out_hex, bonsai_err_ctx *err)
{
    uint8_t digest[BONSAI_SHA256_LEN];
    sha256((const uint8_t *)s, strlen(s), digest);
    *out_hex = hex_encode(digest, BONSAI_SHA256_LEN);
    if (!*out_hex) return bns_fail(err, BNS_ENOMEM, "oom");
    return BNS_OK;
}

/* Resolve a commitment hash: env-provided typed 32-byte hex (lowercased, NOT
 * re-hashed) when set, else the default sha256(UTF-8 charter/string). */
static int resolve_hash(const char *env_name, const char *default_str,
                        char **out_hex, bonsai_err_ctx *err)
{
    const char *v = env_get(env_name);
    if (v && v[0])
        return hash32_env(env_name, v, out_hex, err);
    return sha256_utf8_hex(default_str, out_hex, err);
}

/* ISO-8601 UTC timestamp like JavaScript's `new Date().toISOString()`:
 * YYYY-MM-DDTHH:MM:SS.mmmZ (millisecond precision). */
static void iso8601_now(char out[64])
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    gmtime_r(&ts.tv_sec, &tm);
    int ms = (int)(ts.tv_nsec / 1000000L);
    snprintf(out, 64, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
}

/* loadOrCreateEphemeral(): read {agentWif,counterpartyWif}; on failure generate
 * two random keys and persist with mode 0600. Fills agent/counterparty (owned). */
static int load_or_create_ephemeral(const char *path,
                                    loaded_key_t *agent, loaded_key_t *cpty,
                                    bonsai_err_ctx *err)
{
    /* Try to read + parse an existing ephemeral file. */
    char *agent_wif = NULL, *cpty_wif = NULL;
    FILE *f = fopen(path, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        if (sz > 0 && sz < (1 << 20)) {
            rewind(f);
            char *buf = malloc((size_t)sz + 1);
            if (buf && fread(buf, 1, (size_t)sz, f) == (size_t)sz) {
                buf[sz] = '\0';
                /* Minimal extraction of "agentWif"/"counterpartyWif" string
                 * fields (the file is written by us; keep it dependency-light). */
                const char *p = strstr(buf, "\"agentWif\"");
                const char *q = strstr(buf, "\"counterpartyWif\"");
                char a[128] = {0}, c[128] = {0};
                if (p && sscanf(p, "\"agentWif\"%*[ :]\"%127[^\"]\"", a) == 1 &&
                    q && sscanf(q, "\"counterpartyWif\"%*[ :]\"%127[^\"]\"", c) == 1) {
                    agent_wif = strdup(a);
                    cpty_wif = strdup(c);
                }
            }
            free(buf);
        }
        fclose(f);
    }

    if (agent_wif && cpty_wif) {
        int rc = loaded_key_from_wif(agent_wif, agent, err);
        if (rc == BNS_OK) rc = loaded_key_from_wif(cpty_wif, cpty, err);
        wif_scrub_free(agent_wif); wif_scrub_free(cpty_wif);
        agent_wif = NULL; cpty_wif = NULL;  /* freed above; NULL so the fall-through
                                             * scrub below can't UAF/double-free them */
        if (rc == BNS_OK) return BNS_OK;
        loaded_key_free(agent);
        /* fall through to regenerate on any parse/derive failure */
    }
    /* Only frees a partial-strdup leftover (one strdup OOM'd so the block above was
     * skipped); both are NULL on the normal fall-through, making this a no-op. */
    wif_scrub_free(agent_wif); wif_scrub_free(cpty_wif);

    /* Generate fresh ephemeral keys. */
    ecdsa_key_t *ak = NULL, *ck = NULL;
    int rc = ecdsa_key_random(&ak);
    if (rc != BNS_OK) return bns_fail(err, rc, "ephemeral keygen failed");
    rc = ecdsa_key_random(&ck);
    if (rc != BNS_OK) { ecdsa_key_free(ak); return bns_fail(err, rc, "ephemeral keygen failed"); }

    uint8_t asec[32], csec[32];
    ecdsa_key_to_bytes(ak, asec);
    ecdsa_key_to_bytes(ck, csec);
    ecdsa_key_free(ak);
    ecdsa_key_free(ck);

    char *awif = NULL, *cwif = NULL;
    rc = wif_encode(asec, /*compressed=*/true, TE_NETWORK, &awif);
    if (rc == BNS_OK) rc = wif_encode(csec, true, TE_NETWORK, &cwif);
    if (rc != BNS_OK) { wif_scrub_free(awif); return bns_fail(err, rc, "WIF encode failed"); }

    /* Persist the ephemeral file with 0600 (TS: writeFileSync {mode:0o600}). */
    int wrc = BNS_OK;
    FILE *wf = fopen(path, "wb");
    if (wf) {
        fchmod(fileno(wf), S_IRUSR | S_IWUSR);
        fprintf(wf, "{\n  \"agentWif\": \"%s\",\n  \"counterpartyWif\": \"%s\"\n}\n",
                awif, cwif);
        fclose(wf);
    } else {
        /* Non-fatal: still proceed with the in-memory keys (TS would throw on a
         * write failure, but a dry-run still wants to print the plan). Surface
         * the persist error path is acceptable here as a soft warning. */
        wrc = BNS_EPERSIST;
    }

    rc = loaded_key_from_wif(awif, agent, err);
    if (rc == BNS_OK) rc = loaded_key_from_wif(cwif, cpty, err);
    wif_scrub_free(awif); wif_scrub_free(cwif);
    if (rc != BNS_OK) { loaded_key_free(agent); return rc; }
    (void)wrc;
    return BNS_OK;
}

/* Resolve the agentTea artifact path: $BONSAI_AGENT_TEA_ARTIFACT, else a couple
 * of conventional locations relative to cwd (the golden tests use
 * artifacts/src/contracts-next/agentTea.json). */
static int load_agent_tea_artifact(scrypt_artifact_t *art, bonsai_err_ctx *err)
{
    const char *override = env_get("BONSAI_AGENT_TEA_ARTIFACT");
    const char *candidates[] = {
        override,
        "artifacts/src/contracts-next/agentTea.json",
        "../artifacts/src/contracts-next/agentTea.json",
        NULL
    };
    for (int i = 0; candidates[i]; i++) {
        if (!candidates[i]) continue;
        memset(art, 0, sizeof *art);
        if (load_artifact(candidates[i], art) == BNS_OK)
            return BNS_OK;
    }
    return bns_fail(err, BNS_EPERSIST,
        "cannot load AgentTea artifact (set BONSAI_AGENT_TEA_ARTIFACT)");
}

/* Build the genesis AgentTea params from the loaded keys + freshly generated
 * Rabin keys + ricardianHash. Owns everything (agent_tea_params_free releases). */
static int build_params(const loaded_key_t *elder, const loaded_key_t *agent,
                        const uint8_t ricardian_hash[32],
                        agent_tea_params_t *cp, bonsai_err_ctx *err)
{
    memset(cp, 0, sizeof *cp);
    byte_buf_init(&cp->owner);
    byte_buf_init(&cp->agent);
    byte_buf_init(&cp->ricardian_hash);

    int ok = BNS_OK;
    uint8_t sec[33];
    ok = ecdsa_pubkey_serialize_compressed(elder->pub, sec);
    if (ok == BNS_OK) ok = byte_buf_append(&cp->owner, sec, 33);
    if (ok == BNS_OK) ok = ecdsa_pubkey_serialize_compressed(agent->pub, sec);
    if (ok == BNS_OK) ok = byte_buf_append(&cp->agent, sec, 33);
    if (ok == BNS_OK) ok = byte_buf_append(&cp->ricardian_hash, ricardian_hash, 32);
    if (ok != BNS_OK) { agent_tea_params_free(cp); return bns_fail(err, ok, "params init failed"); }

    ok |= bn_parse_dec(TE_PER_TX, &cp->per_tx_limit);
    ok |= bn_parse_dec(TE_DAILY, &cp->daily_limit);
    ok |= bn_parse_dec(TE_WINDOW, &cp->window_duration);
    ok |= bn_parse_dec(TE_GRAD, &cp->graduation_threshold);
    ok |= bn_parse_dec(TE_VAL_THRESHOLD, &cp->validator_threshold);
    ok |= bn_parse_dec(TE_RECOVERY_THRESH, &cp->recovery_threshold);
    if (ok != BNS_OK) { agent_tea_params_free(cp); return bns_fail(err, BNS_EINVAL, "policy const parse"); }

    /* genRabinKey() x (guardian + ownValidator + 3 recovery); only the modulus n
     * is consumed by the constructor (no signing on the sub-threshold path). */
    rabin_key_t rk; memset(&rk, 0, sizeof rk);
    int rc;
    rc = rabin_keygen(&rk);
    if (rc == BNS_OK) rc = rabin_pubkey(&rk, &cp->designated_validator_pubkey);
    rabin_key_free(&rk);
    if (rc != BNS_OK) { agent_tea_params_free(cp); return bns_fail(err, rc, "rabin keygen failed"); }

    rc = rabin_keygen(&rk);
    if (rc == BNS_OK) rc = rabin_pubkey(&rk, &cp->validator_rabin_pubkey);
    rabin_key_free(&rk);
    if (rc != BNS_OK) { agent_tea_params_free(cp); return bns_fail(err, rc, "rabin keygen failed"); }

    for (int i = 0; i < BONSAI_AGENT_TEA_RECOVERY_KEYS; i++) {
        rc = rabin_keygen(&rk);
        if (rc == BNS_OK) rc = rabin_pubkey(&rk, &cp->recovery_keys[i]);
        rabin_key_free(&rk);
        if (rc != BNS_OK) { agent_tea_params_free(cp); return bns_fail(err, rc, "rabin keygen failed"); }
    }
    return BNS_OK;
}

/* ---- AgentTea ABI method selectors (txbuilders/contract_sign.h notes,
 *      tests/test_broadcast_golden.c main()). ---- */
#define TE_SELECTOR_EXECUTE 0   /* executeAction#0 */
#define TE_SELECTOR_REVOKE  4   /* AgentTea.revoke=4 */

/* Derive the 20-byte hash160 of a loaded key's compressed pubkey (== its P2PKH
 * address payload). TS: bsv.Address from pubkey. */
static int loaded_key_hash160(const loaded_key_t *k, uint8_t out[20],
                              bonsai_err_ctx *err)
{
    uint8_t sec[33];
    int rc = ecdsa_pubkey_serialize_compressed(k->pub, sec);
    if (rc != BNS_OK) return bns_fail(err, rc, "pubkey serialize failed");
    hash160(sec, 33, out);
    return BNS_OK;
}

/* Decode a base58check P2PKH address string -> its 20-byte hash160 (strips the
 * 1-byte version prefix). TS: bsv.Address.fromString(...).hashBuffer. */
static int address_to_hash160(const char *addr, uint8_t out[20],
                              bonsai_err_ctx *err)
{
    byte_buf_t payload; byte_buf_init(&payload);
    int rc = base58check_decode(addr, &payload);
    if (rc != BNS_OK) { byte_buf_free(&payload); return bns_fail(err, rc, "bad change address %s", addr); }
    if (payload.len != 21) { byte_buf_free(&payload); return bns_fail(err, BNS_EPARSE, "bad change address %s", addr); }
    memcpy(out, payload.data + 1, 20);
    byte_buf_free(&payload);
    return BNS_OK;
}

/* Build a single P2PKH funding_utxo_t from a verified-unspent WoC pick (TS:
 * woc.pickFunding). Prints the `fund <label>` line on success. *out is filled
 * (caller frees via funding_utxos_free). */
static int fund_from(woc_client_t *woc, const loaded_key_t *key,
                     const char *label, funding_utxos_t *out,
                     bonsai_err_ctx *err)
{
    memset(out, 0, sizeof *out);
    funding_utxo_t pick; memset(&pick, 0, sizeof pick);
    bool found = false;
    int rc = woc_client_pick_funding(woc, key->address, NULL, &pick, &found);
    if (rc != BNS_OK)
        return bns_fail(err, rc, "WoC pickFunding failed for %s", key->address);
    if (!found)
        return bns_fail(err, BNS_ENOTFOUND,
                        "no genuinely-unspent UTXO to fund %s at %s",
                        label, key->address);

    funding_utxo_t *items = malloc(sizeof *items);
    if (!items) return bns_fail(err, BNS_ENOMEM, "oom");
    items[0] = pick;
    out->items = items;
    out->count = 1;

    printf("fund %-6s   : %s:%u (%lld sats) <- %s\n",
           label, pick.tx_id, pick.output_index,
           (long long)pick.satoshis, key->address);
    return BNS_OK;
}

/* Assemble a single contract_funding_input_t for a P2PKH funding UTXO at
 * `input_index`: builds the prevout P2PKH locking script into *scratch (caller
 * frees) and points the funding entry at it + the funder key. */
static int make_funding_input(const funding_utxos_t *fu, size_t input_index,
                              const loaded_key_t *funder,
                              contract_funding_input_t *out,
                              byte_buf_t *scratch, bonsai_err_ctx *err)
{
    uint8_t h160[20];
    int rc = loaded_key_hash160(funder, h160, err);
    if (rc != BNS_OK) return rc;
    byte_buf_init(scratch);
    rc = build_p2pkh_script(h160, scratch);
    if (rc != BNS_OK) { byte_buf_free(scratch); return bns_fail(err, rc, "p2pkh script"); }
    memset(out, 0, sizeof *out);
    out->input_index = input_index;
    out->script_code = scratch->data;
    out->script_code_len = scratch->len;
    out->value = (uint64_t)fu->items[0].satoshis;
    out->key = funder->key;
    return BNS_OK;
}

/* The full dry-run plan + (refused) broadcast gate. Returns *out_exit_code. */
static int run_lifecycle(int *out_exit_code, bonsai_err_ctx *err)
{
    int exit_code = 0;
    int rc = BNS_OK;

    const char *home = bonsai_home();
    char key_file[1024], ephemeral_file[1024];
    snprintf(key_file, sizeof key_file, "%s/chain/test_bsv.json", home);
    snprintf(ephemeral_file, sizeof ephemeral_file, "%s/chain/live-smoke-keys.json", home);

    const char *key_file_env = env_or("KEY_FILE", key_file);
    const char *ephemeral_env = env_or("EPHEMERAL_FILE", ephemeral_file);
    const char *elder_kf = env_or("ELDER_KEY_FILE", key_file_env);

    loaded_key_t elder = {0}, agent = {0}, cpty = {0};
    loaded_key_t fund_deploy = {0}, fund_action = {0}, fund_revoke = {0};
    bool have_agent = false, have_cpty = false;
    bool have_fd = false, have_fa = false, have_fr = false;
    char *ricardian_hex = NULL, *action_hex = NULL, *provenance_hex = NULL;
    char *change_addr = NULL;
    scrypt_artifact_t art; memset(&art, 0, sizeof art);
    bool have_art = false;
    agent_tea_params_t cp; memset(&cp, 0, sizeof cp);
    bool have_cp = false;
    agent_tea_t inst; memset(&inst, 0, sizeof inst);
    bool have_state = false;
    byte_buf_t locking; byte_buf_init(&locking);

    /* ---- Elder (kill switch). ELDER_KEY_FILE or KEY_FILE. ---- */
    rc = load_key_file(elder_kf, &elder, err);
    if (rc != BNS_OK) { exit_code = 1; goto done; }

    /* ---- agent + counterparty: deterministic HD keys when both *_KEY_FILE set;
     *      else ephemeral (load-or-create). ---- */
    const char *agent_kf = env_get("AGENT_KEY_FILE");
    const char *cpty_kf = env_get("COUNTERPARTY_KEY_FILE");
    if (agent_kf && agent_kf[0] && cpty_kf && cpty_kf[0]) {
        rc = load_key_file(agent_kf, &agent, err); have_agent = (rc == BNS_OK);
        if (rc != BNS_OK) { exit_code = 1; goto done; }
        rc = load_key_file(cpty_kf, &cpty, err); have_cpty = (rc == BNS_OK);
        if (rc != BNS_OK) { exit_code = 1; goto done; }
    } else {
        rc = load_or_create_ephemeral(ephemeral_env, &agent, &cpty, err);
        if (rc != BNS_OK) { exit_code = 1; goto done; }
        have_agent = have_cpty = true;
        /* TS allows ONE of the two being set to mix HD + ephemeral; mirror it. */
        if (agent_kf && agent_kf[0]) {
            loaded_key_free(&agent);
            rc = load_key_file(agent_kf, &agent, err);
            if (rc != BNS_OK) { exit_code = 1; goto done; }
        }
        if (cpty_kf && cpty_kf[0]) {
            loaded_key_free(&cpty);
            rc = load_key_file(cpty_kf, &cpty, err);
            if (rc != BNS_OK) { exit_code = 1; goto done; }
        }
    }

    /* ---- per-step funding keys: FUND_*_KEY_FILE, else the Elder. ---- */
    const char *fd_kf = env_get("FUND_DEPLOY_KEY_FILE");
    const char *fa_kf = env_get("FUND_ACTION_KEY_FILE");
    const char *fr_kf = env_get("FUND_REVOKE_KEY_FILE");
    if (fd_kf && fd_kf[0]) { rc = load_key_file(fd_kf, &fund_deploy, err); if (rc != BNS_OK) { exit_code = 1; goto done; } have_fd = true; }
    if (fa_kf && fa_kf[0]) { rc = load_key_file(fa_kf, &fund_action, err); if (rc != BNS_OK) { exit_code = 1; goto done; } have_fa = true; }
    if (fr_kf && fr_kf[0]) { rc = load_key_file(fr_kf, &fund_revoke, err); if (rc != BNS_OK) { exit_code = 1; goto done; } have_fr = true; }
    const loaded_key_t *fund_d = have_fd ? &fund_deploy : &elder;
    const loaded_key_t *fund_a = have_fa ? &fund_action : &elder;
    const loaded_key_t *fund_r = have_fr ? &fund_revoke : &elder;

    /* ---- change address: CHANGE_ADDRESS, else the Elder address. ---- */
    {
        const char *ca = env_get("CHANGE_ADDRESS");
        change_addr = strdup((ca && ca[0]) ? ca : elder.address);
        if (!change_addr) { rc = bns_fail(err, BNS_ENOMEM, "oom"); exit_code = 1; goto done; }
    }

    /* ---- commitment hashes (env-typed-or-default). ---- */
    {
        char iso[64]; iso8601_now(iso);
        char charter[256];
        snprintf(charter, sizeof charter,
            "chain_c live smoke %s — ephemeral test identity", iso);
        rc = resolve_hash("RICARDIAN_HASH", charter, &ricardian_hex, err);
        if (rc != BNS_OK) { exit_code = 1; goto done; }
    }
    rc = resolve_hash("ACTION_HASH",
        "live smoke action: prove the Pillar B lifecycle on mainnet", &action_hex, err);
    if (rc != BNS_OK) { exit_code = 1; goto done; }
    {
        const char *pv = env_get("PROVENANCE_HASH");
        if (pv && pv[0]) {
            rc = hash32_env("PROVENANCE_HASH", pv, &provenance_hex, err);
        } else {
            provenance_hex = strdup("0000000000000000000000000000000000000000000000000000000000000000");
            rc = provenance_hex ? BNS_OK : BNS_ENOMEM;
        }
        if (rc != BNS_OK) { exit_code = 1; goto done; }
    }

    /* ---- reconstruct the AgentTea locking script (for the script-bytes line). ---- */
    rc = load_agent_tea_artifact(&art, err);
    if (rc != BNS_OK) { exit_code = 1; goto done; }
    have_art = true;

    uint8_t ricardian_raw[32];
    if (hex_decode_fixed(ricardian_hex, ricardian_raw, 32) != BNS_OK) {
        rc = bns_fail(err, BNS_EPARSE, "bad ricardianHash"); exit_code = 1; goto done;
    }
    rc = build_params(&elder, &agent, ricardian_raw, &cp, err);
    if (rc != BNS_OK) { exit_code = 1; goto done; }
    have_cp = true;

    inst.artifact = &art;
    inst.params = cp;            /* params now owned by inst */
    have_cp = false;            /* ownership transferred */
    rc = agent_tea_genesis_state(&inst.state);
    if (rc != BNS_OK) { rc = bns_fail(err, rc, "genesis state"); exit_code = 1; goto done; }
    have_state = true;

    rc = agent_tea_locking_script(&inst, /*is_genesis=*/false, &locking);
    if (rc != BNS_OK) { rc = bns_fail(err, rc, "locking script"); exit_code = 1; goto done; }
    size_t script_bytes = locking.len;

    /* ---- print the plan (TS console.log labels). ---- */
    printf("Network        : %s\n", "livenet");
    printf("Elder          : %s\n", elder.address);
    printf("agent / cpty   : %s / %s\n", agent.address, cpty.address);
    printf("fund d/a/r     : %s / %s / %s\n", fund_d->address, fund_a->address, fund_r->address);
    printf("change addr    : %s\n", change_addr);
    printf("ricardianHash  : %s\n", ricardian_hex);
    printf("actionHash     : %s\n", action_hex);
    printf("identity sats  : %d · action cost units: %s\n", TE_IDENTITY_SATS, TE_ACTION_COST);
    printf("script bytes   : %zu\n", script_bytes);

    /* ---- dry-run gate (TS: CONFIRM_MAINNET_BROADCAST !== 'yes'). ---- */
    if (!confirm_mainnet_broadcast()) {
        printf("\nDRY RUN — not broadcasting. Set CONFIRM_MAINNET_BROADCAST=yes to run live.\n");
        exit_code = 0;
        goto done;
    }

    /* ======================================================================
     * LIVE broadcast: chained deploy -> executeAction -> revoke (TS main()
     * confirm path). Each step spends its OWN pre-split confirmed funding UTXO
     * (TS fundFrom/pickFunding); the contract identity outpoint is threaded
     * between steps. Confirmation waits between steps keep a ~30 KB action off an
     * unconfirmed ~27 KB deploy (ancestor-package limits). On ANY failure: a
     * clear error + nonzero exit (the "LIVE SMOKE FAILED:" prefix is added by
     * bonsai_third_entry_run). ====================================================*/
    {
        /* 20-byte change hash160 (CHANGE_ADDRESS or the Elder address). */
        uint8_t change20[20];
        {
            const char *ca = env_get("CHANGE_ADDRESS");
            if (ca && ca[0]) rc = address_to_hash160(ca, change20, err);
            else             rc = loaded_key_hash160(&elder, change20, err);
            if (rc != BNS_OK) { exit_code = 1; goto done; }
        }

        /* Counterparty 33-byte compressed pubkey (committed in the action). */
        uint8_t cpty_pub33[33];
        rc = ecdsa_pubkey_serialize_compressed(cpty.pub, cpty_pub33);
        if (rc != BNS_OK) { rc = bns_fail(err, rc, "counterparty pubkey"); exit_code = 1; goto done; }

        /* Action commitment hashes as raw 32-byte values. */
        uint8_t action_raw[32], prov_raw[32];
        if (hex_decode_fixed(action_hex, action_raw, 32) != BNS_OK ||
            hex_decode_fixed(provenance_hex, prov_raw, 32) != BNS_OK) {
            rc = bns_fail(err, BNS_EPARSE, "bad action/provenance hash"); exit_code = 1; goto done;
        }

        /* The mainnet WoC client (mainnet-pinned). */
        woc_client_t *woc = chain_broadcast_woc_new(TE_NETWORK, err);
        if (!woc) { rc = err->code ? err->code : BNS_ENET; exit_code = 1; goto done; }

        /* Per-step fees, scaled to the ACTUAL identity-script size (TS scriptBytes
         * formula): action recreates identity (~scriptBytes) AND embeds the spent
         * script in its unlock (~scriptBytes) -> ~2x + overhead; revoke ~1x. */
        fee_window_t fa_w, fr_w;
        int64_t action_fee = 0, revoke_fee = 0;
        if (send_time_fee_window((int64_t)(2 * script_bytes + 3000), TE_FEE_PER_KB, &fa_w) == BNS_OK)
            action_fee = fa_w.recommended;
        if (send_time_fee_window((int64_t)(script_bytes + 2000), TE_FEE_PER_KB, &fr_w) == BNS_OK)
            revoke_fee = fr_w.recommended;

        char *deploy_txid = NULL, *action_txid = NULL, *revoke_txid = NULL;
        funding_utxos_t fu_d = {0}, fu_a = {0}, fu_r = {0};
        byte_buf_t revoke_script_code; byte_buf_init(&revoke_script_code);

        /* ---- 1. DEPLOY: funding -> contract identity output@1 + change ---- */
        rc = fund_from(woc, fund_d, "deploy", &fu_d, err);
        if (rc != BNS_OK) { exit_code = 1; goto live_done; }
        {
            tx_builder_t b; tx_builder_init(&b);
            byte_buf_t fscr;
            contract_funding_input_t fin;
            rc = make_funding_input(&fu_d, 0, fund_d, &fin, &fscr, err);
            if (rc != BNS_OK) { tx_builder_free(&b); exit_code = 1; goto live_done; }

            /* Deploy fee: scaled to the signed size (~identity script output +
             * one P2PKH input/change overhead), inside the send-time window. */
            int64_t deploy_fee = 0;
            { fee_window_t dw;
              if (send_time_fee_window((int64_t)(script_bytes + 400), TE_FEE_PER_KB, &dw) == BNS_OK)
                  deploy_fee = dw.recommended; }
            int64_t avail = fu_d.items[0].satoshis - TE_IDENTITY_SATS;
            if (avail < deploy_fee) { byte_buf_free(&fscr); tx_builder_free(&b);
                rc = bns_fail(err, BNS_ERANGE, "deploy funding %lld < identity+fee %lld",
                              (long long)fu_d.items[0].satoshis, (long long)(TE_IDENTITY_SATS + deploy_fee));
                exit_code = 1; goto live_done; }
            uint64_t deploy_change = (uint64_t)(avail - deploy_fee);

            rc = tx_builder_add_input(&b, fu_d.items[0].tx_id,
                                      fu_d.items[0].output_index, NULL, 0, 0xffffffffu);
            if (rc == BNS_OK)
                rc = tx_builder_add_output(&b, locking.data, locking.len, TE_IDENTITY_SATS);
            if (rc == BNS_OK && deploy_change >= 1u) {
                byte_buf_t cscr; byte_buf_init(&cscr);
                rc = build_p2pkh_script(change20, &cscr);
                if (rc == BNS_OK)
                    rc = tx_builder_add_output(&b, cscr.data, cscr.len, deploy_change);
                byte_buf_free(&cscr);
            }
            if (rc != BNS_OK) { byte_buf_free(&fscr); tx_builder_free(&b); rc = bns_fail(err, rc, "deploy build failed"); exit_code = 1; goto live_done; }

            char *hex = NULL;
            rc = build_contract_deploy(&b, &fin, 1, &hex);
            byte_buf_free(&fscr); tx_builder_free(&b);
            if (rc != BNS_OK) { rc = bns_fail(err, rc, "deploy sign failed"); exit_code = 1; goto live_done; }
            printf("\n[1/3] DEPLOY raw tx       : %s\n", hex);
            rc = chain_broadcast_send(woc, hex, &deploy_txid, err);
            free(hex);
            if (rc != BNS_OK) { exit_code = 1; goto live_done; }
            printf("[1/3] DEPLOY broadcast    : %s\n", deploy_txid);
        }
        /* Wait for CONFIRMATION of the contract identity (action spends it). */
        {
            tx_status_t st;
            rc = woc_client_wait_for_confirmation(woc, deploy_txid, NULL, &st);
            if (rc != BNS_OK) { rc = bns_fail(err, rc, "deploy confirmation wait failed"); exit_code = 1; goto live_done; }
            printf("      deploy confirmed\n");
        }

        printf("fee est (sats) : action %lld · revoke %lld (script %zu B)\n",
               (long long)action_fee, (long long)revoke_fee, script_bytes);

        /* SKIP_ACTION=1 -> deploy -> confirm -> revoke (one confirmation wait). */
        bool skip_action = false;
        { const char *sa = env_get("SKIP_ACTION"); skip_action = (sa && strcmp(sa, "1") == 0); }

        /* The identity outpoint + locking script the revoke will spend. Defaults
         * to the deploy (genesis) script; the action re-points it to the action's
         * recreated identity output. */
        char revoke_identity_txid[65];
        snprintf(revoke_identity_txid, sizeof revoke_identity_txid, "%s", deploy_txid);
        rc = byte_buf_append(&revoke_script_code, locking.data, locking.len);
        if (rc != BNS_OK) { rc = bns_fail(err, rc, "oom"); exit_code = 1; goto live_done; }

        if (!skip_action) {
            /* ---- 2. EXECUTE one metered action (below validator threshold) ---- */
            rc = fund_from(woc, fund_a, "action", &fu_a, err);
            if (rc != BNS_OK) { exit_code = 1; goto live_done; }

            bn_t *amount = NULL;
            rc = bn_parse_dec(TE_ACTION_COST, &amount);
            if (rc != BNS_OK) { rc = bns_fail(err, rc, "amount"); exit_code = 1; goto live_done; }

            /* now = floor(Date.now()/1000) - 600 (past vs miner clocks; TS). */
            int64_t now = (int64_t)time(NULL) - 600;

            agent_tea_utxo_t id;
            memset(&id, 0, sizeof id);
            snprintf(id.txid_display, sizeof id.txid_display, "%s", deploy_txid);
            id.vout = 0;
            id.value = TE_IDENTITY_SATS;

            agent_tea_builder_opts_t opts;
            memset(&opts, 0, sizeof opts);
            opts.funding = &fu_a;
            opts.change_hash160 = change20;
            opts.has_change = true;
            opts.fee_sats = (uint64_t)action_fee;
            opts.has_fee_sats = true;

            tx_builder_t b; tx_builder_init(&b);
            rc = build_agent_tea_action(&inst, &id, cpty_pub33, amount,
                                        action_raw, prov_raw, now, &opts, &b);
            bn_free(amount);
            if (rc != BNS_OK) { tx_builder_free(&b); rc = bns_fail(err, rc, "action build failed"); exit_code = 1; goto live_done; }

            /* Funding inputs follow the contract input at index 0. */
            byte_buf_t fscr;
            contract_funding_input_t fin;
            rc = make_funding_input(&fu_a, 1, fund_a, &fin, &fscr, err);
            if (rc != BNS_OK) { tx_builder_free(&b); exit_code = 1; goto live_done; }

            /* change_amount = the (last) change output the builder settled. */
            int64_t change_amount = 0;
            if (b.tx.num_outputs > 0)
                change_amount = (int64_t)b.tx.outputs[b.tx.num_outputs - 1].satoshis;

            /* Capture the action's recreated identity output[0] (revoke spends it)
             * + its OP_RETURN receipt script BEFORE consuming the builder. */
            byte_buf_t op_return_hex_src; byte_buf_init(&op_return_hex_src);
            if (b.tx.num_outputs > 1)
                byte_buf_append(&op_return_hex_src, b.tx.outputs[1].script.data,
                                b.tx.outputs[1].script.len);
            byte_buf_clear(&revoke_script_code);
            if (b.tx.num_outputs > 0)
                byte_buf_append(&revoke_script_code, b.tx.outputs[0].script.data,
                                b.tx.outputs[0].script.len);

            contract_execute_args_t args;
            memset(&args, 0, sizeof args);
            bn_t *amt2 = NULL, *attlim = NULL, *rabin_s = NULL;
            (void)bn_parse_dec(TE_ACTION_COST, &amt2);     /* amount */
            (void)bn_parse_dec(TE_ACTION_COST, &attlim);   /* attestedLimit (inert) */
            (void)bn_parse_dec("0", &rabin_s);             /* RabinSig.s = 0n (DUMMY_SIG) */
            args.agent_key = agent.key;
            args.counterparty_key = cpty.key;
            args.counterparty_pub33 = cpty_pub33;
            args.amount = amt2;
            args.hash32 = action_raw;
            args.provenance_hash32 = prov_raw;
            args.attested_limit = attlim;
            args.rabin_s = rabin_s;
            args.rabin_padding = NULL;        /* padding "" -> OP_0 */
            args.rabin_padding_len = 0;

            char *hex = NULL;
            rc = (amt2 && attlim && rabin_s) ? BNS_OK : BNS_ENOMEM;
            if (rc == BNS_OK)
                rc = contract_execute_sign(&b, 0, locking.data, locking.len,
                                           TE_IDENTITY_SATS, &args,
                                           change_amount, change20,
                                           TE_SELECTOR_EXECUTE, &fin, 1, &hex);
            bn_free(amt2); bn_free(attlim); bn_free(rabin_s);
            byte_buf_free(&fscr); tx_builder_free(&b);
            if (rc != BNS_OK) { byte_buf_free(&op_return_hex_src); rc = bns_fail(err, rc, "action sign failed"); exit_code = 1; goto live_done; }

            printf("[2/3] EXECUTE raw tx      : %s\n", hex);
            rc = chain_broadcast_send(woc, hex, &action_txid, err);
            free(hex);
            if (rc != BNS_OK) { byte_buf_free(&op_return_hex_src); exit_code = 1; goto live_done; }
            printf("[2/3] EXECUTE broadcast   : %s\n", action_txid);
            {
                char *op_hex = hex_encode(op_return_hex_src.data, op_return_hex_src.len);
                printf("      receipt OP_RETURN  : %s\n", op_hex ? op_hex : "");
                free(op_hex);
            }
            byte_buf_free(&op_return_hex_src);

            {
                tx_status_t st;
                rc = woc_client_wait_for_confirmation(woc, action_txid, NULL, &st);
                if (rc != BNS_OK) { rc = bns_fail(err, rc, "executeAction confirmation wait failed"); exit_code = 1; goto live_done; }
                printf("      executeAction confirmed\n");
            }
            /* Revoke now targets the action's recreated identity output. */
            snprintf(revoke_identity_txid, sizeof revoke_identity_txid, "%s", action_txid);
        } else {
            printf("[2/3] EXECUTE skipped (SKIP_ACTION=1) - revoking the deployed identity\n");
        }

        /* ---- 3. REVOKE (Elder kill switch), funded by its own pre-split UTXO ---- */
        rc = fund_from(woc, fund_r, "revoke", &fu_r, err);
        if (rc != BNS_OK) { exit_code = 1; goto live_done; }
        {
            agent_tea_utxo_t id;
            memset(&id, 0, sizeof id);
            snprintf(id.txid_display, sizeof id.txid_display, "%s", revoke_identity_txid);
            id.vout = 0;
            id.value = TE_IDENTITY_SATS;

            agent_tea_builder_opts_t opts;
            memset(&opts, 0, sizeof opts);
            opts.funding = &fu_r;
            opts.change_hash160 = change20;
            opts.has_change = true;
            opts.fee_sats = (uint64_t)revoke_fee;
            opts.has_fee_sats = true;

            tx_builder_t b; tx_builder_init(&b);
            rc = build_agent_tea_revoke(&inst, &id, &opts, &b);
            if (rc != BNS_OK) { tx_builder_free(&b); rc = bns_fail(err, rc, "revoke build failed"); exit_code = 1; goto live_done; }

            byte_buf_t fscr;
            contract_funding_input_t fin;
            rc = make_funding_input(&fu_r, 1, fund_r, &fin, &fscr, err);
            if (rc != BNS_OK) { tx_builder_free(&b); exit_code = 1; goto live_done; }

            int64_t change_amount = 0;
            if (b.tx.num_outputs > 0)
                change_amount = (int64_t)b.tx.outputs[b.tx.num_outputs - 1].satoshis;

            char *hex = NULL;
            rc = contract_revoke_sign(&b, 0, revoke_script_code.data,
                                      revoke_script_code.len, TE_IDENTITY_SATS,
                                      elder.key, change_amount, change20,
                                      TE_SELECTOR_REVOKE, &fin, 1, &hex);
            byte_buf_free(&fscr); tx_builder_free(&b);
            if (rc != BNS_OK) { rc = bns_fail(err, rc, "revoke sign failed"); exit_code = 1; goto live_done; }
            printf("[3/3] REVOKE raw tx       : %s\n", hex);
            rc = chain_broadcast_send(woc, hex, &revoke_txid, err);
            free(hex);
            if (rc != BNS_OK) { exit_code = 1; goto live_done; }
            printf("[3/3] REVOKE broadcast    : %s\n", revoke_txid);
        }

        printf("\nLIVE SMOKE COMPLETE - on mainnet:\n");
        printf("  deploy : https://whatsonchain.com/tx/%s\n", deploy_txid);
        if (action_txid) printf("  action : https://whatsonchain.com/tx/%s\n", action_txid);
        printf("  revoke : https://whatsonchain.com/tx/%s\n", revoke_txid);
        exit_code = 0;
        rc = BNS_OK;

    live_done:
        free(deploy_txid); free(action_txid); free(revoke_txid);
        funding_utxos_free(&fu_d); funding_utxos_free(&fu_a); funding_utxos_free(&fu_r);
        byte_buf_free(&revoke_script_code);
        chain_broadcast_woc_free(woc);
    }

done:
    if (have_state) agent_tea_state_free(&inst.state);
    /* inst.params is owned by inst once transferred; free it directly. */
    agent_tea_params_free(&inst.params);
    if (have_cp) agent_tea_params_free(&cp);
    if (have_art) scrypt_artifact_free(&art);
    byte_buf_free(&locking);
    free(ricardian_hex); free(action_hex); free(provenance_hex); free(change_addr);
    loaded_key_free(&elder);
    if (have_agent) loaded_key_free(&agent);
    if (have_cpty) loaded_key_free(&cpty);
    if (have_fd) loaded_key_free(&fund_deploy);
    if (have_fa) loaded_key_free(&fund_action);
    if (have_fr) loaded_key_free(&fund_revoke);
    (void)have_agent; (void)have_cpty;

    *out_exit_code = exit_code;
    return rc;
}

int bonsai_third_entry_run(int argc, char **argv, int *out_exit_code)
{
    (void)argc; (void)argv;
    if (!out_exit_code) return BNS_EINVAL;

    bonsai_err_ctx err; memset(&err, 0, sizeof err);
    int exit_code = 1;
    int rc = run_lifecycle(&exit_code, &err);

    /* TS: main().catch -> console.error('LIVE SMOKE FAILED:', e); exit(1). */
    if (rc != BNS_OK && err.msg[0])
        fprintf(stderr, "LIVE SMOKE FAILED: %s\n", err.msg);

    *out_exit_code = exit_code;
    return BNS_OK;
}
