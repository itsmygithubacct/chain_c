/*
 * verify_ricardian_lib.c — the verifyRicardian script logic (TS:
 * scripts/verifyRicardian.ts). Verify the Ricardian charter on read:
 *   1. parse the policy params from legal/ricardian-prose.md §2 and print them;
 *   2. if legal/ricardian-prose.sig exists, verify the issuer ECDSA signature
 *      over the canonical {prose||binding} bytes + the embedded ricardianHash;
 *   3. OPT-IN on-chain check (VERIFY_IDENTITY_TXID set): rebuild the expected
 *      locking script (RicardianTea default, or AgentTea when
 *      IDENTITY_KIND=agenttea) and byte-compare it to the live on-chain
 *      identity output via identity_chain_view + WhatsOnChain.
 * CI-usable: non-zero exit on any failure.
 *
 * ROOT resolution (the TS uses __dirname/.. = the chain repo root): first
 * positional argv, else $BONSAI_CHAIN_ROOT, else the current working directory.
 * legal/ and artifacts/ must live under ROOT.
 */
#include "scripts/verify_ricardian.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strcasecmp — case-insensitive hex pubkey compare */
#include <ctype.h>
#include <sys/stat.h>

#include "scripts/script_support.h"        /* env_get */
#include "ricardian_charter.h"
#include "atlas_identity.h"
#include "contracts/ricardian_tea.h"
#include "contracts_next/agent_tea.h"
#include "scrypt/artifact_loader.h"
#include "scrypt/scrypt_contract.h"
#include "crypto/bignum.h"
#include "crypto/ecdsa.h"
#include "common/bytes.h"
#include "common/hex.h"
#include "json/json.h"
#include "broker/identity_chain_view.h"
#include "chainSources/whats_on_chain.h"
#include "chainSources/http_transport.h"
#include "reputation_indexer.h"

/* --------------------------------------------------------------------------
 * small local helpers
 * -------------------------------------------------------------------------- */

/* Read an entire file into a freshly malloc'd NUL-terminated buffer (raw bytes:
 * no newline normalization, as the charter preimage is byte-fragile). Returns
 * BNS_OK / BNS_EPERSIST. */
static int read_file_text(const char *path, char **out, size_t *out_len)
{
    *out = NULL;
    if (out_len) *out_len = 0;
    FILE *f = fopen(path, "rb");
    if (!f) return BNS_EPERSIST;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return BNS_EPERSIST; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return BNS_EPERSIST; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return BNS_EPERSIST; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return BNS_ENOMEM; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';
    *out = buf;
    if (out_len) *out_len = rd;
    return BNS_OK;
}

static bool path_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/* Join root + "/" + rel into a freshly malloc'd string (NULL on OOM). */
static char *path_join(const char *root, const char *rel)
{
    size_t rl = strlen(root);
    size_t need = rl + 1 + strlen(rel) + 1;
    char *p = malloc(need);
    if (!p) return NULL;
    if (rl > 0)
        snprintf(p, need, "%s/%s", root, rel);
    else
        snprintf(p, need, "%s", rel);
    return p;
}

/* env getter that mirrors the TS `need(n)` throw used in the on-chain branch:
 * on missing/empty prints "on-chain verify needs <n>" and returns NULL. */
static const char *env_need(const char *name)
{
    const char *v = env_get(name);
    if (!v || v[0] == '\0') {
        fprintf(stderr, "on-chain verify needs %s\n", name);
        return NULL;
    }
    return v;
}

/* Parse 33-byte compressed SEC pubkey bytes from a (possibly uncompressed) hex
 * string into `out` (init'd, appended). Mirrors PubKey(toHex(bsv.PublicKey
 * .fromHex(...))) — normalizes to a valid compressed key. BNS_OK on success. */
static int pubkey_hex_to_compressed(const char *hex, byte_buf_t *out)
{
    ecdsa_pubkey_t *pk = NULL;
    int rc = ecdsa_pubkey_from_hex(hex, &pk);
    if (rc != BNS_OK) return rc;
    uint8_t sec[BONSAI_ECDSA_PUBKEY_COMPRESSED_LEN];
    rc = ecdsa_pubkey_serialize_compressed(pk, sec);
    ecdsa_pubkey_free(pk);
    if (rc != BNS_OK) return rc;
    return byte_buf_append(out, sec, sizeof sec);
}

/* Lowercase a string in place. */
static void str_tolower(char *s)
{
    for (; *s; ++s) *s = (char)tolower((unsigned char)*s);
}

/* --------------------------------------------------------------------------
 * .sig sidecar parse: cJSON tree -> charter_signature_t (owned).
 * TS: JSON.parse(readFileSync(...)) as CharterSignature.
 * -------------------------------------------------------------------------- */

static char *dup_json_str(const cJSON *obj, const char *key)
{
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsString(it) || !it->valuestring) return NULL;
    return strdup(it->valuestring);
}

/* Parse the .sig JSON text into *out (caller frees via charter_signature_free).
 * BNS_OK / BNS_EPARSE / BNS_ENOMEM. */
static int parse_sig_json(const char *json_text, charter_signature_t *out)
{
    memset(out, 0, sizeof *out);
    cJSON *root = NULL;
    int rc = json_parse(json_text, &root);
    if (rc != BNS_OK) return rc;

    int ret = BNS_EPARSE;
    out->algo           = dup_json_str(root, "algo");
    out->issuer_pubkey  = dup_json_str(root, "issuerPubKey");
    out->signature      = dup_json_str(root, "signature");
    out->ricardian_hash = dup_json_str(root, "ricardianHash");

    const cJSON *b = cJSON_GetObjectItemCaseSensitive(root, "binding");
    if (cJSON_IsObject(b)) {
        out->binding.agent_pubkey                  = dup_json_str(b, "agentPubKey");
        out->binding.designated_validator_pubkey   = dup_json_str(b, "designatedValidatorPubKey");
        out->binding.validator_rabin_pubkey        = dup_json_str(b, "validatorRabinPubKey");
        out->binding.max_slashing_target           = dup_json_str(b, "maxSlashingTarget");
        out->binding.min_slash_confirmations       = dup_json_str(b, "minSlashConfirmations");
        out->binding.initial_slash_checkpoint_hash = dup_json_str(b, "initialSlashCheckpointHash");
    }

    if (out->algo && out->issuer_pubkey && out->signature && out->ricardian_hash &&
        out->binding.agent_pubkey && out->binding.designated_validator_pubkey &&
        out->binding.validator_rabin_pubkey && out->binding.max_slashing_target &&
        out->binding.min_slash_confirmations && out->binding.initial_slash_checkpoint_hash) {
        ret = BNS_OK;
    }
    cJSON_Delete(root);
    if (ret != BNS_OK) charter_signature_free(out);
    return ret;
}

/* --------------------------------------------------------------------------
 * print the parsed charter params (TS: Object.entries(charter) order).
 * -------------------------------------------------------------------------- */

static int print_one_param(const char *key, const bn_t *v)
{
    char *dec = NULL;
    int rc = bn_to_dec(v, &dec);
    if (rc != BNS_OK) return rc;
    /* k.padEnd(20) */
    printf("  %-20s = %s\n", key, dec);
    free(dec);
    return BNS_OK;
}

static int print_charter_params(const charter_params_t *c)
{
    int rc;
    if ((rc = print_one_param("perTxLimit",          c->per_tx_limit))         != BNS_OK) return rc;
    if ((rc = print_one_param("dailyLimit",          c->daily_limit))          != BNS_OK) return rc;
    if ((rc = print_one_param("windowDuration",      c->window_duration))      != BNS_OK) return rc;
    if ((rc = print_one_param("graduationThreshold", c->graduation_threshold)) != BNS_OK) return rc;
    if ((rc = print_one_param("validatorThreshold",  c->validator_threshold))  != BNS_OK) return rc;
    return BNS_OK;
}

/* --------------------------------------------------------------------------
 * on-chain reconstruction helpers (return BNS_OK with the malloc'd lowercase
 * locking-script hex in *out_hex; non-OK on a (printed) missing-env / build
 * failure).
 * -------------------------------------------------------------------------- */

/* AgentTea reconstruction — mirrors agentd's deploy ctor. ricardianHash is taken
 * DIRECTLY from RICARDIAN_HASH (lowercased), not recomputed from the binding. */
static int build_agenttea_script(const char *prose_text, const char *root,
                                 char **out_hex, bonsai_err_ctx *ctx)
{
    *out_hex = NULL;
    /* TS `need(n)` throws on the FIRST missing var: short-circuit in order. */
    const char *elder = env_need("ELDER_PUBKEY");                 if (!elder) return BNS_EINVAL;
    const char *agent = env_need("AGENT_PUBKEY");                 if (!agent) return BNS_EINVAL;
    const char *rhash = env_need("RICARDIAN_HASH");               if (!rhash) return BNS_EINVAL;
    const char *dvr   = env_need("DESIGNATED_VALIDATOR_RABIN_PUBKEY"); if (!dvr) return BNS_EINVAL;
    const char *vrp   = env_need("VALIDATOR_RABIN_PUBKEY");       if (!vrp)   return BNS_EINVAL;
    const char *rrk   = env_need("RECOVERY_RABIN_PUBKEYS");       if (!rrk)   return BNS_EINVAL;
    const char *rthr  = env_need("RECOVERY_THRESHOLD");           if (!rthr)  return BNS_EINVAL;

    /* charter params from prose (per-tx/daily/window/graduation/validator). */
    charter_params_t charter; memset(&charter, 0, sizeof charter);
    int rc = parse_charter_params(prose_text, &charter, ctx);
    if (rc != BNS_OK) return rc;

    int ret = BNS_EINVAL;
    char *art_path = NULL;
    scrypt_artifact_t art; memset(&art, 0, sizeof art);
    bool art_loaded = false;
    agent_tea_t inst; memset(&inst, 0, sizeof inst);
    byte_buf_t script; byte_buf_init(&script);
    bool inst_owned = false;

    /* split RECOVERY_RABIN_PUBKEYS by comma -> 3 bn_t. */
    char *rrk_copy = strdup(rrk);
    if (!rrk_copy) { ret = BNS_ENOMEM; goto done; }
    bn_t *recovery[BONSAI_AGENT_TEA_RECOVERY_KEYS] = {0};
    int nrec = 0;
    {
        char *save = NULL;
        for (char *tok = strtok_r(rrk_copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
            while (*tok == ' ' || *tok == '\t') ++tok;
            char *end = tok + strlen(tok);
            while (end > tok && (end[-1] == ' ' || end[-1] == '\t')) *--end = '\0';
            if (nrec >= BONSAI_AGENT_TEA_RECOVERY_KEYS) { nrec++; break; }
            if (bn_parse_dec(tok, &recovery[nrec]) != BNS_OK) {
                fprintf(stderr, "RECOVERY_RABIN_PUBKEYS entry not a decimal: %s\n", tok);
                ret = BNS_EINVAL; goto rec_done;
            }
            nrec++;
        }
    }
    if (nrec != BONSAI_AGENT_TEA_RECOVERY_KEYS) {
        fprintf(stderr, "RECOVERY_RABIN_PUBKEYS must be 3 comma-separated Rabin pubkeys\n");
        ret = BNS_EINVAL; goto rec_done;
    }

    art_path = path_join(root, "artifacts/src/contracts-next/agentTea.json");
    if (!art_path) { ret = BNS_ENOMEM; goto rec_done; }
    if ((rc = load_artifact(art_path, &art)) != BNS_OK) {
        fprintf(stderr, "could not load AgentTea artifact (%s)\n", art_path);
        ret = rc; goto rec_done;
    }
    art_loaded = true;

    /* Build the 12 ctor params (declaration order). */
    inst.artifact = &art;
    inst_owned = true;
    byte_buf_init(&inst.params.owner);
    byte_buf_init(&inst.params.agent);
    byte_buf_init(&inst.params.ricardian_hash);
    if (pubkey_hex_to_compressed(elder, &inst.params.owner) != BNS_OK) { ret = BNS_EINVAL; goto rec_done; }
    if (pubkey_hex_to_compressed(agent, &inst.params.agent) != BNS_OK) { ret = BNS_EINVAL; goto rec_done; }
    {
        char *rh_lc = strdup(rhash);
        if (!rh_lc) { ret = BNS_ENOMEM; goto rec_done; }
        str_tolower(rh_lc);
        rc = hex_decode(rh_lc, &inst.params.ricardian_hash);
        free(rh_lc);
        if (rc != BNS_OK) { fprintf(stderr, "RICARDIAN_HASH not valid hex\n"); ret = BNS_EINVAL; goto rec_done; }
    }
    /* policy params shared with the charter (dup so we own them). */
    if (bn_dup(charter.per_tx_limit,         &inst.params.per_tx_limit)         != BNS_OK ||
        bn_dup(charter.daily_limit,          &inst.params.daily_limit)          != BNS_OK ||
        bn_dup(charter.window_duration,      &inst.params.window_duration)      != BNS_OK ||
        bn_dup(charter.graduation_threshold, &inst.params.graduation_threshold) != BNS_OK ||
        bn_dup(charter.validator_threshold,  &inst.params.validator_threshold)  != BNS_OK) {
        ret = BNS_ENOMEM; goto rec_done;
    }
    if (bn_parse_dec(dvr, &inst.params.designated_validator_pubkey) != BNS_OK ||
        bn_parse_dec(vrp, &inst.params.validator_rabin_pubkey)      != BNS_OK ||
        bn_parse_dec(rthr, &inst.params.recovery_threshold)         != BNS_OK) {
        fprintf(stderr, "Rabin pubkey / threshold env not decimal\n");
        ret = BNS_EINVAL; goto rec_done;
    }
    for (int i = 0; i < BONSAI_AGENT_TEA_RECOVERY_KEYS; ++i) {
        inst.params.recovery_keys[i] = recovery[i];
        recovery[i] = NULL; /* ownership transferred to params */
    }

    if ((rc = agent_tea_genesis_state(&inst.state)) != BNS_OK) { ret = rc; goto rec_done; }
    if ((rc = agent_tea_locking_script(&inst, true, &script)) != BNS_OK) {
        fprintf(stderr, "could not reconstruct AgentTea locking script\n");
        ret = rc; goto rec_done;
    }
    *out_hex = hex_encode_buf(&script);
    ret = (*out_hex) ? BNS_OK : BNS_ENOMEM;

rec_done:
    for (int i = 0; i < BONSAI_AGENT_TEA_RECOVERY_KEYS; ++i) bn_free(recovery[i]);
    free(rrk_copy);
done:
    byte_buf_free(&script);
    if (inst_owned) agent_tea_free(&inst);
    if (art_loaded) scrypt_artifact_free(&art);
    free(art_path);
    charter_params_free(&charter);
    return ret;
}

/* RicardianTea reconstruction via build_atlas_instance (the shared deploy path). */
static int build_ricardiantea_script(const char *prose_text, const char *root,
                                     char **out_hex, bonsai_err_ctx *ctx)
{
    *out_hex = NULL;
    /* TS `need(n)` throws on the FIRST missing var: short-circuit in order. */
    const char *elder = env_need("ELDER_PUBKEY");                 if (!elder) return BNS_EINVAL;
    const char *agent = env_need("AGENT_PUBKEY");                 if (!agent) return BNS_EINVAL;
    const char *dvr   = env_need("DESIGNATED_VALIDATOR_RABIN_PUBKEY"); if (!dvr) return BNS_EINVAL;
    const char *vrp   = env_need("VALIDATOR_RABIN_PUBKEY");       if (!vrp)   return BNS_EINVAL;
    const char *mst   = env_need("MAX_SLASHING_TARGET");          if (!mst)   return BNS_EINVAL;
    const char *msc   = env_need("MIN_SLASH_CONFIRMATIONS");      if (!msc)   return BNS_EINVAL;
    const char *isch  = env_need("INITIAL_SLASH_CHECKPOINT_HASH"); if (!isch) return BNS_EINVAL;

    int ret = BNS_EINVAL;
    char *art_path = NULL;
    scrypt_artifact_t art; memset(&art, 0, sizeof art);
    bool art_loaded = false;
    atlas_deployment_params_t p; memset(&p, 0, sizeof p);
    byte_buf_init(&p.elder_pubkey);
    byte_buf_init(&p.agent_pubkey);
    byte_buf_init(&p.initial_slash_checkpoint_hash);
    atlas_instance_t out; memset(&out, 0, sizeof out);
    bool out_owned = false;
    byte_buf_t script; byte_buf_init(&script);

    if (pubkey_hex_to_compressed(elder, &p.elder_pubkey) != BNS_OK) { goto done; }
    if (pubkey_hex_to_compressed(agent, &p.agent_pubkey) != BNS_OK) { goto done; }
    if (bn_parse_dec(dvr, &p.designated_validator_pubkey) != BNS_OK ||
        bn_parse_dec(vrp, &p.validator_rabin_pubkey)      != BNS_OK ||
        bn_parse_dec(mst, &p.max_slashing_target)         != BNS_OK ||
        bn_parse_dec(msc, &p.min_slash_confirmations)     != BNS_OK) {
        fprintf(stderr, "Rabin pubkey / slashing env not decimal\n");
        goto done;
    }
    {
        char *isch_lc = strdup(isch);
        if (!isch_lc) { ret = BNS_ENOMEM; goto done; }
        str_tolower(isch_lc);
        int rc = hex_decode(isch_lc, &p.initial_slash_checkpoint_hash);
        free(isch_lc);
        if (rc != BNS_OK) { fprintf(stderr, "INITIAL_SLASH_CHECKPOINT_HASH not valid hex\n"); goto done; }
    }

    art_path = path_join(root, "artifacts/ricardianTea.json");
    if (!art_path) { ret = BNS_ENOMEM; goto done; }
    int rc = load_artifact(art_path, &art);
    if (rc != BNS_OK) { fprintf(stderr, "could not load RicardianTea artifact (%s)\n", art_path); ret = rc; goto done; }
    art_loaded = true;

    rc = build_atlas_instance(prose_text, &p, &art, &out, ctx);
    if (rc != BNS_OK) { ret = rc; goto done; }
    out_owned = true;

    rc = ricardian_tea_locking_script(&out.instance, true, &script);
    if (rc != BNS_OK) { fprintf(stderr, "could not reconstruct RicardianTea locking script\n"); ret = rc; goto done; }
    *out_hex = hex_encode_buf(&script);
    ret = (*out_hex) ? BNS_OK : BNS_ENOMEM;

done:
    byte_buf_free(&script);
    if (out_owned) atlas_instance_free(&out);
    if (art_loaded) scrypt_artifact_free(&art);
    free(art_path);
    bn_free(p.designated_validator_pubkey);
    bn_free(p.validator_rabin_pubkey);
    bn_free(p.max_slashing_target);
    bn_free(p.min_slash_confirmations);
    byte_buf_free(&p.elder_pubkey);
    byte_buf_free(&p.agent_pubkey);
    byte_buf_free(&p.initial_slash_checkpoint_hash);
    return ret;
}

/* --------------------------------------------------------------------------
 * the run entry point
 * -------------------------------------------------------------------------- */

int verify_ricardian_run(int argc, char **argv, int *out_exit_code)
{
    if (out_exit_code) *out_exit_code = 1; /* default to failure exit */

    /* ROOT resolution (TS __dirname/..): argv[1], else $BONSAI_CHAIN_ROOT, else cwd. */
    const char *root = (argc > 1 && argv[1] && argv[1][0]) ? argv[1]
                     : env_or("BONSAI_CHAIN_ROOT", ".");

    bonsai_err_ctx ctx; memset(&ctx, 0, sizeof ctx);
    int final_exit = 0;
    char *prose = NULL;
    char *prose_path = NULL, *sig_path = NULL;
    charter_params_t charter; memset(&charter, 0, sizeof charter);
    bool charter_loaded = false;

    prose_path = path_join(root, "legal/ricardian-prose.md");
    if (!prose_path) { fprintf(stderr, "out of memory\n"); return BNS_ENOMEM; }
    int rc = read_file_text(prose_path, &prose, NULL);
    if (rc != BNS_OK) {
        fprintf(stderr, "could not read %s\n", prose_path);
        free(prose_path);
        return rc;
    }

    rc = parse_charter_params(prose, &charter, &ctx);
    if (rc != BNS_OK) {
        fprintf(stderr, "%s\n", ctx.msg[0] ? ctx.msg : "failed to parse charter params");
        final_exit = 1;
        goto cleanup;
    }
    charter_loaded = true;

    printf("Parsed Ricardian policy parameters (from legal/ricardian-prose.md \xc2\xa7" "2):\n");
    if ((rc = print_charter_params(&charter)) != BNS_OK) { final_exit = 1; goto cleanup; }
    printf("OK \xe2\x80\x94 the prose is the single source of truth; "
           "all required terms present and well-formed.\n");

    /* (2) issuer signature sidecar. */
    sig_path = path_join(root, "legal/ricardian-prose.sig");
    if (!sig_path) { final_exit = 1; goto cleanup; }
    if (path_exists(sig_path)) {
        char *sig_text = NULL;
        rc = read_file_text(sig_path, &sig_text, NULL);
        if (rc != BNS_OK) {
            fprintf(stderr, "could not read %s\n", sig_path);
            final_exit = 1; goto cleanup;
        }
        charter_signature_t sig;
        rc = parse_sig_json(sig_text, &sig);
        free(sig_text);
        if (rc != BNS_OK) {
            fprintf(stderr, "could not parse %s\n", sig_path);
            final_exit = 1; goto cleanup;
        }
        charter_verify_result_t res; memset(&res, 0, sizeof res);
        rc = verify_charter_signature(prose, &sig, &res);
        if (rc != BNS_OK) {
            charter_signature_free(&sig);
            fprintf(stderr, "signature verification error\n");
            final_exit = 1; goto cleanup;
        }
        if (!res.ok) {
            fprintf(stderr, "\nISSUER SIGNATURE INVALID: %s\n",
                    res.reason ? res.reason : "(unknown)");
            charter_signature_free(&sig);
            final_exit = 1; goto cleanup;
        }
        /* PIN the issuer to the Elder trust root. A signature that merely verifies
         * under its own self-asserted issuerPubKey proves nothing: an attacker who
         * can write legal/ricardian-prose.{md,sig} substitutes their own prose and a
         * signature under their own key and the gate would otherwise print "OK" and
         * exit 0. ELDER_PUBKEY (the same trust root the on-chain path requires) must
         * equal sig.issuer_pubkey. Without ELDER_PUBKEY the issuer is unauthenticated:
         * fail closed unless ALLOW_UNPINNED_ISSUER explicitly opts into the dev path. */
        {
            const char *elder_pub = env_get("ELDER_PUBKEY");
            if (elder_pub && elder_pub[0]) {
                /* Normalize BOTH keys to canonical 33-byte compressed form before comparing
                 * (pubkey_hex_to_compressed accepts uncompressed 04.. + whitespace, exactly as the
                 * on-chain reconstruction path does). A raw strcasecmp would falsely reject a valid
                 * uncompressed/variant ELDER_PUBKEY that the on-chain compare accepts (review-2 #10). */
                byte_buf_t elder_c, issuer_c;
                byte_buf_init(&elder_c); byte_buf_init(&issuer_c);
                bool issuer_match = (sig.issuer_pubkey
                    && pubkey_hex_to_compressed(elder_pub, &elder_c) == BNS_OK
                    && pubkey_hex_to_compressed(sig.issuer_pubkey, &issuer_c) == BNS_OK
                    && elder_c.len == issuer_c.len
                    && memcmp(elder_c.data, issuer_c.data, elder_c.len) == 0);
                byte_buf_free(&elder_c); byte_buf_free(&issuer_c);
                if (!issuer_match) {
                    fprintf(stderr, "\nISSUER NOT TRUSTED: signature is under %s, not the "
                            "pinned ELDER_PUBKEY %s\n",
                            sig.issuer_pubkey ? sig.issuer_pubkey : "(none)", elder_pub);
                    charter_signature_free(&sig);
                    final_exit = 1; goto cleanup;
                }
                printf("\nIssuer signature OK \xe2\x80\x94 signed by the pinned Elder %s\n",
                       sig.issuer_pubkey);
                printf("  ricardianHash = %s\n", sig.ricardian_hash);
            } else if (env_get("ALLOW_UNPINNED_ISSUER")) {
                printf("\nWARNING: issuer signature is internally valid but NOT pinned to a "
                       "trust root (ALLOW_UNPINNED_ISSUER set; signer %s)\n", sig.issuer_pubkey);
                printf("  ricardianHash = %s\n", sig.ricardian_hash);
            } else {
                fprintf(stderr, "\nISSUER UNVERIFIED: a signature is present but ELDER_PUBKEY is "
                        "not set, so the issuer (%s) cannot be authenticated. Set ELDER_PUBKEY to "
                        "the trust root, or ALLOW_UNPINNED_ISSUER=1 to accept an unpinned signature.\n",
                        sig.issuer_pubkey ? sig.issuer_pubkey : "(none)");
                charter_signature_free(&sig);
                final_exit = 1; goto cleanup;
            }
        }
        charter_signature_free(&sig);
    } else {
        /* No sig sidecar. The issuer pin lives only in the sig-present branch, so an attacker who
         * substitutes legal/ricardian-prose.md and DELETES the .sig would otherwise sail through
         * with exit 0 over an unsigned, attacker-authored charter (review-2 #3/#9). When the pin is
         * in effect (ELDER_PUBKEY set, no ALLOW_UNPINNED_ISSUER), a MISSING signature is a hard
         * failure: a pinned-issuer policy requires the charter to actually carry an Elder signature. */
        const char *elder_pub = env_get("ELDER_PUBKEY");
        if (elder_pub && elder_pub[0] && !env_get("ALLOW_UNPINNED_ISSUER")) {
            fprintf(stderr, "\nISSUER UNVERIFIED: ELDER_PUBKEY is set (issuer pin in effect) but "
                    "legal/ricardian-prose.sig is MISSING — refusing to accept an unsigned charter. "
                    "Provide the Elder signature, or set ALLOW_UNPINNED_ISSUER=1.\n");
            final_exit = 1; goto cleanup;
        }
        printf("\n(no legal/ricardian-prose.sig present \xe2\x80\x94 "
               "run scripts/deploy.ts to produce the issuer signature)\n");
    }

    /* (3) OPT-IN on-chain verification. */
    const char *txid = env_get("VERIFY_IDENTITY_TXID");
    if (!txid || txid[0] == '\0') {
        printf("\n(set VERIFY_IDENTITY_TXID + the identity public params "
               "to also verify against the live chain)\n");
        final_exit = 0;
        goto cleanup;
    }

    const char *kind_env = env_or("IDENTITY_KIND", "ricardiantea");
    char kind[32];
    snprintf(kind, sizeof kind, "%s", kind_env);
    str_tolower(kind);

    char *expected_hex = NULL;
    if (strcmp(kind, "agenttea") == 0) {
        rc = build_agenttea_script(prose, root, &expected_hex, &ctx);
        if (rc != BNS_OK) { final_exit = 1; goto cleanup; }
        printf("\n(IDENTITY_KIND=agenttea \xe2\x80\x94 auditing a Pillar B AgentTea identity)\n");
    } else {
        rc = build_ricardiantea_script(prose, root, &expected_hex, &ctx);
        if (rc != BNS_OK) { final_exit = 1; goto cleanup; }
    }

    /* live on-chain compare (network). */
    {
        woc_network_t net = (strcmp(env_or("WOC_NETWORK", "main"), "test") == 0)
                              ? WOC_NETWORK_TEST : WOC_NETWORK_MAIN;
        http_transport_t transport; memset(&transport, 0, sizeof transport);
        rc = http_transport_curl(&transport);
        if (rc != BNS_OK) {
            fprintf(stderr, "could not init HTTP transport\n");
            free(expected_hex);
            final_exit = 1; goto cleanup;
        }
        whats_on_chain_opts_t opts; memset(&opts, 0, sizeof opts);
        opts.network = net;
        opts.transport = &transport;
        whats_on_chain_t *woc = NULL;
        rc = whats_on_chain_new(&opts, &woc);
        if (rc != BNS_OK) {
            if (transport.free) transport.free(transport.ctx);
            free(expected_hex);
            fprintf(stderr, "could not init WhatsOnChain source\n");
            final_exit = 1; goto cleanup;
        }
        chain_source_t source; memset(&source, 0, sizeof source);
        whats_on_chain_as_source(woc, &source);
        chain_source_identity_view_t *cv = NULL;
        rc = chain_source_identity_view_new(&source, &cv);
        if (rc != BNS_OK) {
            whats_on_chain_free(woc);
            if (transport.free) transport.free(transport.ctx);
            free(expected_hex);
            final_exit = 1; goto cleanup;
        }
        identity_chain_view_t view; memset(&view, 0, sizeof view);
        chain_source_identity_view_as_view(cv, &view);

        bool ok = false;
        char reason[512];
        verify_identity_script_on_chain(&view, txid, 0, expected_hex,
                                        &ok, reason, sizeof reason);
        if (!ok) {
            fprintf(stderr, "\nON-CHAIN IDENTITY MISMATCH (%s): %s\n", txid, reason);
            final_exit = 1;
        } else {
            printf("\nOn-chain identity binding OK \xe2\x80\x94 %s commits exactly "
                   "this charter + deployment params.\n", txid);
            final_exit = 0;
        }
        chain_source_identity_view_free(cv);
        whats_on_chain_free(woc);
        if (transport.free) transport.free(transport.ctx);
    }
    free(expected_hex);

cleanup:
    if (charter_loaded) charter_params_free(&charter);
    free(prose);
    free(prose_path);
    free(sig_path);
    if (out_exit_code) *out_exit_code = final_exit;
    return BNS_OK;
}
