/*
 * deploy_lib.c — deploy ATLAS-01, a RicardianTea identity, to MAINNET.
 *
 * Faithful C port of chain/scripts/deploy.ts. The Ricardian binding is closed
 * here: the policy PARAMETERS are read out of legal/ricardian-prose.md (the
 * single source of truth — there are no parameter literals in this script) and
 * ricardianHash = H(prose || canonical deployment-binding). The Elder key signs
 * the canonical contract bytes and a self-contained sidecar
 * legal/ricardian-prose.sig is written (JSON.stringify(...,null,2) + "\n").
 *
 * SAFETY: DRY-RUN by default. It builds/prints the deployment but does NOT
 * broadcast unless CONFIRM_MAINNET_BROADCAST=yes. On confirm it runs the live
 * fund -> build -> sign -> broadcast path: it selects funding from WhatsOnChain
 * for the Elder address covering IDENTITY_SATS + fee, builds the
 * unsigned deploy tx (output[0] = the reconstructed RicardianTea genesis locking
 * script at IDENTITY_SATS, then change to the Elder or $CHANGE_ADDRESS), signs
 * the P2PKH funding input(s) via build_contract_deploy, broadcasts the signed raw
 * tx, and prints "DEPLOYED. txid   : <txid>" (mirroring scrypt-ts
 * instance.deploy(IDENTITY_SATS)).
 *
 * ROOT resolution (the TS uses __dirname/.. = the chain repo root): first
 * positional argv, else $BONSAI_CHAIN_ROOT, else the current working directory.
 * legal/ and artifacts/ must live under ROOT.
 *
 * ELDER KEY: loaded from a JSON key file {wif,address}, resolved as
 * $ELDER_KEY_FILE, else $KEY_FILE, else <bonsai_home()>/chain/test_bsv.json, and
 * verified to derive its stated mainnet address. The legacy $PRIVATE_KEY env var
 * (raw WIF) is honored only as a DEPRECATED fallback — it leaks the WIF via the
 * process environment (/proc/<pid>/environ, inherited by child processes).
 *
 * TS origin: scripts/deploy.ts (main + parsePubKeyEnv/parseRabinPubKeyEnv/
 * parseBigIntEnv/parseHashEnv).
 */
#include "scripts/deploy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "scripts/script_support.h"
#include "scripts/chain_broadcast.h"
#include "common/error.h"
#include "common/bytes.h"
#include "common/hex.h"
#include "crypto/bignum.h"
#include "crypto/ecdsa.h"
#include "crypto/hash.h"
#include "bsv/address.h"
#include "bsv/base58.h"
#include "bsv/tx_builder.h"
#include "bsv/script_utils.h"
#include "txbuilders/contract_sign.h"
#include "chainSources/utxo_select.h"
#include "chainSources/woc_client.h"
#include "chainSources/throttled_provider.h"
#include "chainSources/bsv_fees.h"
#include "json/json.h"
#include "ricardian_charter.h"
#include "atlas_identity.h"
#include "contracts/ricardian_tea.h"
#include "scrypt/artifact_loader.h"
#include "scrypt/scrypt_contract.h"

/* Value locked in the persistent identity UTXO (== slashable collateral). 1 sat
 * is fine for an agent identity. TS: deploy.ts IDENTITY_SATS. */
#define IDENTITY_SATS 1

/* --------------------------------------------------------------------------
 * small local helpers (mirroring verify_ricardian_lib.c conventions)
 * -------------------------------------------------------------------------- */

/* Read an entire file into a freshly malloc'd NUL-terminated buffer (raw bytes:
 * no newline normalization — the charter preimage is byte-fragile).
 * BNS_OK / BNS_EPERSIST / BNS_ENOMEM. */
static int read_file_text(const char *path, char **out)
{
    *out = NULL;
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
    return BNS_OK;
}

static int write_file(const char *path, const char *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return BNS_EPERSIST;
    size_t n = fwrite(data, 1, len, f);
    fclose(f);
    return (n == len) ? BNS_OK : BNS_EPERSIST;
}

/* Join root + "/" + rel into a freshly malloc'd string (NULL on OOM). */
static char *path_join(const char *root, const char *rel)
{
    size_t rl = strlen(root);
    size_t need = rl + 1 + strlen(rel) + 1;
    char *p = malloc(need);
    if (!p) return NULL;
    if (rl > 0) snprintf(p, need, "%s/%s", root, rel);
    else        snprintf(p, need, "%s", rel);
    return p;
}

/* Parse 33-byte compressed SEC pubkey bytes from a (possibly uncompressed) hex
 * string into `out` (init'd, appended). Mirrors PubKey(toHex(bsv.PublicKey
 * .fromHex(...))). BNS_OK on success. */
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

/* Decode a base58check P2PKH address string into its 20-byte hash160 on `net`
 * (verifies the version byte). Mirrors bsv.Address.fromString(...).hashBuffer.
 * BNS_OK / BNS_EPARSE / BNS_EINTEGRITY / BNS_EINVAL. */
static int address_to_hash160(const char *addr, bsv_network_t net,
                              uint8_t out[20])
{
    byte_buf_t payload; byte_buf_init(&payload);
    int rc = base58check_decode(addr, &payload);
    if (rc != BNS_OK) { byte_buf_free(&payload); return rc; }
    /* payload = versionByte || 20-byte hash160 */
    if (payload.len != 21) { byte_buf_free(&payload); return BNS_EPARSE; }
    uint8_t want = (net == BSV_TESTNET) ? 0x6f : 0x00;
    if (payload.data[0] != want) { byte_buf_free(&payload); return BNS_EINVAL; }
    memcpy(out, payload.data + 1, 20);
    byte_buf_free(&payload);
    return BNS_OK;
}

/* --------------------------------------------------------------------------
 * env parse helpers (mirror the TS parse*Env functions; verbatim "Set <NAME>")
 * -------------------------------------------------------------------------- */

/* parsePubKeyEnv: require env, normalize to a valid compressed point. */
static int parse_pubkey_env(const char *name, byte_buf_t *out, bonsai_err_ctx *err)
{
    const char *val;
    if (env_require(name, &val, err) != BNS_OK) return err->code;
    int rc = pubkey_hex_to_compressed(val, out);
    if (rc != BNS_OK) return bns_fail(err, rc, "%s: invalid public key hex", name);
    return BNS_OK;
}

/* parseRabinPubKeyEnv / parseBigIntEnv: BigInt(requireEnv(name)) — decimal. */
static int parse_bigint_env(const char *name, bn_t **out, bonsai_err_ctx *err)
{
    const char *val;
    if (env_require(name, &val, err) != BNS_OK) return err->code;
    int rc = bn_parse_dec(val, out);
    if (rc != BNS_OK) return bns_fail(err, rc, "%s: not a valid integer", name);
    return BNS_OK;
}

/* parseHashEnv: require /^[0-9a-fA-F]{64}$/ then 32 raw bytes (lowercased). */
static int parse_hash_env(const char *name, byte_buf_t *out, bonsai_err_ctx *err)
{
    const char *val;
    if (env_require(name, &val, err) != BNS_OK) return err->code;
    if (strlen(val) != 64) return bns_fail(err, BNS_EINVAL, "%s must be a 32-byte hex string", name);
    for (size_t i = 0; i < 64; i++)
        if (!isxdigit((unsigned char)val[i]))
            return bns_fail(err, BNS_EINVAL, "%s must be a 32-byte hex string", name);
    char lower[65];
    for (size_t i = 0; i < 64; i++) lower[i] = (char)tolower((unsigned char)val[i]);
    lower[64] = '\0';
    int rc = hex_decode(lower, out);
    if (rc != BNS_OK) return bns_fail(err, BNS_EINVAL, "%s must be a 32-byte hex string", name);
    return BNS_OK;
}

/* --------------------------------------------------------------------------
 * the .sig sidecar JSON in insertion order:
 * { algo, issuerPubKey, signature, ricardianHash, binding{...} }.
 * TS: JSON.stringify(charterSig, null, 2) + '\n'.
 * -------------------------------------------------------------------------- */
static int build_sig_json(const charter_signature_t *csig, char **out_text)
{
    *out_text = NULL;
    cJSON *root = cJSON_CreateObject();
    if (!root) return BNS_ENOMEM;
    cJSON *bind = cJSON_CreateObject();
    if (!bind) { cJSON_Delete(root); return BNS_ENOMEM; }

    if (!cJSON_AddStringToObject(root, "algo", csig->algo) ||
        !cJSON_AddStringToObject(root, "issuerPubKey", csig->issuer_pubkey) ||
        !cJSON_AddStringToObject(root, "signature", csig->signature) ||
        !cJSON_AddStringToObject(root, "ricardianHash", csig->ricardian_hash)) {
        cJSON_Delete(bind); cJSON_Delete(root); return BNS_ENOMEM;
    }
    cJSON_AddItemToObject(root, "binding", bind);
    if (!cJSON_AddStringToObject(bind, "agentPubKey", csig->binding.agent_pubkey) ||
        !cJSON_AddStringToObject(bind, "designatedValidatorPubKey", csig->binding.designated_validator_pubkey) ||
        !cJSON_AddStringToObject(bind, "validatorRabinPubKey", csig->binding.validator_rabin_pubkey) ||
        !cJSON_AddStringToObject(bind, "maxSlashingTarget", csig->binding.max_slashing_target) ||
        !cJSON_AddStringToObject(bind, "minSlashConfirmations", csig->binding.min_slash_confirmations) ||
        !cJSON_AddStringToObject(bind, "initialSlashCheckpointHash", csig->binding.initial_slash_checkpoint_hash)) {
        cJSON_Delete(root); return BNS_ENOMEM;
    }

    int rc = json_print_pretty2_nl(root, out_text);   /* includes trailing '\n' */
    cJSON_Delete(root);
    return rc;
}

/* --------------------------------------------------------------------------
 * run
 * -------------------------------------------------------------------------- */

int deploy_run(int argc, char **argv, int *out_exit_code)
{
    if (out_exit_code) *out_exit_code = 1; /* default failure */

    /* ROOT resolution (TS __dirname/..): argv[1], else $BONSAI_CHAIN_ROOT, else cwd. */
    const char *root = (argc > 1 && argv[1] && argv[1][0]) ? argv[1]
                     : env_or("BONSAI_CHAIN_ROOT", ".");

    bonsai_err_ctx err; memset(&err, 0, sizeof err);
    int rc = BNS_OK;
    int exit_code = 1;

    /* owned resources */
    char *prose = NULL;
    char *prose_path = NULL, *sig_path = NULL, *art_path = NULL;
    ecdsa_key_t *elder = NULL;
    bn_t *max_slashing = NULL, *min_confirm = NULL;
    bn_t *desig_validator = NULL, *validator_rabin = NULL;
    byte_buf_t agent_pk;   byte_buf_init(&agent_pk);
    byte_buf_t elder_pk;   byte_buf_init(&elder_pk);
    byte_buf_t init_ckpt;  byte_buf_init(&init_ckpt);
    scrypt_artifact_t artifact; memset(&artifact, 0, sizeof artifact);
    bool artifact_ok = false;
    atlas_instance_t inst; memset(&inst, 0, sizeof inst);
    bool inst_ok = false;
    charter_signature_t csig; memset(&csig, 0, sizeof csig);
    bool csig_ok = false;
    char *sig_text = NULL;
    byte_buf_t genesis_script; byte_buf_init(&genesis_script);
    woc_client_t *woc = NULL;
    throttled_provider_t *provider = NULL;
    funding_utxos_t funding; memset(&funding, 0, sizeof funding);
    tx_builder_t txb; memset(&txb, 0, sizeof txb);
    bool txb_ok = false;
    char *raw_hex = NULL;
    char *txid = NULL;
    contract_funding_input_t *cfunding = NULL;
    byte_buf_t *funding_scripts = NULL;
    size_t n_funding_scripts = 0;

    /* Elder key (mainnet). Preferred source is a JSON key file {wif,address}
     * (ELDER_KEY_FILE, else KEY_FILE, else <bonsai_home()>/chain/test_bsv.json),
     * which keeps the raw WIF off the process environment. PRIVATE_KEY (raw WIF
     * in the environment) remains a DEPRECATED fallback. Either way `elder` ends
     * up holding the mainnet Elder key. */
    {
        const char *priv = getenv("PRIVATE_KEY");
        if (priv && priv[0]) {
            /* DEPRECATED: a raw WIF in the environment leaks via /proc/<pid>/environ
             * and is inherited by posix_spawn'd children. Prefer ELDER_KEY_FILE. */
            fprintf(stderr,
                    "Warning: PRIVATE_KEY is deprecated and exposes the WIF via the "
                    "process environment; use ELDER_KEY_FILE (a JSON key file) instead.\n");
            uint8_t secret[32]; bool compressed = false; bsv_network_t net = BSV_MAINNET;
            rc = wif_decode(priv, secret, &compressed, &net);
            if (rc != BNS_OK) { bns_fail(&err, rc, "PRIVATE_KEY: invalid WIF"); goto fail; }
            if (net != BSV_MAINNET) {
                memset(secret, 0, sizeof secret);
                rc = bns_fail(&err, BNS_EINVAL, "PRIVATE_KEY is for testnet, expected livenet");
                goto fail;
            }
            rc = ecdsa_key_from_bytes(secret, &elder);
            memset(secret, 0, sizeof secret);
            (void)compressed;
            if (rc != BNS_OK) { bns_fail(&err, rc, "PRIVATE_KEY: bad key bytes"); goto fail; }
        } else {
            /* Key file: ELDER_KEY_FILE, else KEY_FILE, else the default path. */
            char default_elder[1024];
            snprintf(default_elder, sizeof default_elder, "%s/chain/test_bsv.json",
                     bonsai_home());
            const char *key_file_env = env_or("KEY_FILE", default_elder);
            const char *elder_file = env_or("ELDER_KEY_FILE", key_file_env);

            key_file_t kf; memset(&kf, 0, sizeof kf);
            rc = key_file_load(elder_file, &kf, &err);
            if (rc != BNS_OK) goto fail;
            rc = key_file_verify(&kf, BSV_MAINNET, &err);   /* enforces mainnet derivation */
            if (rc != BNS_OK) { key_file_free(&kf); goto fail; }
            bool compressed = false;
            rc = ecdsa_key_from_wif(kf.wif, &elder, &compressed);
            key_file_free(&kf);
            (void)compressed;
            if (rc != BNS_OK) { bns_fail(&err, rc, "elder key file: bad WIF"); goto fail; }
        }

        /* derive + serialize the compressed Elder pubkey into elder_pk. */
        ecdsa_pubkey_t *pub = NULL;
        rc = ecdsa_key_derive_pubkey(elder, &pub);
        if (rc != BNS_OK) { bns_fail(&err, rc, "cannot derive elder pubkey"); goto fail; }
        uint8_t sec[BONSAI_ECDSA_PUBKEY_COMPRESSED_LEN];
        rc = ecdsa_pubkey_serialize_compressed(pub, sec);
        ecdsa_pubkey_free(pub);
        if (rc != BNS_OK) { bns_fail(&err, rc, "cannot serialize elder pubkey"); goto fail; }
        rc = byte_buf_append(&elder_pk, sec, sizeof sec);
        if (rc != BNS_OK) { bns_fail(&err, rc, "out of memory"); goto fail; }
    }

    /* slashing policy + guards. */
    if (parse_bigint_env("MAX_SLASHING_TARGET", &max_slashing, &err) != BNS_OK) { rc = err.code; goto fail; }
    if (parse_bigint_env("MIN_SLASH_CONFIRMATIONS", &min_confirm, &err) != BNS_OK) { rc = err.code; goto fail; }
    {
        bn_t *zero = NULL;
        rc = bn_parse_dec("0", &zero);
        if (rc != BNS_OK) { bns_fail(&err, rc, "out of memory"); goto fail; }
        int cmp = bn_cmp(max_slashing, zero);
        bn_free(zero);
        if (cmp <= 0) { rc = bns_fail(&err, BNS_EINVAL, "MAX_SLASHING_TARGET must be > 0"); goto fail; }
    }
    {
        bn_t *one = NULL, *six = NULL;
        if (bn_parse_dec("1", &one) != BNS_OK || bn_parse_dec("6", &six) != BNS_OK) {
            bn_free(one); bn_free(six);
            rc = bns_fail(&err, BNS_ENOMEM, "out of memory"); goto fail;
        }
        int lo = bn_cmp(min_confirm, one), hi = bn_cmp(min_confirm, six);
        bn_free(one); bn_free(six);
        if (lo < 0 || hi > 0) {
            rc = bns_fail(&err, BNS_EINVAL, "MIN_SLASH_CONFIRMATIONS must be between 1 and 6");
            goto fail;
        }
    }

    /* remaining binding env. */
    if (parse_pubkey_env("AGENT_PUBKEY", &agent_pk, &err) != BNS_OK) { rc = err.code; goto fail; }
    if (parse_bigint_env("DESIGNATED_VALIDATOR_RABIN_PUBKEY", &desig_validator, &err) != BNS_OK) { rc = err.code; goto fail; }
    if (parse_bigint_env("VALIDATOR_RABIN_PUBKEY", &validator_rabin, &err) != BNS_OK) { rc = err.code; goto fail; }
    if (parse_hash_env("INITIAL_SLASH_CHECKPOINT_HASH", &init_ckpt, &err) != BNS_OK) { rc = err.code; goto fail; }

    /* single source of truth: read prose verbatim, load artifact, build instance. */
    prose_path = path_join(root, "legal/ricardian-prose.md");
    if (!prose_path) { rc = bns_fail(&err, BNS_ENOMEM, "out of memory"); goto fail; }
    rc = read_file_text(prose_path, &prose);
    if (rc != BNS_OK) { bns_fail(&err, rc, "could not read %s", prose_path); goto fail; }

    art_path = path_join(root, "artifacts/ricardianTea.json");
    if (!art_path) { rc = bns_fail(&err, BNS_ENOMEM, "out of memory"); goto fail; }
    rc = load_artifact(art_path, &artifact);
    if (rc != BNS_OK) { bns_fail(&err, rc, "could not load artifact %s", art_path); goto fail; }
    artifact_ok = true;

    {
        atlas_deployment_params_t p; memset(&p, 0, sizeof p);
        p.elder_pubkey = elder_pk;
        p.agent_pubkey = agent_pk;
        p.designated_validator_pubkey = desig_validator;
        p.validator_rabin_pubkey = validator_rabin;
        p.max_slashing_target = max_slashing;
        p.min_slash_confirmations = min_confirm;
        p.initial_slash_checkpoint_hash = init_ckpt;
        rc = build_atlas_instance(prose, &p, &artifact, &inst, &err);
        if (rc != BNS_OK) goto fail;
        inst_ok = true;
    }

    /* sign the canonical contract bytes; write the sidecar; verify. */
    rc = sign_charter(prose, &inst.binding, elder, &csig);
    if (rc != BNS_OK) { bns_fail(&err, rc, "signCharter failed"); goto fail; }
    csig_ok = true;

    rc = build_sig_json(&csig, &sig_text);
    if (rc != BNS_OK) { bns_fail(&err, rc, "out of memory"); goto fail; }
    sig_path = path_join(root, "legal/ricardian-prose.sig");
    if (!sig_path) { rc = bns_fail(&err, BNS_ENOMEM, "out of memory"); goto fail; }
    rc = write_file(sig_path, sig_text, strlen(sig_text));
    if (rc != BNS_OK) { bns_fail(&err, rc, "could not write %s", sig_path); goto fail; }

    {
        charter_verify_result_t vr; memset(&vr, 0, sizeof vr);
        rc = verify_charter_signature(prose, &csig, &vr);
        if (rc != BNS_OK) { bns_fail(&err, rc, "verify failed"); goto fail; }
        if (!vr.ok) {
            rc = bns_fail(&err, BNS_EINTEGRITY, "issuer signature failed to verify: %s",
                          vr.reason ? vr.reason : "unknown");
            goto fail;
        }

        /* identity script first 64 hex. Reconstruct the genesis locking script
         * ONCE into the outer-scope buffer so the live broadcast path below can
         * reuse the exact same bytes as output[0]. */
        char id_first64[65] = {0};
        rc = ricardian_tea_locking_script(&inst.instance, /*is_genesis=*/true, &genesis_script);
        if (rc != BNS_OK) { bns_fail(&err, rc, "cannot reconstruct locking script"); goto fail; }
        char *full = hex_encode_buf(&genesis_script);
        if (!full) { rc = bns_fail(&err, BNS_ENOMEM, "out of memory"); goto fail; }
        size_t n = strlen(full);
        size_t take = n < 64 ? n : 64;
        memcpy(id_first64, full, take);
        id_first64[take] = '\0';
        free(full);

        printf("Network          : %s\n", "livenet");
        printf("ricardianHash    : %s\n", inst.ricardian_hash);
        printf("Issuer signature : legal/ricardian-prose.sig (verified: %s)\n", vr.ok ? "true" : "false");
        printf("Identity script  : %s \xe2\x80\xa6\n", id_first64);
        printf("Agent pubkey     : %s\n", inst.binding.agent_pubkey);
    }

    if (!confirm_mainnet_broadcast()) {
        printf("\nDRY RUN \xe2\x80\x94 not broadcasting. "
               "Re-run with CONFIRM_MAINNET_BROADCAST=yes to deploy for real.\n");
        exit_code = 0;
        goto cleanup;
    }

    /* ---- LIVE broadcast: fund -> build -> sign -> broadcast --------------- *
     * Mirrors scrypt-ts instance.deploy(IDENTITY_SATS): fund from the Elder
     * key-file address, lock output[0] = the reconstructed genesis script
     * at IDENTITY_SATS, return change to the Elder (or $CHANGE_ADDRESS). */
    {
        /* Elder hash160 + P2PKH funding scriptCode + funder/change addresses. */
        uint8_t elder_h160[20];
        hash160(elder_pk.data, elder_pk.len, elder_h160);

        char *funder_addr = NULL;
        rc = address_from_hash160(elder_h160, BSV_MAINNET, &funder_addr);
        if (rc != BNS_OK) { bns_fail(&err, rc, "cannot derive elder address"); goto fail; }

        /* change -> $CHANGE_ADDRESS if set, else the Elder address. */
        uint8_t change_h160[20];
        const char *change_env = env_get("CHANGE_ADDRESS");
        if (change_env && change_env[0]) {
            rc = address_to_hash160(change_env, BSV_MAINNET, change_h160);
            if (rc != BNS_OK) {
                free(funder_addr);
                bns_fail(&err, rc, "CHANGE_ADDRESS: invalid mainnet P2PKH address");
                goto fail;
            }
        } else {
            memcpy(change_h160, elder_h160, 20);
        }

        /* funder P2PKH scriptCode (== prevout locking script of each input). */
        byte_buf_t funder_spk; byte_buf_init(&funder_spk);
        rc = build_p2pkh_script(elder_h160, &funder_spk);
        if (rc != BNS_OK) { free(funder_addr); byte_buf_free(&funder_spk);
                            bns_fail(&err, rc, "out of memory"); goto fail; }

        /* WoC client + effective fee rate (override env or WoC quote). */
        woc = chain_broadcast_woc_new(BSV_MAINNET, &err);
        if (!woc) { rc = err.code; free(funder_addr); byte_buf_free(&funder_spk); goto fail; }

        /* Default bsv.Transaction.FEE_PER_KB == 50 sats/KB (bsv/tx_change.h
         * BONSAI_FEE_PER_KB); hardcoded here to avoid that header's clashing
         * fee_window_t typedef. */
        int64_t fee_per_kb = 50;
        {
            throttled_provider_opts_t popts; memset(&popts, 0, sizeof popts);
            popts.client = woc;
            const char *fee_env = env_get("FEE_PER_KB");
            if (fee_env && fee_env[0]) {
                popts.fee_per_kb_override = (int64_t)strtoll(fee_env, NULL, 10);
                popts.has_fee_per_kb_override = true;
            }
            rc = throttled_provider_new(&popts, &provider);
            if (rc != BNS_OK) { free(funder_addr); byte_buf_free(&funder_spk);
                                bns_fail(&err, rc, "cannot build fee provider"); goto fail; }
            int64_t q = 0;
            if (throttled_provider_fee_per_kb(provider, &q) == BNS_OK && q > 0)
                fee_per_kb = q;
        }

        /* Fee: size the deploy tx (genesis output dominates) + per-input/overhead
         * headroom, then take the in-window recommended fee. */
        int64_t signed_size = (int64_t)genesis_script.len + 1000; /* output + tx overhead */
        fee_window_t fw; memset(&fw, 0, sizeof fw);
        rc = chain_broadcast_fee_window(signed_size, fee_per_kb, &fw, &err);
        if (rc != BNS_OK) { free(funder_addr); byte_buf_free(&funder_spk); goto fail; }
        int64_t fee = fw.recommended;

        /* Select funding from the Elder address covering IDENTITY_SATS + fee. */
        int64_t need = (int64_t)IDENTITY_SATS + fee;
        rc = chain_broadcast_select_funding(woc, funder_addr, need, &funding, &err);
        if (rc != BNS_OK) { free(funder_addr); byte_buf_free(&funder_spk); goto fail; }
        free(funder_addr);

        int64_t total_in = 0;
        for (size_t i = 0; i < funding.count; i++) total_in += funding.items[i].satoshis;

        /* Build the unsigned tx: funding inputs (placeholder scriptSig), then
         * output[0] = genesis locking script @ IDENTITY_SATS, then change (if
         * above dust). */
        tx_builder_init(&txb);
        txb_ok = true;

        for (size_t i = 0; i < funding.count; i++) {
            rc = tx_builder_add_input(&txb, funding.items[i].tx_id,
                                      funding.items[i].output_index,
                                      NULL, 0, 0xffffffff);
            if (rc != BNS_OK) { byte_buf_free(&funder_spk);
                                bns_fail(&err, rc, "cannot add funding input"); goto fail; }
        }

        rc = tx_builder_add_output(&txb, genesis_script.data, genesis_script.len,
                                   (uint64_t)IDENTITY_SATS);
        if (rc != BNS_OK) { byte_buf_free(&funder_spk);
                            bns_fail(&err, rc, "cannot add identity output"); goto fail; }

        int64_t change_val = total_in - (int64_t)IDENTITY_SATS - fee;
        if (change_val >= BONSAI_FEE_DUST_FLOOR) {
            byte_buf_t change_spk; byte_buf_init(&change_spk);
            rc = build_p2pkh_script(change_h160, &change_spk);
            if (rc == BNS_OK)
                rc = tx_builder_add_output(&txb, change_spk.data, change_spk.len,
                                           (uint64_t)change_val);
            byte_buf_free(&change_spk);
            if (rc != BNS_OK) { byte_buf_free(&funder_spk);
                                bns_fail(&err, rc, "cannot add change output"); goto fail; }
        }
        /* else: dust change is dropped into the fee. */

        /* Sign every P2PKH funding input over the SAME shared scriptCode/key. */
        cfunding = calloc(funding.count, sizeof *cfunding);
        funding_scripts = calloc(funding.count, sizeof *funding_scripts);
        if (!cfunding || !funding_scripts) {
            byte_buf_free(&funder_spk);
            rc = bns_fail(&err, BNS_ENOMEM, "out of memory"); goto fail;
        }
        n_funding_scripts = funding.count;
        for (size_t i = 0; i < funding.count; i++) {
            byte_buf_init(&funding_scripts[i]);
            rc = byte_buf_append_buf(&funding_scripts[i], &funder_spk);
            if (rc != BNS_OK) { byte_buf_free(&funder_spk);
                                bns_fail(&err, rc, "out of memory"); goto fail; }
            cfunding[i].input_index     = i;
            cfunding[i].script_code     = funding_scripts[i].data;
            cfunding[i].script_code_len = funding_scripts[i].len;
            cfunding[i].value           = (uint64_t)funding.items[i].satoshis;
            cfunding[i].key             = elder;
        }
        byte_buf_free(&funder_spk);

        /* Finalize + sign -> byte-exact signed raw tx hex. */
        rc = build_contract_deploy(&txb, cfunding, funding.count, &raw_hex);
        if (rc != BNS_OK) { bns_fail(&err, rc, "deploy signing failed"); goto fail; }

        printf("\nSigned raw tx    : %s\n", raw_hex);

        rc = chain_broadcast_send(woc, raw_hex, &txid, &err);
        if (rc != BNS_OK) goto fail;

        printf("\nDEPLOYED. txid   : %s\n", txid);
        printf("BROADCAST OK: %s\n", txid);
        exit_code = 0;
        goto cleanup;
    }

fail:
    if (err.msg[0]) fprintf(stderr, "Error: %s\n", err.msg);
    else fprintf(stderr, "Error: %s\n", bns_err_name(rc));
    exit_code = 1;

cleanup:
    free(txid);
    free(raw_hex);
    if (funding_scripts) {
        for (size_t i = 0; i < n_funding_scripts; i++)
            byte_buf_free(&funding_scripts[i]);
        free(funding_scripts);
    }
    free(cfunding);
    if (txb_ok) tx_builder_free(&txb);
    funding_utxos_free(&funding);
    if (provider) throttled_provider_free(provider);
    if (woc) chain_broadcast_woc_free(woc);
    byte_buf_free(&genesis_script);
    free(sig_text);
    if (csig_ok) charter_signature_free(&csig);
    if (inst_ok) atlas_instance_free(&inst);
    if (artifact_ok) scrypt_artifact_free(&artifact);
    bn_free(max_slashing);
    bn_free(min_confirm);
    bn_free(desig_validator);
    bn_free(validator_rabin);
    byte_buf_free(&agent_pk);
    byte_buf_free(&elder_pk);
    byte_buf_free(&init_ckpt);
    ecdsa_key_free(elder);
    free(prose);
    free(prose_path);
    free(sig_path);
    free(art_path);

    if (out_exit_code) *out_exit_code = exit_code;
    return BNS_OK;
}
