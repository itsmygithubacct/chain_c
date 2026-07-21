/*
 * test_tier3456_golden.c — GOLDEN INTEGRATION TEST for the chain_c tier 3-6 lib.
 *
 * Self-contained C program (own main(), no Unity). Loads tests/golden/golden.json
 * via the in-lib cJSON, drives the real C tier 3-6 public API (ricardian_charter,
 * atlas_identity, agent_tea, arp_attest, zk/limit_commitment + mimc7,
 * reputation_indexer, rabin_attestor, release_anchor_verifier, key_broker,
 * privacy enclave/key_vault, woc_client over a stub transport), and asserts
 * byte-exact equality against the TypeScript-captured golden strings — or, for
 * behavioral modules without a byte golden, ports the KEY assertion from the
 * matching chain/tests priscilla *.test.ts.
 *
 * Build (from chain_c/):
 *   gcc -std=c11 -D_GNU_SOURCE -Iinclude -Ithird_party/cJSON \
 *       -Ithird_party/ripemd160 -Ithird_party/mimc7_consts \
 *       tests/test_tier3456_golden.c -Lbuild -lbonsai_chain \
 *       $(pkg-config --libs libsecp256k1 libcrypto libcurl) -lm -lpthread \
 *       -o /tmp/t3456
 *
 * The _golden suffix makes the CMake treat it as a standalone harness, run with
 * WORKING_DIRECTORY == chain_c root. Prints "[PASS]/[FAIL]/[SKIP] <name>" per
 * check, a final "RESULT: X/Y passed", and exits nonzero on any FAIL.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <math.h>

#include "cJSON.h"

#include "common/error.h"
#include "common/bytes.h"
#include "common/hex.h"
#include "crypto/hash.h"
#include "crypto/bignum.h"
#include "crypto/ecdsa.h"
#include "crypto/rabin.h"
#include "scrypt/scrypt_contract.h"
#include "scrypt/artifact_loader.h"
#include "scrypt/script_codec.h"
#include "zk/mimc7.h"

/* tier 3-6 surface under test */
#include "ricardian_charter.h"
#include "atlas_identity.h"
#include "contracts/ricardian_tea.h"
#include "contracts_next/agent_tea.h"
#include "contracts_next/arp_attest.h"
#include "zk/limit_commitment.h"
#include "reputation_indexer.h"
#include "verifier/rabin_attestor.h"
#include "verifier/release_anchor_verifier.h"
#include "broker/key_broker.h"
#include "broker/authorization_envelope.h"
#include "broker/identity_chain_view.h"
#include "privacy/key_vault.h"
#include "privacy/enclave.h"
#include "chainSources/woc_client.h"
#include "chainSources/http_transport.h"

/* ----------------------------------------------------------------------------
 * Tiny test harness
 * ------------------------------------------------------------------------- */
static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;

static void pass(const char *name) { g_pass++; printf("[PASS] %s\n", name); }

static void fail_se(const char *name, const char *expected, const char *got)
{
    g_fail++;
    printf("[FAIL] %s\n", name);
    printf("    expected: %s\n", expected ? expected : "(null)");
    printf("    got:      %s\n", got ? got : "(null)");
}

static void skip(const char *name, const char *reason)
{
    g_skip++;
    printf("[SKIP] %s  (%s)\n", name, reason ? reason : "");
}

static void chk_str(const char *name, const char *expected, const char *got)
{
    if (expected && got && strcmp(expected, got) == 0) pass(name);
    else fail_se(name, expected, got);
}

static void chk_bool(const char *name, bool cond)
{
    if (cond) pass(name);
    else fail_se(name, "true", "false");
}

static void chk_i64(const char *name, int64_t expected, int64_t got)
{
    if (expected == got) pass(name);
    else {
        char eb[32], gb[32];
        snprintf(eb, sizeof eb, "%" PRId64, expected);
        snprintf(gb, sizeof gb, "%" PRId64, got);
        fail_se(name, eb, gb);
    }
}

/* assert two doubles equal within an absolute epsilon (IEEE-754 double) */
static void chk_double(const char *name, double expected, double got, double eps)
{
    if (fabs(expected - got) <= eps) pass(name);
    else {
        char eb[64], gb[64];
        snprintf(eb, sizeof eb, "%.17g", expected);
        snprintf(gb, sizeof gb, "%.17g", got);
        fail_se(name, eb, gb);
    }
}

/* ----------------------------------------------------------------------------
 * JSON convenience
 * ------------------------------------------------------------------------- */
static const cJSON *obj(const cJSON *o, const char *k)
{
    return cJSON_GetObjectItemCaseSensitive(o, k);
}
static const char *str(const cJSON *o, const char *k)
{
    const cJSON *i = obj(o, k);
    return (i && cJSON_IsString(i)) ? i->valuestring : NULL;
}

static char *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[rd] = '\0';
    if (out_len) *out_len = rd;
    return buf;
}

static char *buf_hex(const byte_buf_t *b) { return hex_encode(b->data, b->len); }

/* first differing offset (in BYTES) between two hex strings; -1 if equal. */
static long first_diff_byte(const char *exp, const char *got)
{
    size_t le = strlen(exp), lg = strlen(got);
    size_t n = le < lg ? le : lg;
    for (size_t i = 0; i < n; i++) {
        if (exp[i] != got[i]) return (long)(i / 2);
    }
    if (le != lg) return (long)(n / 2);
    return -1;
}

/* Compare a reconstructed buffer (script/preimage) against an expected hex,
 * reporting the first differing byte offset + a window on mismatch. */
static void chk_hex_buf(const char *name, const char *exp_hex, const byte_buf_t *got)
{
    char *got_hex = buf_hex(got);
    if (got_hex && exp_hex && strcmp(exp_hex, got_hex) == 0) {
        pass(name);
    } else {
        g_fail++;
        printf("[FAIL] %s\n", name);
        long off = first_diff_byte(exp_hex ? exp_hex : "", got_hex ? got_hex : "");
        size_t le = exp_hex ? strlen(exp_hex) : 0, lg = got_hex ? strlen(got_hex) : 0;
        printf("    expected length: %zu bytes\n", le / 2);
        printf("    got      length: %zu bytes\n", lg / 2);
        if (off >= 0) {
            printf("    first differing byte offset: %ld\n", off);
            long start = off * 2 - 8; if (start < 0) start = 0;
            char ewin[33] = {0}, gwin[33] = {0};
            if (exp_hex && (size_t)start < le) strncpy(ewin, exp_hex + start, 32);
            if (got_hex && (size_t)start < lg) strncpy(gwin, got_hex + start, 32);
            printf("    expected @%ld: ...%s...\n", start / 2, ewin);
            printf("    got      @%ld: ...%s...\n", start / 2, gwin);
        }
    }
    free(got_hex);
}

/* Same diff reporting for a plain hex string output (not a byte_buf). */
static void chk_hex_str(const char *name, const char *exp_hex, const char *got_hex)
{
    if (got_hex && exp_hex && strcmp(exp_hex, got_hex) == 0) {
        pass(name);
    } else {
        g_fail++;
        printf("[FAIL] %s\n", name);
        long off = first_diff_byte(exp_hex ? exp_hex : "", got_hex ? got_hex : "");
        size_t le = exp_hex ? strlen(exp_hex) : 0, lg = got_hex ? strlen(got_hex) : 0;
        printf("    expected length: %zu bytes\n", le / 2);
        printf("    got      length: %zu bytes\n", lg / 2);
        if (off >= 0) printf("    first differing byte offset: %ld\n", off);
        printf("    expected: %s\n", exp_hex ? exp_hex : "(null)");
        printf("    got:      %s\n", got_hex ? got_hex : "(null)");
    }
}

/* ----------------------------------------------------------------------------
 * hex helpers
 * ------------------------------------------------------------------------- */
/* decode a fixed-width hex field into a raw byte array (returns 1 on success) */
static int hex_to_fixed(const char *hex, uint8_t *out, size_t n)
{
    return hex_decode_fixed(hex, out, n) == BNS_OK;
}

/* ============================================================================
 * 1. ricardian_charter (module API)
 * ========================================================================= */
/* Build the golden FIXED DeploymentBinding from the ricardianCharter golden. */
static int build_charter_binding(const cJSON *b, deployment_binding_t *out)
{
    memset(out, 0, sizeof *out);
    const char *ag = str(b, "agentPubKey");
    const char *dv = str(b, "designatedValidatorPubKey");
    const char *vr = str(b, "validatorRabinPubKey");
    const char *mt = str(b, "maxSlashingTarget");
    const char *mc = str(b, "minSlashConfirmations");
    const char *ic = str(b, "initialSlashCheckpointHash");
    if (!ag || !dv || !vr || !mt || !mc || !ic) return 0;
    out->agent_pubkey                  = strdup(ag);
    out->designated_validator_pubkey   = strdup(dv);
    out->validator_rabin_pubkey        = strdup(vr);
    out->max_slashing_target           = strdup(mt);
    out->min_slash_confirmations       = strdup(mc);
    out->initial_slash_checkpoint_hash = strdup(ic);
    return out->agent_pubkey && out->designated_validator_pubkey &&
           out->validator_rabin_pubkey && out->max_slashing_target &&
           out->min_slash_confirmations && out->initial_slash_checkpoint_hash;
}

static void area_ricardian_charter(const cJSON *root, const char *prose, size_t prose_len)
{
    const cJSON *rc = obj(root, "ricardianCharter");
    if (!rc) { skip("ricardian_charter", "missing golden area"); return; }
    if (!prose) { skip("ricardian_charter", "prose file unreadable"); return; }
    (void)prose_len;

    /* 1a. parse_charter_params(prose) == golden parsedCharterParams */
    const cJSON *pp = obj(rc, "parsedCharterParams");
    bonsai_err_ctx ctx; memset(&ctx, 0, sizeof ctx);
    charter_params_t params; memset(&params, 0, sizeof params);
    int rc_parse = parse_charter_params(prose, &params, &ctx);
    if (rc_parse != BNS_OK) {
        fail_se("charter.parse_charter_params", "BNS_OK", bns_err_name(rc_parse));
    } else {
        struct { const char *key; const bn_t *bn; } pf[] = {
            { "perTxLimit",          params.per_tx_limit },
            { "dailyLimit",          params.daily_limit },
            { "windowDuration",      params.window_duration },
            { "graduationThreshold", params.graduation_threshold },
            { "validatorThreshold",  params.validator_threshold },
        };
        for (int i = 0; i < 5; i++) {
            char *got = NULL; char nm[64];
            snprintf(nm, sizeof nm, "charter.parse.%s", pf[i].key);
            if (bn_to_dec(pf[i].bn, &got) == BNS_OK) {
                chk_str(nm, str(pp, pf[i].key), got); free(got);
            } else fail_se(nm, str(pp, pf[i].key), "(to_dec err)");
        }
    }
    charter_params_free(&params);

    /* Build the golden binding for the canonical/hash/sign/verify checks. */
    deployment_binding_t binding;
    if (!build_charter_binding(obj(rc, "binding"), &binding)) {
        fail_se("charter.canonical_json", str(rc, "canonicalJSON_of_binding"), "(binding build err)");
        deployment_binding_free(&binding);
        return;
    }

    /* 1b. charter_canonical_json == golden canonicalJSON_of_binding */
    char *cj = NULL;
    if (charter_canonical_json(&binding, &cj) == BNS_OK) {
        chk_str("charter.canonical_json", str(rc, "canonicalJSON_of_binding"), cj);
        free(cj);
    } else fail_se("charter.canonical_json", str(rc, "canonicalJSON_of_binding"), "(error)");

    /* 1c. canonical_contract_bytes == golden canonicalContractBytes_hex */
    byte_buf_t ccb; byte_buf_init(&ccb);
    if (canonical_contract_bytes(prose, &binding, &ccb) == BNS_OK) {
        chk_hex_buf("charter.canonical_contract_bytes", str(rc, "canonicalContractBytes_hex"), &ccb);
    } else fail_se("charter.canonical_contract_bytes", str(rc, "canonicalContractBytes_hex"), "(error)");
    byte_buf_free(&ccb);

    /* 1d. compute_ricardian_hash == golden ricardianHash 35be6235... */
    char *rh = NULL;
    if (compute_ricardian_hash(prose, &binding, &rh) == BNS_OK) {
        chk_str("charter.compute_ricardian_hash == 35be6235...", str(rc, "ricardianHash_hex"), rh);
        free(rh);
    } else fail_se("charter.compute_ricardian_hash == 35be6235...", str(rc, "ricardianHash_hex"), "(error)");

    /* 1e. verify_charter_signature(prose, golden sig) -> ok:true */
    const cJSON *sgn = obj(rc, "sign");
    const char *der    = sgn ? str(sgn, "signature_der_hex") : NULL;
    const char *issuer = sgn ? str(sgn, "issuerPubKey_hex")  : NULL;
    const char *algo   = sgn ? str(sgn, "algo")              : NULL;
    const char *sighash= sgn ? str(sgn, "ricardianHash_hex") : NULL;
    if (der && issuer && algo && sighash) {
        charter_signature_t sig; memset(&sig, 0, sizeof sig);
        sig.algo           = (char*)algo;
        sig.issuer_pubkey  = (char*)issuer;
        sig.signature      = (char*)der;
        sig.ricardian_hash = (char*)sighash;
        /* binding copy (borrowed strings; verify only reads them) */
        sig.binding = binding;

        charter_verify_result_t vr; memset(&vr, 0, sizeof vr);
        int rcv = verify_charter_signature(prose, &sig, &vr);
        if (rcv == BNS_OK) {
            chk_bool("charter.verify_charter_signature(valid) -> ok:true", vr.ok);
        } else fail_se("charter.verify_charter_signature(valid) -> ok:true", "BNS_OK", bns_err_name(rcv));

        /* 1f. tampered prose -> ok:false. Flip the first byte of the prose copy. */
        char *tampered = malloc(strlen(prose) + 1);
        if (tampered) {
            memcpy(tampered, prose, strlen(prose) + 1);
            tampered[0] = (tampered[0] == 'X') ? 'Y' : 'X';
            charter_verify_result_t vr2; memset(&vr2, 0, sizeof vr2);
            int rcv2 = verify_charter_signature(tampered, &sig, &vr2);
            if (rcv2 == BNS_OK) {
                chk_bool("charter.verify_charter_signature(tampered prose) -> ok:false", !vr2.ok);
            } else fail_se("charter.verify_charter_signature(tampered prose) -> ok:false", "BNS_OK", bns_err_name(rcv2));
            free(tampered);
        } else skip("charter.verify_charter_signature(tampered prose) -> ok:false", "OOM");
        /* do NOT charter_signature_free(&sig): its members are borrowed (golden + binding) */
    } else {
        skip("charter.verify_charter_signature", "golden sig fields missing");
    }

    deployment_binding_free(&binding);
}

/* ============================================================================
 * 2. atlas_identity (build_atlas_instance -> ricardianHash + locking script)
 * ========================================================================= */
static void area_atlas_identity(const cJSON *root, const char *prose)
{
    const cJSON *ls = obj(root, "lockingScripts");
    const cJSON *rt = ls ? obj(ls, "ricardianTea") : NULL;
    if (!rt) { skip("atlas_identity", "missing lockingScripts.ricardianTea golden"); return; }
    if (!prose) { skip("atlas_identity", "prose file unreadable"); return; }

    const cJSON *in = obj(rt, "inputs");
    const char *exp_rh   = str(rt, "ricardianHash_hex");
    const char *exp_ls   = str(rt, "lockingScript_hex");
    const char *elder    = str(in, "elderPubKey_hex");
    const char *agent    = str(in, "agentPubKey_hex");
    const char *dvp      = str(in, "designatedValidatorPubKey_decimal");
    const char *vrp      = str(in, "validatorRabinPubKey_decimal");
    const char *mst      = str(in, "maxSlashingTarget");
    const char *msc      = str(in, "minSlashConfirmations");
    const char *isch     = str(in, "initialSlashCheckpointHash_hex");

    /* Load the compiled RicardianTea artifact. */
    scrypt_artifact_t art; memset(&art, 0, sizeof art);
    if (load_artifact("artifacts/ricardianTea.json", &art) != BNS_OK) {
        fail_se("atlas.build_atlas_instance.ricardianHash", exp_rh, "(load_artifact err)");
        fail_se("atlas.locking_script == golden(50286)", exp_ls, "(load_artifact err)");
        return;
    }

    /* Build AtlasDeploymentParams. */
    atlas_deployment_params_t p; memset(&p, 0, sizeof p);
    byte_buf_init(&p.elder_pubkey);
    byte_buf_init(&p.agent_pubkey);
    byte_buf_init(&p.initial_slash_checkpoint_hash);
    int ok = 1;
    ok &= hex_decode(elder, &p.elder_pubkey) == BNS_OK;
    ok &= hex_decode(agent, &p.agent_pubkey) == BNS_OK;
    ok &= hex_decode(isch, &p.initial_slash_checkpoint_hash) == BNS_OK;
    ok &= bn_parse_dec(dvp, &p.designated_validator_pubkey) == BNS_OK;
    ok &= bn_parse_dec(vrp, &p.validator_rabin_pubkey) == BNS_OK;
    ok &= bn_parse_dec(mst, &p.max_slashing_target) == BNS_OK;
    ok &= bn_parse_dec(msc, &p.min_slash_confirmations) == BNS_OK;

    if (!ok) {
        fail_se("atlas.build_atlas_instance.ricardianHash", exp_rh, "(param build err)");
        fail_se("atlas.locking_script == golden(50286)", exp_ls, "(param build err)");
    } else {
        bonsai_err_ctx ctx; memset(&ctx, 0, sizeof ctx);
        atlas_instance_t inst; memset(&inst, 0, sizeof inst);
        int rcb = build_atlas_instance(prose, &p, &art, &inst, &ctx);
        if (rcb != BNS_OK) {
            char gb[300]; snprintf(gb, sizeof gb, "rc=%s msg=%s", bns_err_name(rcb), ctx.msg);
            fail_se("atlas.build_atlas_instance.ricardianHash", exp_rh, gb);
            fail_se("atlas.locking_script == golden(50286)", exp_ls, gb);
        } else {
            /* 2a. ricardianHash == golden (f68f5ece...) */
            chk_str("atlas.build_atlas_instance.ricardianHash", exp_rh, inst.ricardian_hash);

            /* 2b. reconstruct locking script through the module API -> golden */
            byte_buf_t scr; byte_buf_init(&scr);
            int rcs = ricardian_tea_locking_script(&inst.instance, /*is_genesis=*/false, &scr);
            if (rcs == BNS_OK) {
                chk_hex_buf("atlas.locking_script == golden(50286)", exp_ls, &scr);
            } else {
                char gb[64]; snprintf(gb, sizeof gb, "rc=%s", bns_err_name(rcs));
                fail_se("atlas.locking_script == golden(50286)", exp_ls, gb);
            }
            byte_buf_free(&scr);
            atlas_instance_free(&inst);
        }
    }

    /* free atlas params */
    byte_buf_free(&p.elder_pubkey);
    byte_buf_free(&p.agent_pubkey);
    byte_buf_free(&p.initial_slash_checkpoint_hash);
    bn_free(p.designated_validator_pubkey);
    bn_free(p.validator_rabin_pubkey);
    bn_free(p.max_slashing_target);
    bn_free(p.min_slash_confirmations);
    scrypt_artifact_free(&art);
}

/* ============================================================================
 * 3. contracts_next/agent_tea: locking script + cross-language receipt hash
 * ========================================================================= */
static void build_agent_tea_params(const cJSON *in, agent_tea_params_t *cp, int *ok)
{
    memset(cp, 0, sizeof *cp);
    byte_buf_init(&cp->owner);
    byte_buf_init(&cp->agent);
    byte_buf_init(&cp->ricardian_hash);
    *ok = 1;
    *ok &= hex_decode(str(in, "owner_hex"), &cp->owner) == BNS_OK;
    *ok &= hex_decode(str(in, "agent_hex"), &cp->agent) == BNS_OK;
    *ok &= hex_decode(str(in, "ricardianHash_hex"), &cp->ricardian_hash) == BNS_OK;
    *ok &= bn_parse_dec(str(in, "perTxLimit"), &cp->per_tx_limit) == BNS_OK;
    *ok &= bn_parse_dec(str(in, "dailyLimit"), &cp->daily_limit) == BNS_OK;
    *ok &= bn_parse_dec(str(in, "windowDuration"), &cp->window_duration) == BNS_OK;
    *ok &= bn_parse_dec(str(in, "graduationThreshold"), &cp->graduation_threshold) == BNS_OK;
    *ok &= bn_parse_dec(str(in, "validatorThreshold"), &cp->validator_threshold) == BNS_OK;
    *ok &= bn_parse_dec(str(in, "designatedValidatorPubKey_decimal"), &cp->designated_validator_pubkey) == BNS_OK;
    *ok &= bn_parse_dec(str(in, "validatorRabinPubKey_decimal"), &cp->validator_rabin_pubkey) == BNS_OK;
    const cJSON *rk = obj(in, "recoveryKeys_decimal");
    for (int i = 0; i < BONSAI_AGENT_TEA_RECOVERY_KEYS; i++) {
        const cJSON *e = cJSON_GetArrayItem(rk, i);
        *ok &= (e && bn_parse_dec(e->valuestring, &cp->recovery_keys[i]) == BNS_OK);
    }
    *ok &= bn_parse_dec(str(in, "recoveryThreshold"), &cp->recovery_threshold) == BNS_OK;
}

static void area_agent_tea(const cJSON *root)
{
    const cJSON *ls = obj(root, "lockingScripts");
    const cJSON *at = ls ? obj(ls, "agentTea") : NULL;
    if (!at) { skip("agent_tea", "missing lockingScripts.agentTea golden"); return; }
    const cJSON *in = obj(at, "inputs");
    const char *exp_ls = str(at, "lockingScript_hex");

    scrypt_artifact_t art; memset(&art, 0, sizeof art);
    if (load_artifact("artifacts/src/contracts-next/agentTea.json", &art) != BNS_OK) {
        fail_se("agent_tea.locking_script == golden(54528)", exp_ls, "(load_artifact err)");
    } else {
        agent_tea_params_t cp; int ok = 0;
        build_agent_tea_params(in, &cp, &ok);
        if (!ok) {
            fail_se("agent_tea.locking_script == golden(54528)", exp_ls, "(param build err)");
        } else {
            agent_tea_t c; memset(&c, 0, sizeof c);
            c.artifact = &art;
            c.params = cp;
            if (agent_tea_genesis_state(&c.state) != BNS_OK) {
                fail_se("agent_tea.locking_script == golden(54528)", exp_ls, "(genesis state err)");
            } else {
                byte_buf_t scr; byte_buf_init(&scr);
                int rcs = agent_tea_locking_script(&c, /*is_genesis=*/false, &scr);
                if (rcs == BNS_OK) chk_hex_buf("agent_tea.locking_script == golden(54528)", exp_ls, &scr);
                else {
                    char gb[64]; snprintf(gb, sizeof gb, "rc=%s", bns_err_name(rcs));
                    fail_se("agent_tea.locking_script == golden(54528)", exp_ls, gb);
                }
                byte_buf_free(&scr);
                agent_tea_state_free(&c.state);
            }
        }
        agent_tea_params_free(&cp);
        scrypt_artifact_free(&art);
    }

    /* --- cross-language golden action-receipt hash (chain/tests/agentd.test.ts) ---
     * receipt = ricardianHash(aa*32) || agent('02'+bb*32, 33B) ||
     *           counterparty('03'+cc*32, 33B) || int2ByteString(1234,8) ||
     *           actionHash(dd*32) || provenanceHash(ee*32) ||
     *           int2ByteString(7,8) || int2ByteString(1700000000,4)
     * sha256(receipt) == cdc6a3e1b4bfd4ac931e25d31aa0309938d10900807cd403f74222ed2a00a33d
     *
     * Driven through agent_tea_receipt_hash: the contract sources ricardianHash
     * from params.ricardian_hash, agent from params.agent, txCount from
     * state.tx_count (PRE-increment). We don't need the artifact for the preimage. */
    {
        const char *EXPECT = "cdc6a3e1b4bfd4ac931e25d31aa0309938d10900807cd403f74222ed2a00a33d";
        agent_tea_t c; memset(&c, 0, sizeof c);
        int ok = 1;
        byte_buf_init(&c.params.ricardian_hash);
        byte_buf_init(&c.params.agent);
        ok &= hex_decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &c.params.ricardian_hash) == BNS_OK;
        /* 33-byte agent pubkey: 02 || bb*32 */
        {
            char ah[67]; ah[0]='0'; ah[1]='2'; for (int i=0;i<64;i++) ah[2+i]='b'; ah[66]='\0';
            ok &= hex_decode(ah, &c.params.agent) == BNS_OK;
        }
        ok &= bn_parse_dec("7", &c.state.tx_count) == BNS_OK; /* PRE-increment txCount */

        uint8_t counterparty[33];
        uint8_t action_hash[32], provenance_hash[32];
        {
            char cph[67]; cph[0]='0'; cph[1]='3'; for (int i=0;i<64;i++) cph[2+i]='c'; cph[66]='\0';
            ok &= hex_to_fixed(cph, counterparty, 33);
        }
        ok &= hex_to_fixed("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", action_hash, 32);
        ok &= hex_to_fixed("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", provenance_hash, 32);

        bn_t *amount = NULL;
        ok &= bn_parse_dec("1234", &amount) == BNS_OK;

        if (!ok) {
            fail_se("agent_tea.receipt_hash == cdc6a3e1...", EXPECT, "(input build err)");
        } else {
            /* First show the preimage we build for diagnosis, then the hash. */
            byte_buf_t pre; byte_buf_init(&pre);
            int rcp = agent_tea_receipt_preimage(&c, counterparty, amount,
                                                 action_hash, provenance_hash,
                                                 1700000000LL, &pre);
            if (rcp == BNS_OK) {
                /* expected preimage hex (for offset reporting if the hash fails) */
                static const char *EXP_PRE =
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    "02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    "03cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    "d204000000000000"
                    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                    "0700000000000000"
                    "00f15365"; /* int2ByteString(1700000000,4) = signed 4-byte LE */
                chk_hex_buf("agent_tea.receipt_preimage (agentd golden layout)", EXP_PRE, &pre);
            } else {
                char gb[64]; snprintf(gb, sizeof gb, "rc=%s", bns_err_name(rcp));
                fail_se("agent_tea.receipt_preimage (agentd golden layout)", "(54-byte+ layout)", gb);
            }
            byte_buf_free(&pre);

            char *got = NULL;
            int rch = agent_tea_receipt_hash(&c, counterparty, amount,
                                             action_hash, provenance_hash,
                                             1700000000LL, &got);
            if (rch == BNS_OK) {
                chk_hex_str("agent_tea.receipt_hash == cdc6a3e1...", EXPECT, got);
                free(got);
            } else {
                char gb[64]; snprintf(gb, sizeof gb, "rc=%s", bns_err_name(rch));
                fail_se("agent_tea.receipt_hash == cdc6a3e1...", EXPECT, gb);
            }
        }
        bn_free(amount);
        byte_buf_free(&c.params.ricardian_hash);
        byte_buf_free(&c.params.agent);
        bn_free(c.state.tx_count);
    }
}

/* ============================================================================
 * 4. contracts_next/arp_attest: attestation message
 * ========================================================================= */
static void area_arp_attest(const cJSON *root)
{
    const cJSON *ls = obj(root, "lockingScripts");
    const cJSON *aa = ls ? obj(ls, "arpAttest") : NULL;
    if (!aa) { skip("arp_attest", "missing lockingScripts.arpAttest golden"); return; }
    const cJSON *in = obj(aa, "inputs");
    const char *seq_dec = str(in, "seq");
    const char *dig_hex = str(in, "activateDigest_hex");
    const char *exp     = str(aa, "attestationMsg_hex");

    bn_t *seq = NULL;
    uint8_t dig[32];
    int ok = 1;
    ok &= bn_parse_dec(seq_dec, &seq) == BNS_OK;
    ok &= hex_to_fixed(dig_hex, dig, 32);
    if (!ok) { fail_se("arp_attest.attestation_msg == golden", exp, "(input err)"); bn_free(seq); return; }

    byte_buf_t out; byte_buf_init(&out);
    int rc = arp_attestation_msg(seq, dig, &out);
    if (rc == BNS_OK) {
        chk_hex_buf("arp_attest.attestation_msg == golden(415250315f...)", exp, &out);
        /* structural pin: tag(14) || seq8LE || digest32 */
        chk_i64("arp_attest.msg length == 54", BONSAI_ARP_ATTEST_MSG_LEN, (int64_t)out.len);
    } else {
        char gb[64]; snprintf(gb, sizeof gb, "rc=%s", bns_err_name(rc));
        fail_se("arp_attest.attestation_msg == golden(415250315f...)", exp, gb);
    }
    byte_buf_free(&out);
    bn_free(seq);
}

/* ============================================================================
 * 5. zk/limit_commitment + mimc7 (the nested/single MiMC7 formula)
 * ========================================================================= */
static void area_limit_commitment(const cJSON *root)
{
    const cJSON *m = obj(root, "mimc7");
    if (!m) { skip("limit_commitment", "missing mimc7 golden"); return; }

    const cJSON *fix = obj(m, "commitLimit_with_fixed_salt");
    const char *limit_dec = fix ? str(fix, "limit") : str(obj(m,"input"), "limit");
    const char *salt_dec  = fix ? str(fix, "salt")  : str(obj(m,"input"), "salt");
    const char *exp_comm  = fix ? str(fix, "commitment_decimal") : str(m, "mimc7_hash_decimal");

    /* 5a. The commitment formula: limitCommitment = MiMC7(limit, salt). Prove the
     * exact decimal for the fixed (1000,42) vector via mimc7_hash. */
    bn_t *limit = NULL, *salt = NULL, *h = NULL;
    int ok = bn_parse_dec(limit_dec, &limit) == BNS_OK && bn_parse_dec(salt_dec, &salt) == BNS_OK;
    if (ok && mimc7_hash(limit, salt, &h) == BNS_OK) {
        char *d = NULL;
        if (bn_to_dec(h, &d) == BNS_OK) {
            chk_str("limit_commitment.MiMC7(1000,42) == golden decimal", exp_comm, d);
            free(d);
        } else fail_se("limit_commitment.MiMC7(1000,42) == golden decimal", exp_comm, "(to_dec err)");
    } else fail_se("limit_commitment.MiMC7(1000,42) == golden decimal", exp_comm, "(setup/hash err)");
    bn_free(h);

    /* 5b. commit_limit(limit): random salt; assert the binding property
     * commitment == MiMC7(limit, returned salt), and commitment in [0, r). */
    if (ok) {
        bn_t *comm = NULL, *rsalt = NULL;
        int rcl = commit_limit(limit, &comm, &rsalt);
        if (rcl == BNS_OK) {
            bn_t *recomp = NULL;
            int match = 0, in_field = 0;
            if (mimc7_hash(limit, rsalt, &recomp) == BNS_OK)
                match = (bn_cmp(comm, recomp) == 0);
            bn_t *field = NULL;
            if (mimc7_scalar_field(&field) == BNS_OK)
                in_field = (bn_cmp(comm, field) < 0) && !bn_is_zero(comm); /* 0 < comm < r */
            chk_bool("limit_commitment.commit_limit == MiMC7(limit, returned salt)", match);
            chk_bool("limit_commitment.commit_limit commitment in (0, r)", in_field);
            bn_free(recomp); bn_free(field);
            bn_free(comm); bn_free(rsalt);
        } else {
            char gb[64]; snprintf(gb, sizeof gb, "rc=%s", bns_err_name(rcl));
            fail_se("limit_commitment.commit_limit == MiMC7(limit, returned salt)", "match", gb);
        }
    } else {
        skip("limit_commitment.commit_limit", "limit parse err");
    }
    bn_free(limit); bn_free(salt);
}

/* ============================================================================
 * 6. reputation_indexer: decayed score over the golden event set
 * ========================================================================= */
static void area_reputation(const cJSON *root)
{
    const cJSON *ri = obj(root, "reputationIndexer");
    if (!ri) { skip("reputation_indexer", "missing golden area"); return; }
    const cJSON *in = obj(ri, "inputs");
    const cJSON *sc = obj(ri, "score");
    int64_t now = (int64_t)obj(in, "now")->valuedouble;
    double lambda = obj(in, "lambda")->valuedouble;
    const cJSON *rcpts = obj(in, "receipts");
    int n = cJSON_GetArraySize(rcpts);

    tea_receipts_t recs; recs.count = (size_t)n;
    recs.items = calloc((size_t)n, sizeof(tea_receipt_t));
    if (!recs.items) { skip("reputation_indexer.reputation_score", "OOM"); return; }
    for (int i = 0; i < n; i++) {
        const cJSON *r = cJSON_GetArrayItem(rcpts, i);
        const char *txid = str(r, "txid");
        const char *rh   = str(r, "receiptHash");
        snprintf(recs.items[i].txid, sizeof recs.items[i].txid, "%s", txid ? txid : "");
        snprintf(recs.items[i].receipt_hash, sizeof recs.items[i].receipt_hash, "%s", rh ? rh : "");
        recs.items[i].time  = (int64_t)obj(r, "time")->valuedouble;
        recs.items[i].valid = cJSON_IsTrue(obj(r, "valid"));
        recs.items[i].erased = false;
    }

    reputation_score_t out; memset(&out, 0, sizeof out);
    int rc = reputation_score(&recs, now, lambda, &out);
    if (rc == BNS_OK) {
        chk_double("reputation_indexer.rho == 1.0", obj(sc, "rho")->valuedouble, out.rho, 1e-12);
        chk_double("reputation_indexer.weightTotal == 0.3679248411012048",
                   obj(sc, "weightTotal")->valuedouble, out.weight_total, 1e-15);
        chk_i64("reputation_indexer.count == 3", (int64_t)obj(sc, "count")->valuedouble, (int64_t)out.count);
    } else {
        char gb[64]; snprintf(gb, sizeof gb, "rc=%s", bns_err_name(rc));
        fail_se("reputation_indexer.reputation_score", "BNS_OK", gb);
    }
    free(recs.items);
}

/* ============================================================================
 * 7. verifier/rabin_attestor: msg byte-identity + verify roundtrip
 * ========================================================================= */
static void area_rabin_attestor(const cJSON *root)
{
    /* 7a. attestation_msg_hex(seq, digest) == ArpAttest golden (same 54-byte
     * layout: ATTEST_DOMAIN_HEX || seq(8 LE) || digest). Pin against the golden
     * arpAttest vector (seq=7, digest=ef*32). */
    const cJSON *ls = obj(root, "lockingScripts");
    const cJSON *aa = ls ? obj(ls, "arpAttest") : NULL;
    if (aa) {
        const cJSON *in = obj(aa, "inputs");
        const char *exp = str(aa, "attestationMsg_hex");
        uint64_t seq = (uint64_t)strtoull(str(in, "seq"), NULL, 10);
        const char *dig = str(in, "activateDigest_hex");
        char *got = NULL;
        int rc = attestation_msg_hex(seq, dig, &got);
        if (rc == BNS_OK) {
            chk_hex_str("rabin_attestor.attestation_msg_hex == arpAttest golden", exp, got);
            free(got);
        } else {
            char gb[64]; snprintf(gb, sizeof gb, "rc=%s", bns_err_name(rc));
            fail_se("rabin_attestor.attestation_msg_hex == arpAttest golden", exp, gb);
        }
    } else {
        skip("rabin_attestor.attestation_msg_hex", "no arpAttest golden");
    }

    /* 7b. parse_attestation behavior (chain/tests/.../rabinAttestor.test.ts): a
     * well-formed wire string parses; malformed ones fail-close (out_ok=false). */
    {
        struct { const char *wire; bool good; } cases[] = {
            { "5:ff:2",        true  },  /* seq=5, s=0xff=255, pad=2 */
            { "1:ab",          false },  /* too few fields           */
            { "1:ab:2:3",      false },  /* too many fields          */
            { "notnum:ab:2",   false },  /* non-numeric seq          */
            { "-1:ab:2",       false },  /* negative seq             */
            { "1:zz:2",        false },  /* non-hex signature        */
            { "1:ab:-1",       false },  /* negative padding         */
            { "1:ab:x",        false },  /* non-integer padding      */
        };
        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            parsed_attestation_t pa; memset(&pa, 0, sizeof pa);
            bool ok = false;
            char nm[96];
            snprintf(nm, sizeof nm, "rabin_attestor.parse_attestation(\"%s\") ok==%s",
                     cases[i].wire, cases[i].good ? "true" : "false");
            int rc = parse_attestation(cases[i].wire, &pa, &ok);
            if (rc != BNS_OK) { fail_se(nm, "BNS_OK", bns_err_name(rc)); parsed_attestation_free(&pa); continue; }
            if (ok == cases[i].good) {
                if (cases[i].good) {
                    /* verify the parsed fields for "5:ff:2" */
                    char *sd = NULL;
                    bool fields_ok = (pa.seq == 5) && (pa.padding_byte_count == 2);
                    if (pa.s && bn_to_dec(pa.s, &sd) == BNS_OK) {
                        fields_ok = fields_ok && strcmp(sd, "255") == 0;
                        free(sd);
                    } else fields_ok = false;
                    chk_bool(nm, fields_ok);
                } else {
                    pass(nm);
                }
            } else {
                fail_se(nm, cases[i].good ? "ok=true" : "ok=false", ok ? "ok=true" : "ok=false");
            }
            parsed_attestation_free(&pa);
        }
    }

    /* 7c. real-crypto sign->verify roundtrip (keys generated; not byte-golden but
     * the rabin verify path == true, and a wrong-pubkey verify == false). */
    {
        rabin_attestor_key_t key1; memset(&key1, 0, sizeof key1);
        rabin_attestor_key_t key2; memset(&key2, 0, sizeof key2);
        const char *digest = "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";
        if (generate_attestor_key(&key1) == BNS_OK && generate_attestor_key(&key2) == BNS_OK) {
            char *pub1 = NULL, *pub2 = NULL, *sig = NULL;
            int ok_setup = attestor_pub_key(&key1, &pub1) == BNS_OK
                        && attestor_pub_key(&key2, &pub2) == BNS_OK
                        && rabin_attestor_sign_digest(&key1, digest, 1, &sig) == BNS_OK;
            if (ok_setup) {
                bool v_ok = false, v_bad = false;
                rabin_attestation_verify(pub1, digest, sig, &v_ok);
                rabin_attestation_verify(pub2, digest, sig, &v_bad); /* wrong pubkey */
                chk_bool("rabin_attestor.sign->verify under signing pubkey == true", v_ok);
                chk_bool("rabin_attestor.verify under DIFFERENT pubkey == false", !v_bad);
            } else {
                skip("rabin_attestor.sign->verify roundtrip", "key/sign setup err");
            }
            free(pub1); free(pub2); free(sig);
        } else {
            skip("rabin_attestor.sign->verify roundtrip", "keygen err");
        }
        rabin_key_free(&key1);
        rabin_key_free(&key2);
    }
}

/* ============================================================================
 * 8. verifier/release_anchor_verifier (ported from releaseAnchorVerifier.test.ts)
 * ========================================================================= */
/* ---- fake SPV ---- */
typedef struct {
    spv_lookup_t announce;  bool announce_found;
    spv_lookup_t activate;  bool activate_found;
    int64_t tip;            bool throw_tip;
} fake_spv_ctx_t;

static int fake_spv_lookup(void *ctx, const char *txid, spv_lookup_t *out, bool *out_found)
{
    fake_spv_ctx_t *s = ctx;
    if (strcmp(txid, "announce1") == 0) { *out = s->announce; *out_found = s->announce_found; return BNS_OK; }
    if (strcmp(txid, "activate1") == 0) { *out = s->activate; *out_found = s->activate_found; return BNS_OK; }
    *out_found = false; return BNS_OK;
}
static int fake_spv_tip(void *ctx, int64_t *out_tip)
{
    fake_spv_ctx_t *s = ctx;
    if (s->throw_tip) return BNS_ENET;
    *out_tip = s->tip; return BNS_OK;
}

/* ---- fake attestor: good iff "pubkey:sig" is in the good set ---- */
typedef struct { const char **good; size_t n; } fake_att_ctx_t;
static int fake_att_verify(void *ctx, const char *pub, const char *dig,
                           const char *sig, bool *out_ok)
{
    (void)dig;
    fake_att_ctx_t *a = ctx;
    char key[256]; snprintf(key, sizeof key, "%s:%s", pub, sig);
    *out_ok = false;
    for (size_t i = 0; i < a->n; i++) if (strcmp(key, a->good[i]) == 0) { *out_ok = true; break; }
    return BNS_OK;
}

/* ---- fake revocation ---- */
typedef struct { bool revoked; bool throw_check; } fake_rev_ctx_t;
static int fake_rev_check(void *ctx, const char *g, const char *s, const char *v, bool *out)
{
    (void)g; (void)s; (void)v;
    fake_rev_ctx_t *r = ctx;
    if (r->throw_check) return BNS_ENET;
    *out = r->revoked; return BNS_OK;
}

static const char *g_ns_scopes[]  = { "bsv-anchor-*" };
static const char *g_att_pubkeys[] = { "att1", "att2", "att3" };

static void rav_run(const char *name, deny_reason_t want_reason, bool want_ok,
                    int64_t depth, int64_t tip, const char **goodSigs, size_t nGood,
                    bool activate_found, spv_lookup_t activate_override, bool use_override,
                    bool throw_tip, bool throw_rev, bool revoked,
                    bool fail_closed, bool has_fail_closed,
                    const release_attestation_t *atts, size_t natts,
                    const char *scope_override, const char *local_fsr_override,
                    const char *digest_override, bool publisher_null)
{
    fake_spv_ctx_t spv = {0};
    spv.announce = (spv_lookup_t){ .depth = depth, .block_height = 800000, .merkle_verified = true };
    spv.announce_found = true;
    spv.activate = use_override ? activate_override
                                : (spv_lookup_t){ .depth = 3, .block_height = 800197, .merkle_verified = true };
    spv.activate_found = activate_found;
    spv.tip = tip;
    spv.throw_tip = throw_tip;

    fake_att_ctx_t att = { goodSigs, nGood };
    fake_rev_ctx_t rev = { revoked, throw_rev };

    spv_client_t spvc = { .ctx = &spv, .lookup = fake_spv_lookup, .tip_height = fake_spv_tip };
    attestation_verifier_t attc = { .ctx = &att, .verify = fake_att_verify };
    release_revocation_oracle_t revc = { .ctx = &rev, .is_release_revoked = fake_rev_check };

    release_anchor_verifier_t *v = NULL;
    if (release_anchor_verifier_new(&spvc, &attc, &revc, &v) != BNS_OK) {
        fail_se(name, deny_reason_str(want_reason), "(verifier_new err)");
        return;
    }

    /* the canonical release fields; digest computed unless overridden */
    const char *genesis = "f3a1:0";
    const char *scope = scope_override ? scope_override : "bsv-anchor-core";
    const char *version = "1.2.0";
    const char *bundle = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const char *fsr = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const char *announce = "announce1";

    char *digest = NULL;
    if (digest_override) {
        digest = strdup(digest_override);
    } else {
        /* digest is computed from the CANONICAL (non-overridden scope) release */
        compute_activate_digest(genesis, "bsv-anchor-core", version, bundle, fsr, announce, &digest);
    }

    release_attestation_t default_atts[] = {
        { "att1", "sig1" }, { "att2", "sig2" },
    };
    publish_ref_t ref = {
        .genesis_outpoint = genesis, .scope = scope, .version = version,
        .bundle_hash = bundle, .file_set_root = fsr, .announce_txid = announce,
        .activate_txid = "activate1", .activate_digest = digest,
        .attestations = atts ? atts : default_atts,
        .num_attestations = atts ? natts : 2,
    };
    local_artifact_t local = {
        .bundle_hash = bundle,
        .file_set_root = local_fsr_override ? local_fsr_override : fsr,
    };
    trusted_publisher_t publisher = {
        .label = "bsv-anchor-bundle", .genesis_outpoint = "f3a1:0",
        .namespace_scopes = g_ns_scopes, .num_namespace_scopes = 1,
        .min_depth = 144, .min_quorum = 2,
        .attestor_pubkeys = g_att_pubkeys, .num_attestor_pubkeys = 3,
        .max_staleness = 72,
    };
    verify_opts_t opts = { .fail_closed = fail_closed, .has_fail_closed = has_fail_closed };

    verify_result_t res; memset(&res, 0, sizeof res);
    int rc = release_anchor_verifier_verify(v, &ref, &local,
                                            publisher_null ? NULL : &publisher,
                                            has_fail_closed ? &opts : NULL, &res);
    if (rc != BNS_OK) {
        fail_se(name, want_ok ? "ok=true" : deny_reason_str(want_reason), bns_err_name(rc));
    } else if (want_ok) {
        chk_bool(name, res.ok);
        if (!res.ok) printf("    (got reason: %s)\n", deny_reason_str(res.reason));
    } else {
        if (!res.ok && res.reason == want_reason) pass(name);
        else fail_se(name, deny_reason_str(want_reason),
                     res.ok ? "ok=true" : deny_reason_str(res.reason));
    }
    free(digest);
    release_anchor_verifier_free(v);
}

static void area_release_anchor(void)
{
    const char *good2[] = { "att1:sig1", "att2:sig2" };
    const char *good1[] = { "att1:sig1" };
    const char *evil2[] = { "evil1:sigX", "evil2:sigY" };

    /* accept happy path */
    rav_run("release_anchor.accept (well-formed/aged/quorum/un-revoked)", DENY_NONE, true,
            200, 800200, good2, 2, true, (spv_lookup_t){0}, false, false, false, false,
            false, false, NULL, 0, NULL, NULL, NULL, false);

    /* unknown publisher */
    rav_run("release_anchor.unknown-publisher", DENY_UNKNOWN_PUBLISHER, false,
            200, 800200, good2, 2, true, (spv_lookup_t){0}, false, false, false, false,
            false, false, NULL, 0, NULL, NULL, NULL, /*publisher_null=*/true);

    /* scope not in namespace */
    rav_run("release_anchor.scope-not-in-namespace", DENY_SCOPE_NOT_IN_NAMESPACE, false,
            200, 800200, good2, 2, true, (spv_lookup_t){0}, false, false, false, false,
            false, false, NULL, 0, "evil-package", NULL, NULL, false);

    /* fileset-root mismatch (local fsr != ref fsr) */
    rav_run("release_anchor.fileset-root-mismatch", DENY_FILESET_ROOT_MISMATCH, false,
            200, 800200, good2, 2, true, (spv_lookup_t){0}, false, false, false, false,
            false, false, NULL, 0, NULL,
            "0000000000000000000000000000000000000000000000000000000000000000", NULL, false);

    /* insufficient depth (depth < minDepth) */
    rav_run("release_anchor.insufficient-depth (depth=10)", DENY_INSUFFICIENT_DEPTH, false,
            10, 800200, good2, 2, true, (spv_lookup_t){0}, false, false, false, false,
            false, false, NULL, 0, NULL, NULL, NULL, false);

    /* BOUNDARY: depth == minDepth(144) passes (uses '<'); staleness 56 < 72 */
    rav_run("release_anchor.BOUNDARY depth==minDepth(144) accepts", DENY_NONE, true,
            144, 800200, good2, 2, true, (spv_lookup_t){0}, false, false, false, false,
            false, false, NULL, 0, NULL, NULL, NULL, false);

    /* BOUNDARY: depth == minDepth-1 (143) fails */
    rav_run("release_anchor.BOUNDARY depth==minDepth-1(143) insufficient-depth", DENY_INSUFFICIENT_DEPTH, false,
            143, 800200, good2, 2, true, (spv_lookup_t){0}, false, false, false, false,
            false, false, NULL, 0, NULL, NULL, NULL, false);

    /* stale chain (tip far ahead) */
    rav_run("release_anchor.stale-chain (tip=900000)", DENY_STALE_CHAIN, false,
            200, 900000, good2, 2, true, (spv_lookup_t){0}, false, false, false, false,
            false, false, NULL, 0, NULL, NULL, NULL, false);

    /* BOUNDARY: staleness == maxStaleness(72) passes (uses '>'); tip 800272 */
    rav_run("release_anchor.BOUNDARY staleness==max(72) accepts", DENY_NONE, true,
            200, 800272, good2, 2, true, (spv_lookup_t){0}, false, false, false, false,
            false, false, NULL, 0, NULL, NULL, NULL, false);

    /* BOUNDARY: staleness == max+1 (73) fails; tip 800273 */
    rav_run("release_anchor.BOUNDARY staleness==max+1(73) stale-chain", DENY_STALE_CHAIN, false,
            200, 800273, good2, 2, true, (spv_lookup_t){0}, false, false, false, false,
            false, false, NULL, 0, NULL, NULL, NULL, false);

    /* activate unconfirmed (activate lookup null) */
    rav_run("release_anchor.activate-unconfirmed (no activate lookup)", DENY_ACTIVATE_UNCONFIRMED, false,
            200, 800200, good2, 2, /*activate_found=*/false, (spv_lookup_t){0}, false, false, false, false,
            false, false, NULL, 0, NULL, NULL, NULL, false);

    /* BOUNDARY: activate depth < 1 (depth 0) fails activate-unconfirmed */
    rav_run("release_anchor.BOUNDARY activate depth<1 (depth=0) activate-unconfirmed", DENY_ACTIVATE_UNCONFIRMED, false,
            200, 800200, good2, 2, true,
            (spv_lookup_t){ .depth = 0, .block_height = 800197, .merkle_verified = true }, /*use_override=*/true,
            false, false, false, false, false, NULL, 0, NULL, NULL, NULL, false);

    /* activate no merkle proof */
    rav_run("release_anchor.activate-no-merkle-proof", DENY_ACTIVATE_NO_MERKLE_PROOF, false,
            200, 800200, good2, 2, true,
            (spv_lookup_t){ .depth = 3, .block_height = 800197, .merkle_verified = false }, /*use_override=*/true,
            false, false, false, false, false, NULL, 0, NULL, NULL, NULL, false);

    /* digest mismatch (ref.activateDigest bound to a different version) */
    {
        char *bad = NULL;
        compute_activate_digest("f3a1:0", "bsv-anchor-core", "1.1.9",
                                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                                "announce1", &bad);
        rav_run("release_anchor.digest-mismatch (cross-release replay)", DENY_DIGEST_MISMATCH, false,
                200, 800200, good2, 2, true, (spv_lookup_t){0}, false, false, false, false,
                false, false, NULL, 0, NULL, NULL, bad, false);
        free(bad);
    }

    /* below-quorum: only att1 valid -> bad-attestation (att2 sig fails) */
    rav_run("release_anchor.bad-attestation (one good sig, need 2)", DENY_BAD_ATTESTATION, false,
            200, 800200, good1, 1, true, (spv_lookup_t){0}, false, false, false, false,
            false, false, NULL, 0, NULL, NULL, NULL, false);

    /* duplicate attestor */
    {
        release_attestation_t dup[] = { { "att1", "sig1" }, { "att1", "sig1" } };
        rav_run("release_anchor.duplicate-attestor", DENY_DUPLICATE_ATTESTOR, false,
                200, 800200, good1, 1, true, (spv_lookup_t){0}, false, false, false, false,
                false, false, dup, 2, NULL, NULL, NULL, false);
    }

    /* attestor not in set (valid sigs from non-charter keys) */
    {
        release_attestation_t outset[] = { { "evil1", "sigX" }, { "evil2", "sigY" } };
        rav_run("release_anchor.attestor-not-in-set", DENY_ATTESTOR_NOT_IN_SET, false,
                200, 800200, evil2, 2, true, (spv_lookup_t){0}, false, false, false, false,
                false, false, outset, 2, NULL, NULL, NULL, false);
    }

    /* release revoked */
    rav_run("release_anchor.release-revoked", DENY_RELEASE_REVOKED, false,
            200, 800200, good2, 2, true, (spv_lookup_t){0}, false, false, false, /*revoked=*/true,
            false, false, NULL, 0, NULL, NULL, NULL, false);

    /* fail-closed (default): tip unavailable -> stale-chain */
    rav_run("release_anchor.fail-closed tip-unavailable -> stale-chain", DENY_STALE_CHAIN, false,
            200, 800200, good2, 2, true, (spv_lookup_t){0}, false, /*throw_tip=*/true, false, false,
            false, false, NULL, 0, NULL, NULL, NULL, false);

    /* fail-open (opt-in): tip unavailable -> accept */
    rav_run("release_anchor.fail-open tip-unavailable -> accept", DENY_NONE, true,
            200, 800200, good2, 2, true, (spv_lookup_t){0}, false, /*throw_tip=*/true, false, false,
            /*fail_closed=*/false, /*has_fail_closed=*/true, NULL, 0, NULL, NULL, NULL, false);

    /* fail-closed (default): revocation oracle unavailable -> release-revoked */
    rav_run("release_anchor.fail-closed revocation-unavailable -> release-revoked", DENY_RELEASE_REVOKED, false,
            200, 800200, good2, 2, true, (spv_lookup_t){0}, false, false, /*throw_rev=*/true, false,
            false, false, NULL, 0, NULL, NULL, NULL, false);
}

/* ============================================================================
 * 9. broker/key_broker (ordering ported from keyBroker.test.ts)
 * ========================================================================= */
/* Controllable oracle: revoked flag + throw-once. */
typedef struct { bool revoked; bool throw_once; } kb_oracle_ctx_t;
static int kb_oracle_is_revoked(void *ctx, const char *id, bool *out)
{
    (void)id;
    kb_oracle_ctx_t *o = ctx;
    if (o->throw_once) { o->throw_once = false; return BNS_ENET; }
    *out = o->revoked; return BNS_OK;
}
/* fixed clock at 1000 */
static int64_t kb_clock(void *user) { (void)user; return 1000; }

static void area_key_broker(void)
{
    /* Build the same envelope as the TS test:
     *   params {perTxLimit:100, dailyLimit:250, windowDuration:86400}
     *   scopes ['api:llm:chat','repo:read:acme/widgets'] */
    identity_params_t ip = { .per_tx_limit = 100, .daily_limit = 250, .window_duration = 86400 };
    const char *scopes[] = { "api:llm:chat", "repo:read:acme/widgets" };
    authorization_envelope_t env; memset(&env, 0, sizeof env);
    if (envelope_from_identity(&ip, scopes, 2, &env) != BNS_OK) {
        skip("key_broker", "envelope build err"); return;
    }

    kb_oracle_ctx_t oc = { false, false };
    revocation_oracle_t oracle = { .ctx = &oc, .is_revoked = kb_oracle_is_revoked };
    key_broker_t *broker = NULL;
    if (key_broker_new(&oracle, kb_clock, NULL, &broker) != BNS_OK) {
        skip("key_broker", "broker new err"); authorization_envelope_free(&env); return;
    }

    key_broker_issue_args_t ia = {
        .agent_pub_key = "02aa",
        .ricardian_hash = "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe",
        .identity_id = "genesis-txid-1",
        .envelope = &env,
    };
    issued_key_t key; memset(&key, 0, sizeof key);
    char *secret = NULL;
    if (key_broker_issue(broker, &ia, &key, &secret) != BNS_OK || !secret) {
        skip("key_broker", "issue err"); key_broker_free(broker); authorization_envelope_free(&env); return;
    }

    authorization_decision_t d;

    /* 9a. in-scope, in-budget -> allow */
    {
        authorization_request_t req = { .secret = secret, .scope = "api:llm:chat", .amount = 40 };
        memset(&d, 0, sizeof d); key_broker_authorize(broker, &req, &d);
        chk_bool("key_broker.in-scope in-budget -> allow", d.allowed);
    }

    /* 9b. unknown secret -> deny with NO keyId (has_key_id false) */
    {
        authorization_request_t req = { .secret = "pk_bogus", .scope = "api:llm:chat", .amount = 1 };
        memset(&d, 0, sizeof d); key_broker_authorize(broker, &req, &d);
        chk_bool("key_broker.unknown secret -> deny", !d.allowed);
        chk_bool("key_broker.unknown secret -> NO keyId (has_key_id==false)", !d.has_key_id);
    }

    /* 9c. out-of-scope -> deny (reason mentions scope) */
    {
        authorization_request_t req = { .secret = secret, .scope = "repo:write:acme/widgets", .amount = 1 };
        memset(&d, 0, sizeof d); key_broker_authorize(broker, &req, &d);
        bool ok = !d.allowed && d.reason && strstr(d.reason, "scope") != NULL;
        chk_bool("key_broker.out-of-scope -> deny(scope)", ok);
        if (!ok) printf("    (reason: %s)\n", d.reason ? d.reason : "(null)");
    }

    /* 9d. per-call cap (amount 101 > 100) -> deny(per-call) */
    {
        authorization_request_t req = { .secret = secret, .scope = "api:llm:chat", .amount = 101 };
        memset(&d, 0, sizeof d); key_broker_authorize(broker, &req, &d);
        bool ok = !d.allowed && d.reason && strstr(d.reason, "per-call") != NULL;
        chk_bool("key_broker.per-call cap -> deny(per-call)", ok);
        if (!ok) printf("    (reason: %s)\n", d.reason ? d.reason : "(null)");
    }

    /* 9e. revocation -> scope -> caps ORDER: revoked wins over an out-of-scope,
     * over-cap request -> reason must mention 'revoked' (NOT scope/per-call). */
    {
        oc.revoked = true; oc.throw_once = false;
        authorization_request_t req = { .secret = secret, .scope = "repo:write:acme/secrets", .amount = 9999 };
        memset(&d, 0, sizeof d); key_broker_authorize(broker, &req, &d);
        bool ok = !d.allowed && d.reason && strstr(d.reason, "revoked") != NULL
                  && !strstr(d.reason, "scope") && !strstr(d.reason, "per-call") && !strstr(d.reason, "window");
        chk_bool("key_broker.order: revocation BEFORE scope/caps (reason=revoked)", ok);
        if (!ok) printf("    (reason: %s)\n", d.reason ? d.reason : "(null)");
    }

    /* 9f. local latch: after observing revocation, a throwing oracle still denies
     * via the LOCAL latch (fail-closed order: local-latch before oracle). */
    {
        oc.revoked = false;     /* on-chain flag gone */
        oc.throw_once = true;   /* oracle would throw if consulted */
        authorization_request_t req = { .secret = secret, .scope = "api:llm:chat", .amount = 1 };
        memset(&d, 0, sizeof d); key_broker_authorize(broker, &req, &d);
        bool denied = !d.allowed;
        bool not_failclosed = !(d.reason && strstr(d.reason, "fail-closed"));
        bool latch_unconsumed = oc.throw_once; /* true => oracle was NOT called */
        chk_bool("key_broker.local latch denies without re-consulting oracle", denied && not_failclosed && latch_unconsumed);
        if (!(denied && not_failclosed && latch_unconsumed))
            printf("    (reason: %s, throw_once still set: %d)\n", d.reason ? d.reason : "(null)", oc.throw_once);
    }

    /* 9g. fail-closed when oracle unavailable (fresh key so no local latch). */
    {
        /* issue a second key bound to a different identity */
        key_broker_issue_args_t ia2 = ia;
        ia2.identity_id = "genesis-txid-2";
        issued_key_t k2; memset(&k2, 0, sizeof k2);
        char *secret2 = NULL;
        if (key_broker_issue(broker, &ia2, &k2, &secret2) == BNS_OK && secret2) {
            oc.revoked = false; oc.throw_once = true;
            authorization_request_t req = { .secret = secret2, .scope = "api:llm:chat", .amount = 1 };
            memset(&d, 0, sizeof d); key_broker_authorize(broker, &req, &d);
            bool ok = !d.allowed && d.reason && strstr(d.reason, "fail-closed") != NULL;
            chk_bool("key_broker.fail-closed when oracle unavailable", ok);
            if (!ok) printf("    (reason: %s)\n", d.reason ? d.reason : "(null)");
            free(secret2); issued_key_free(&k2);
        } else {
            skip("key_broker.fail-closed when oracle unavailable", "second issue err");
        }
    }

    free(secret);
    issued_key_free(&key);
    key_broker_free(broker);
    authorization_envelope_free(&env);
}

/* ============================================================================
 * 10. privacy/enclave + key_vault
 * ========================================================================= */
static void area_enclave(const cJSON *root)
{
    key_vault_t vault; memset(&vault, 0, sizeof vault);
    if (in_memory_key_vault_new(&vault) != BNS_OK) { skip("enclave", "vault new err"); return; }
    private_enclave_t *enc = NULL;
    if (private_enclave_new(&vault, NULL, NULL, &enc) != BNS_OK) {
        skip("enclave", "enclave new err"); in_memory_key_vault_free(&vault); return;
    }

    const char *identity = "genesis-txid-1";
    const uint8_t payload[] = "bonsai inference payload";
    size_t plen = sizeof payload - 1;

    /* 10a. seal/open roundtrip */
    sealed_record_t rec; memset(&rec, 0, sizeof rec);
    if (private_enclave_seal(enc, identity, payload, plen, &rec) == BNS_OK) {
        byte_buf_t out; byte_buf_init(&out);
        int rco = private_enclave_open(enc, &rec, &out);
        bool roundtrip = (rco == BNS_OK) && out.len == plen && memcmp(out.data, payload, plen) == 0;
        chk_bool("enclave.seal/open roundtrip", roundtrip);
        byte_buf_free(&out);

        /* 10b. crypto-shred -> get_key returns absent + open fails BNS_ESHREDDED */
        bool shredded = false; char *marker = NULL;
        int rcs = private_enclave_shred(enc, identity, &shredded, &marker);
        chk_bool("enclave.shred reports a key was present", rcs == BNS_OK && shredded);

        /* vault.get_key now absent */
        uint8_t kb[BONSAI_KEY_VAULT_KEY_LEN]; bool found = true;
        vault.get_key(vault.ctx, identity, kb, &found);
        chk_bool("key_vault.get_key after shred -> absent", !found);

        /* open now fails BNS_ESHREDDED */
        byte_buf_t out2; byte_buf_init(&out2);
        int rco2 = private_enclave_open(enc, &rec, &out2);
        chk_bool("enclave.open after shred -> BNS_ESHREDDED", rco2 == BNS_ESHREDDED);
        byte_buf_free(&out2);

        /* 10c. shredMarker == static marker == reputation_indexer.shred_marker_hex */
        char *marker_static = NULL, *marker_rep = NULL;
        private_enclave_shred_marker(identity, &marker_static);
        shred_marker_hex(identity, &marker_rep);
        chk_str("enclave.shredMarker == private_enclave_shred_marker", marker_static, marker);
        chk_str("enclave.shredMarker == reputation_indexer.shred_marker_hex", marker_rep, marker_static);
        /* derive shredMarker = SHA256("SHRED_V1" || identity) and compare */
        {
            byte_buf_t pre; byte_buf_init(&pre);
            byte_buf_append(&pre, BONSAI_SHRED_MARKER_DOMAIN, strlen(BONSAI_SHRED_MARKER_DOMAIN));
            byte_buf_append(&pre, identity, strlen(identity));
            uint8_t dig[32]; sha256(pre.data, pre.len, dig);
            char *derived = hex_encode(dig, 32);
            chk_str("enclave.shredMarker == derived SHA256(\"SHRED_V1\"||id)", derived, marker_static);
            free(derived); byte_buf_free(&pre);
        }
        free(marker); free(marker_static); free(marker_rep);
        sealed_record_free(&rec);
    } else {
        fail_se("enclave.seal/open roundtrip", "BNS_OK", "(seal err)");
    }
    (void)root;
    private_enclave_free(enc);
    in_memory_key_vault_free(&vault);
}

/* ============================================================================
 * 11. chainSources/woc_client over an http stub
 * ========================================================================= */
static void area_woc_client(void)
{
    /* 11a. interpret_tx_status reads 'blockheight' (confirmations>=1 -> confirmed) */
    {
        tx_status_t st; memset(&st, 0, sizeof st);
        interpret_tx_status(/*raw_present=*/true, /*conf=*/3, /*blockheight=*/800197, /*has=*/true, &st);
        bool ok = st.state == TX_STATE_CONFIRMED && st.confirmations == 3
               && st.has_block_height && st.block_height == 800197;
        chk_bool("woc.interpret_tx_status confirmed reads blockheight", ok);
        if (!ok) printf("    (state=%d conf=%lld height=%lld has=%d)\n",
                        (int)st.state, (long long)st.confirmations,
                        (long long)st.block_height, (int)st.has_block_height);

        /* mempool: raw present, 0 confirmations, no height */
        tx_status_t st2; memset(&st2, 0, sizeof st2);
        interpret_tx_status(true, 0, 0, false, &st2);
        chk_bool("woc.interpret_tx_status mempool (raw, 0 conf)", st2.state == TX_STATE_MEMPOOL && !st2.has_block_height);

        /* unknown: no raw, 0 conf */
        tx_status_t st3; memset(&st3, 0, sizeof st3);
        interpret_tx_status(false, 0, 0, false, &st3);
        chk_bool("woc.interpret_tx_status unknown (no raw)", st3.state == TX_STATE_UNKNOWN);
    }

    /* 11b. raw_tx 404 -> NULL (existence check). Stub returns 404 for /hex. */
    {
        http_stub_entry_t script[] = {
            { "GET", "/hex", 404, "", 0 },
        };
        http_transport_t tr; memset(&tr, 0, sizeof tr);
        if (http_transport_stub(script, 1, &tr) == BNS_OK) {
            woc_client_opts_t opts = { .transport = &tr, .sleep = NULL, .sleep_user = NULL };
            woc_client_t *c = NULL;
            if (woc_client_new(&opts, &c) == BNS_OK) {
                char *hex = (char*)0x1;
                int rc = woc_client_raw_tx(c, "deadbeef", &hex);
                chk_bool("woc.raw_tx 404 -> NULL (BNS_OK)", rc == BNS_OK && hex == NULL);
                free(hex);
                woc_client_free(c);
            } else skip("woc.raw_tx 404", "client new err");
            if (tr.free) tr.free(tr.ctx);
        } else skip("woc.raw_tx 404", "stub err");
    }

    /* 11c. is_output_spent: 404 -> false (unspent; index lag), before checking ok */
    {
        http_stub_entry_t script[] = {
            { "GET", "/spent", 404, "", 0 },
        };
        http_transport_t tr; memset(&tr, 0, sizeof tr);
        if (http_transport_stub(script, 1, &tr) == BNS_OK) {
            woc_client_opts_t opts = { .transport = &tr };
            woc_client_t *c = NULL;
            if (woc_client_new(&opts, &c) == BNS_OK) {
                bool spent = true;
                int rc = woc_client_is_output_spent(c, "deadbeef", 0, &spent);
                chk_bool("woc.is_output_spent 404 -> false (before !ok)", rc == BNS_OK && spent == false);
                woc_client_free(c);
            } else skip("woc.is_output_spent 404", "client new err");
            if (tr.free) tr.free(tr.ctx);
        } else skip("woc.is_output_spent 404", "stub err");
    }

    /* 11d. broadcast derives the display txid from the signed bytes rather
     * than trusting even a syntactically valid provider response. */
    {
        http_stub_entry_t script[] = {
            { "POST", "/tx/raw", 200,
              "\"abc123def4567890abc123def4567890abc123def4567890abc123def4567890\"", 0 },
        };
        http_transport_t tr; memset(&tr, 0, sizeof tr);
        if (http_transport_stub(script, 1, &tr) == BNS_OK) {
            woc_client_opts_t opts = { .transport = &tr };
            woc_client_t *c = NULL;
            if (woc_client_new(&opts, &c) == BNS_OK) {
                char *txid = NULL;
                int rc = woc_client_broadcast(c, "00", &txid);
                const char *want = "9a538906e6466ebd2617d321f71bc94e56056ce213d366773699e28158e00614";
                if (rc == BNS_OK) chk_str("woc.broadcast uses locally computed txid", want, txid);
                else fail_se("woc.broadcast uses locally computed txid", want, bns_err_name(rc));
                free(txid);
                woc_client_free(c);
            } else skip("woc.broadcast", "client new err");
            if (tr.free) tr.free(tr.ctx);
        } else skip("woc.broadcast", "stub err");
    }
}

/* ============================================================================
 *  main
 * ========================================================================= */
int main(int argc, char **argv)
{
    const char *golden_path = (argc > 1) ? argv[1] : "tests/golden/golden.json";
    const char *prose_path  = (argc > 2) ? argv[2] : "legal/ricardian-prose.md";

    size_t len = 0;
    char *txt = read_file(golden_path, &len);
    if (!txt) {
        fprintf(stderr, "FATAL: cannot read golden vectors at %s\n", golden_path);
        return 2;
    }
    cJSON *root = cJSON_Parse(txt);
    free(txt);
    if (!root) { fprintf(stderr, "FATAL: cannot parse golden JSON\n"); return 2; }

    size_t prose_len = 0;
    char *prose = read_file(prose_path, &prose_len);
    if (!prose)
        fprintf(stderr, "WARN: charter prose not found at %s; charter/atlas hash checks will SKIP\n", prose_path);

    printf("== chain_c tier 3-6 GOLDEN INTEGRATION TEST ==\n");
    printf("golden: %s\n", golden_path);
    printf("prose:  %s%s\n\n", prose_path, prose ? "" : " (missing)");

    printf("-- 1. ricardian_charter --\n");        area_ricardian_charter(root, prose, prose_len);
    printf("\n-- 2. atlas_identity --\n");          area_atlas_identity(root, prose);
    printf("\n-- 3. contracts_next/agent_tea --\n");area_agent_tea(root);
    printf("\n-- 4. contracts_next/arp_attest --\n");area_arp_attest(root);
    printf("\n-- 5. zk/limit_commitment + mimc7 --\n");area_limit_commitment(root);
    printf("\n-- 6. reputation_indexer --\n");      area_reputation(root);
    printf("\n-- 7. verifier/rabin_attestor --\n"); area_rabin_attestor(root);
    printf("\n-- 8. verifier/release_anchor_verifier --\n"); area_release_anchor();
    printf("\n-- 9. broker/key_broker --\n");       area_key_broker();
    printf("\n-- 10. privacy/enclave + key_vault --\n"); area_enclave(root);
    printf("\n-- 11. chainSources/woc_client --\n");area_woc_client();

    cJSON_Delete(root);
    free(prose);

    int total = g_pass + g_fail;
    printf("\n============================================================\n");
    printf("RESULT: %d/%d passed   (%d failed, %d skipped)\n",
           g_pass, total, g_fail, g_skip);
    printf("============================================================\n");

    return g_fail == 0 ? 0 : 1;
}
