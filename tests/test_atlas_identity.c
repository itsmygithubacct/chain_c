/*
 * test_atlas_identity.c — Unity port of
 * chain/tests/priscilla/atlasIdentity.test.ts
 * ("buildAtlasInstance — single source of truth, Grigg dim 1 / Theme A").
 *
 * Pins that build_atlas_instance parses the policy params OUT of the charter
 * prose (no literals) and computes ricardianHash over that SAME prose+binding,
 * and that editing one prose param changes BOTH the contract param and the hash.
 *
 * Real C public API exercised:
 *   atlas_identity.h : build_atlas_instance / atlas_instance_free
 *   ricardian_charter.h : parse_charter_params, compute_ricardian_hash
 *   contracts/ricardian_tea.h : the constructed instance's ctor params (bn_t)
 *   scrypt/artifact_loader.h : load_artifact (artifacts/ricardianTea.json)
 *   crypto/bignum.h, common/hex.h
 *
 * Runs with WORKING_DIRECTORY == chain_c root (reads legal/ricardian-prose.md
 * and artifacts/ricardianTea.json).
 *
 * The TS uses bsv.PrivateKey.fromRandom() for elder/agent; only their compressed
 * pubkey BYTES matter as binding inputs, so deterministic tx_helper keys are an
 * equivalent (and the hash equality is checked against compute_ricardian_hash
 * over the SAME built binding, not a literal golden — exactly as the TS does).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "unity.h"

#include "common/error.h"
#include "common/bytes.h"
#include "common/hex.h"
#include "crypto/bignum.h"
#include "crypto/ecdsa.h"
#include "scrypt/scrypt_contract.h"
#include "scrypt/artifact_loader.h"
#include "ricardian_charter.h"
#include "atlas_identity.h"
#include "contracts/ricardian_tea.h"

#include "tx_helper.h"

#define PROSE_PATH    "legal/ricardian-prose.md"
#define ARTIFACT_PATH "artifacts/ricardianTea.json"

static char            *g_prose = NULL;
static scrypt_artifact_t g_art;
static bool             g_art_loaded = false;

void setUp(void) {}
void tearDown(void) {}

static char *read_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[got] = '\0';
    return buf;
}

/* Build the TS `params` AtlasDeploymentParams (elder/agent pubkey bytes from
 * deterministic keys; designatedValidator=123n, validatorRabin=456n,
 * maxSlashingTarget=1n, minSlashConfirmations=1n, checkpoint = 00*32). The
 * struct's byte_buf/bn members are filled; caller frees via atlas_params_free. */
static void build_params(atlas_deployment_params_t *p)
{
    memset(p, 0, sizeof *p);
    byte_buf_init(&p->elder_pubkey);
    byte_buf_init(&p->agent_pubkey);
    byte_buf_init(&p->initial_slash_checkpoint_hash);

    uint8_t elder33[33], agent33[33];
    TEST_ASSERT_EQUAL_INT(BNS_OK, tx_helper_pubkey_bytes(TX_KEY_ELDER, elder33));
    TEST_ASSERT_EQUAL_INT(BNS_OK, tx_helper_pubkey_bytes(TX_KEY_AGENT, agent33));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&p->elder_pubkey, elder33, 33));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&p->agent_pubkey, agent33, 33));

    uint8_t zero32[32]; memset(zero32, 0, sizeof zero32);
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        byte_buf_append(&p->initial_slash_checkpoint_hash, zero32, 32));

    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("123", &p->designated_validator_pubkey));
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("456", &p->validator_rabin_pubkey));
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("1",   &p->max_slashing_target));
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("1",   &p->min_slash_confirmations));
}

static void free_params(atlas_deployment_params_t *p)
{
    byte_buf_free(&p->elder_pubkey);
    byte_buf_free(&p->agent_pubkey);
    byte_buf_free(&p->initial_slash_checkpoint_hash);
    bn_free(p->designated_validator_pubkey);
    bn_free(p->validator_rabin_pubkey);
    bn_free(p->max_slashing_target);
    bn_free(p->min_slash_confirmations);
}

static void assert_bn_eq(const bn_t *a, const bn_t *b)
{
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_NOT_NULL(b);
    TEST_ASSERT_EQUAL_INT(0, bn_cmp(a, b));
}

static void assert_bn_eq_dec(const bn_t *a, const char *dec)
{
    bn_t *w = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec(dec, &w));
    TEST_ASSERT_EQUAL_INT(0, bn_cmp(a, w));
    bn_free(w);
}

/* TS: 'builds the identity with params PARSED FROM the prose (no literals), hash
 * over the same prose'. */
static void test_builds_params_parsed_from_prose(void)
{
    if (!g_art_loaded) { TEST_IGNORE_MESSAGE("artifacts/ricardianTea.json not loadable"); return; }

    atlas_deployment_params_t p; build_params(&p);
    bonsai_err_ctx ctx; memset(&ctx, 0, sizeof ctx);
    atlas_instance_t inst; memset(&inst, 0, sizeof inst);
    int rc = build_atlas_instance(g_prose, &p, &g_art, &inst, &ctx);
    if (rc != BNS_OK) {
        char m[300]; snprintf(m, sizeof m, "build_atlas_instance rc=%s msg=%s",
                              bns_err_name(rc), ctx.msg);
        TEST_FAIL_MESSAGE(m);
    }

    /* The contract's policy params are exactly the prose-parsed ones. */
    charter_params_t parsed; memset(&parsed, 0, sizeof parsed);
    bonsai_err_ctx pctx; memset(&pctx, 0, sizeof pctx);
    TEST_ASSERT_EQUAL_INT(BNS_OK, parse_charter_params(g_prose, &parsed, &pctx));

    const ricardian_tea_params_t *cp = &inst.instance.params;
    assert_bn_eq(cp->per_tx_limit,         parsed.per_tx_limit);
    assert_bn_eq(cp->daily_limit,          parsed.daily_limit);
    assert_bn_eq(cp->window_duration,      parsed.window_duration);
    assert_bn_eq(cp->graduation_threshold, parsed.graduation_threshold);
    assert_bn_eq(cp->validator_threshold,  parsed.validator_threshold);

    /* The identity hash is over the SAME prose + the SAME (built) binding. */
    char *rh = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, compute_ricardian_hash(g_prose, &inst.binding, &rh));
    TEST_ASSERT_EQUAL_STRING(rh, inst.ricardian_hash);

    /* charter deep-equals parsed. */
    assert_bn_eq(inst.charter.per_tx_limit,         parsed.per_tx_limit);
    assert_bn_eq(inst.charter.daily_limit,          parsed.daily_limit);
    assert_bn_eq(inst.charter.window_duration,      parsed.window_duration);
    assert_bn_eq(inst.charter.graduation_threshold, parsed.graduation_threshold);
    assert_bn_eq(inst.charter.validator_threshold,  parsed.validator_threshold);

    free(rh);
    charter_params_free(&parsed);
    atlas_instance_free(&inst);
    free_params(&p);
}

/* TS: 'editing a prose param changes BOTH the contract param AND the
 * ricardianHash (true single source)'. */
static void test_editing_prose_changes_param_and_hash(void)
{
    if (!g_art_loaded) { TEST_IGNORE_MESSAGE("artifacts/ricardianTea.json not loadable"); return; }

    atlas_deployment_params_t p; build_params(&p);

    /* base build from the real prose */
    bonsai_err_ctx ctx; memset(&ctx, 0, sizeof ctx);
    atlas_instance_t base; memset(&base, 0, sizeof base);
    TEST_ASSERT_EQUAL_INT(BNS_OK, build_atlas_instance(g_prose, &p, &g_art, &base, &ctx));

    /* Bump only perTxLimit in the prose: first "100000" -> "100001". */
    char *edited = strdup(g_prose);
    TEST_ASSERT_NOT_NULL(edited);
    char *hit = strstr(edited, "100000");
    TEST_ASSERT_NOT_NULL(hit);
    hit[5] = '1';
    TEST_ASSERT_TRUE(strcmp(edited, g_prose) != 0);

    atlas_deployment_params_t p2; build_params(&p2);
    bonsai_err_ctx ctx2; memset(&ctx2, 0, sizeof ctx2);
    atlas_instance_t edinst; memset(&edinst, 0, sizeof edinst);
    TEST_ASSERT_EQUAL_INT(BNS_OK, build_atlas_instance(edited, &p2, &g_art, &edinst, &ctx2));

    /* The contract built from the edited prose carries 100001; base carries 100000. */
    assert_bn_eq_dec(edinst.instance.params.per_tx_limit, "100001");
    assert_bn_eq_dec(base.instance.params.per_tx_limit,   "100000");

    /* ...and the identity hash changes — the prose is the single source. */
    TEST_ASSERT_TRUE(strcmp(edinst.ricardian_hash, base.ricardian_hash) != 0);

    free(edited);
    atlas_instance_free(&base);
    atlas_instance_free(&edinst);
    free_params(&p);
    free_params(&p2);
}

int main(void)
{
    g_prose = read_file(PROSE_PATH);
    if (!g_prose) {
        fprintf(stderr, "FATAL: cannot read %s (run from chain_c root)\n", PROSE_PATH);
        return 2;
    }
    memset(&g_art, 0, sizeof g_art);
    g_art_loaded = (load_artifact(ARTIFACT_PATH, &g_art) == BNS_OK);

    UNITY_BEGIN();
    RUN_TEST(test_builds_params_parsed_from_prose);
    RUN_TEST(test_editing_prose_changes_param_and_hash);
    int rc = UNITY_END();

    if (g_art_loaded) scrypt_artifact_free(&g_art);
    free(g_prose);
    return rc;
}
