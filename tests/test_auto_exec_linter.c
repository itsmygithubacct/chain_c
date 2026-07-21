/*
 * test_auto_exec_linter.c — Unity port of
 *   chain/tests/priscilla/autoExecLinter.test.ts
 *
 * ARP-1's first attestor class: deterministic lint over a release manifest for
 * IDE/agent auto-exec vectors + package.json install hooks; sign-only-if-clean
 * AutoExecLinterAttestor with strictly-increasing Rabin seq; plus the
 * stake-floor consumer policy predicates.
 *
 * Covers: clean pass, every Miasma vector, nested/case-variant/Windows-path-
 * equivalence vectors, package.json hook detection (incl. case-variant filename
 * and backslash+trailing-dot), unparseable fail-closed, benign look-alikes,
 * EVERY-violation-in-one-pass ordering, attest()'s clean-sign / refuse / seq
 * invariants, and stakePolicy floors.
 *
 * One shared Rabin key (keygen is the slow part). Build+run standalone.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "unity.h"
#include "common/error.h"
#include "crypto/rabin.h"
#include "attestor/auto_exec_linter.h"
#include "verifier/rabin_attestor.h"
#include "verifier/release_anchor_verifier.h"
#include "verifier/stake_policy.h"

/* shared attestor key (generated once in main). */
static rabin_attestor_key_t g_key;
static bool g_key_ready;

#define B64 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define F64 "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

/* the TS CLEAN manifest */
static const manifest_entry_t CLEAN[] = {
    { "src/index.ts", NULL },
    { "README.md",    NULL },
    { "lib/util.js",  NULL },
};
#define CLEAN_N (sizeof(CLEAN)/sizeof(CLEAN[0]))

static const release_fields_t RELEASE = {
    .genesis_outpoint = "f3a1:0", .scope = "bsv-anchor-core", .version = "1.2.0",
    .bundle_hash = B64, .file_set_root = F64, .announce_txid = "announce1",
};

void setUp(void) {}
void tearDown(void) {}

/* ---- small helpers ------------------------------------------------------ */
static bool lint_clean(const manifest_entry_t *m, size_t n)
{
    lint_result_t r; memset(&r, 0, sizeof r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, lint_manifest(m, n, &r));
    bool clean = r.clean;
    lint_result_free(&r);
    return clean;
}

/* lint a manifest containing CLEAN plus one extra entry. */
static bool lint_clean_with_extra(const char *path, const char *content)
{
    manifest_entry_t m[CLEAN_N + 1];
    memcpy(m, CLEAN, sizeof(CLEAN));
    m[CLEAN_N].path = path; m[CLEAN_N].content = content;
    return lint_clean(m, CLEAN_N + 1);
}

/* ----------------------------------------------------------------------------
 * lintManifest
 * ------------------------------------------------------------------------- */
static void test_passes_clean_manifest(void)
{
    lint_result_t r; memset(&r, 0, sizeof r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, lint_manifest(CLEAN, CLEAN_N, &r));
    TEST_ASSERT_TRUE(r.clean);
    TEST_ASSERT_EQUAL_size_t(0u, r.violations_count);
    lint_result_free(&r);
}

static void test_catches_every_miasma_vector(void)
{
    static const char *vectors[] = {
        ".cl" "aude/settings.json",
        ".vscode/tasks.json",
        ".gemini/settings.json",
        ".cursor/rules",
        ".cursor/rules/evil.md",
        ".idea/runConfigurations/run.xml",
    };
    for (size_t i = 0; i < sizeof(vectors)/sizeof(vectors[0]); i++)
        TEST_ASSERT_FALSE_MESSAGE(lint_clean_with_extra(vectors[i], NULL), vectors[i]);
}

static void test_catches_nested_subdir_vector(void)
{
    manifest_entry_t m[] = { { "packages/widget/.cl" "aude/settings.json", NULL } };
    lint_result_t r; memset(&r, 0, sizeof r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, lint_manifest(m, 1, &r));
    TEST_ASSERT_FALSE(r.clean);
    TEST_ASSERT_GREATER_THAN_size_t(0u, r.violations_count);
    TEST_ASSERT_NOT_NULL(strstr(r.violations[0].rule, "forbidden-file"));
    lint_result_free(&r);
}

static void test_catches_case_variant_vectors(void)
{
    static const char *vectors[] = {
        ".Cl" "aude/Settings.json",
        ".CL" "AUDE/SETTINGS.JSON",
        ".VSCode/Tasks.json",
        ".Gemini/Settings.json",
        "packages/x/.Cursor/Rules/evil.md",
        ".IDEA/runConfigurations/run.xml",
    };
    for (size_t i = 0; i < sizeof(vectors)/sizeof(vectors[0]); i++) {
        manifest_entry_t m[] = { { vectors[i], NULL } };
        lint_result_t r; memset(&r, 0, sizeof r);
        TEST_ASSERT_EQUAL_INT(BNS_OK, lint_manifest(m, 1, &r));
        TEST_ASSERT_FALSE_MESSAGE(r.clean, vectors[i]);
        lint_result_free(&r);
    }
}

static void test_case_variant_packagejson_install_hook(void)
{
    manifest_entry_t m[] = {
        { "Package.JSON", "{\"scripts\":{\"preinstall\":\"x\"}}" },
    };
    lint_result_t r; memset(&r, 0, sizeof r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, lint_manifest(m, 1, &r));
    TEST_ASSERT_FALSE(r.clean);
    TEST_ASSERT_EQUAL_STRING("install-hook:preinstall", r.violations[0].rule);
    lint_result_free(&r);
}

static void test_windows_path_equivalence_vectors(void)
{
    static const char *vectors[] = {
        ".cl" "aude\\settings.json",       /* backslash separator */
        "packages\\x\\.vscode\\tasks.json", /* nested backslash, depth */
        ".cl" "aude/settings.json.",       /* trailing dot — Windows strips it */
        ".cl" "aude/settings.json ",       /* trailing space — Windows strips it */
        ".cursor\\rules\\evil",             /* backslash + forbidden prefix */
    };
    for (size_t i = 0; i < sizeof(vectors)/sizeof(vectors[0]); i++) {
        manifest_entry_t m[] = { { vectors[i], NULL } };
        lint_result_t r; memset(&r, 0, sizeof r);
        TEST_ASSERT_EQUAL_INT(BNS_OK, lint_manifest(m, 1, &r));
        TEST_ASSERT_FALSE_MESSAGE(r.clean, vectors[i]);
        lint_result_free(&r);
    }
}

static void test_backslash_trailing_dot_packagejson_hook(void)
{
    manifest_entry_t m[] = {
        { "dir\\Package.json.", "{\"scripts\":{\"install\":\"x\"}}" },
    };
    lint_result_t r; memset(&r, 0, sizeof r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, lint_manifest(m, 1, &r));
    TEST_ASSERT_FALSE(r.clean);
    TEST_ASSERT_EQUAL_STRING("install-hook:install", r.violations[0].rule);
    lint_result_free(&r);
}

static void test_install_hook_in_packagejson_content(void)
{
    manifest_entry_t m[] = {
        { "package.json", "{\"scripts\":{\"postinstall\":\"node evil.js\"}}" },
    };
    lint_result_t r; memset(&r, 0, sizeof r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, lint_manifest(m, 1, &r));
    TEST_ASSERT_FALSE(r.clean);
    TEST_ASSERT_EQUAL_STRING("install-hook:postinstall", r.violations[0].rule);
    lint_result_free(&r);
}

static void test_fails_closed_on_unparseable_packagejson(void)
{
    manifest_entry_t m[] = { { "package.json", "{not json" } };
    lint_result_t r; memset(&r, 0, sizeof r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, lint_manifest(m, 1, &r));
    TEST_ASSERT_FALSE(r.clean);
    TEST_ASSERT_EQUAL_STRING("unparseable-package-json", r.violations[0].rule);
    lint_result_free(&r);
}

static void test_does_not_flag_benign_lookalikes(void)
{
    manifest_entry_t m[] = {
        { "package.json", "{\"scripts\":{\"test\":\"mocha\"}}" },
        { "docs/cl" "aude/settings.json.md", NULL },
        { "src/vscode-tasks.json.example", NULL },
    };
    TEST_ASSERT_TRUE(lint_clean(m, 3));
}

static void test_reports_every_violation_in_one_pass(void)
{
    manifest_entry_t m[] = {
        { ".cl" "aude/settings.json", NULL },
        { "src/app.ts", NULL },
        { "pkg/package.json", "{\"scripts\":{\"preinstall\":\"a\",\"postinstall\":\"b\"}}" },
        { ".vscode/tasks.json", NULL },
    };
    lint_result_t r; memset(&r, 0, sizeof r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, lint_manifest(m, 4, &r));
    TEST_ASSERT_FALSE(r.clean);
    TEST_ASSERT_EQUAL_size_t(4u, r.violations_count);

    /* The TS sorts the rule list and compares to:
     *   forbidden-file:<agent-settings-path>
     *   forbidden-file:.vscode/tasks.json
     *   install-hook:postinstall
     *   install-hook:preinstall
     * We don't depend on emission order here — gather + sort the rule strings. */
    const char *want[] = {
        "forbidden-file:.cl" "aude/settings.json",
        "forbidden-file:.vscode/tasks.json",
        "install-hook:postinstall",
        "install-hook:preinstall",
    };
    /* simple insertion sort of the produced rules */
    char *got[4];
    for (size_t i = 0; i < 4; i++) got[i] = r.violations[i].rule;
    for (size_t i = 1; i < 4; i++) {
        char *key = got[i]; size_t j = i;
        while (j > 0 && strcmp(got[j-1], key) > 0) { got[j] = got[j-1]; j--; }
        got[j] = key;
    }
    for (size_t i = 0; i < 4; i++)
        TEST_ASSERT_EQUAL_STRING(want[i], got[i]);
    lint_result_free(&r);
}

/* ----------------------------------------------------------------------------
 * AutoExecLinterAttestor (lint -> sign only if clean)
 * ------------------------------------------------------------------------- */
static void test_attest_clean_release_verifiable_signature(void)
{
    if (!g_key_ready) { TEST_IGNORE_MESSAGE("keygen failed"); }
    auto_exec_linter_attestor_t *a = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, auto_exec_linter_attestor_new(&g_key, 1, &a));

    attest_result_t res; memset(&res, 0, sizeof res);
    TEST_ASSERT_EQUAL_INT(BNS_OK, auto_exec_linter_attestor_attest(a, &RELEASE, CLEAN, CLEAN_N, &res));
    TEST_ASSERT_TRUE(res.attested);

    /* digest == computeActivateDigest(release) */
    char *expect = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, compute_activate_digest(
        RELEASE.genesis_outpoint, RELEASE.scope, RELEASE.version,
        RELEASE.bundle_hash, RELEASE.file_set_root, RELEASE.announce_txid, &expect));
    TEST_ASSERT_EQUAL_STRING(expect, res.digest);

    /* signature verifies under the attestor's pubkey */
    bool ok = false;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_attestation_verify(res.attestor_pubkey, res.digest, res.signature, &ok));
    TEST_ASSERT_TRUE(ok);

    free(expect);
    attest_result_free(&res);
    auto_exec_linter_attestor_free(a);
}

static void test_attest_refuses_poisoned_release_with_violations(void)
{
    if (!g_key_ready) { TEST_IGNORE_MESSAGE("keygen failed"); }
    auto_exec_linter_attestor_t *a = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, auto_exec_linter_attestor_new(&g_key, 1, &a));

    manifest_entry_t m[CLEAN_N + 1];
    memcpy(m, CLEAN, sizeof(CLEAN));
    m[CLEAN_N].path = ".cl" "aude/settings.json"; m[CLEAN_N].content = NULL;

    attest_result_t res; memset(&res, 0, sizeof res);
    TEST_ASSERT_EQUAL_INT(BNS_OK, auto_exec_linter_attestor_attest(a, &RELEASE, m, CLEAN_N + 1, &res));
    TEST_ASSERT_FALSE(res.attested);
    TEST_ASSERT_EQUAL_size_t(1u, res.dirty.violations_count);

    attest_result_free(&res);
    auto_exec_linter_attestor_free(a);
}

static void test_attest_never_reuses_seq(void)
{
    if (!g_key_ready) { TEST_IGNORE_MESSAGE("keygen failed"); }
    auto_exec_linter_attestor_t *a = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, auto_exec_linter_attestor_new(&g_key, 10, &a));

    attest_result_t r1; memset(&r1, 0, sizeof r1);
    TEST_ASSERT_EQUAL_INT(BNS_OK, auto_exec_linter_attestor_attest(a, &RELEASE, CLEAN, CLEAN_N, &r1));
    TEST_ASSERT_TRUE(r1.attested);
    TEST_ASSERT_EQUAL_UINT64(10u, r1.seq);

    release_fields_t r = RELEASE; r.version = "1.2.1";
    attest_result_t r2; memset(&r2, 0, sizeof r2);
    TEST_ASSERT_EQUAL_INT(BNS_OK, auto_exec_linter_attestor_attest(a, &r, CLEAN, CLEAN_N, &r2));
    TEST_ASSERT_TRUE(r2.attested);
    TEST_ASSERT_EQUAL_UINT64(11u, r2.seq);

    TEST_ASSERT_EQUAL_UINT64(12u, auto_exec_linter_attestor_next_seq(a));

    attest_result_free(&r1);
    attest_result_free(&r2);
    auto_exec_linter_attestor_free(a);
}

static void test_refused_attestation_consumes_no_seq(void)
{
    if (!g_key_ready) { TEST_IGNORE_MESSAGE("keygen failed"); }
    auto_exec_linter_attestor_t *a = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, auto_exec_linter_attestor_new(&g_key, 5, &a));

    manifest_entry_t poisoned[CLEAN_N + 1];
    memcpy(poisoned, CLEAN, sizeof(CLEAN));
    poisoned[CLEAN_N].path = ".cl" "aude/settings.json"; poisoned[CLEAN_N].content = NULL;

    attest_result_t refused; memset(&refused, 0, sizeof refused);
    TEST_ASSERT_EQUAL_INT(BNS_OK, auto_exec_linter_attestor_attest(a, &RELEASE, poisoned, CLEAN_N + 1, &refused));
    TEST_ASSERT_FALSE(refused.attested);
    TEST_ASSERT_EQUAL_UINT64(5u, auto_exec_linter_attestor_next_seq(a)); /* unchanged */
    attest_result_free(&refused);

    /* next CLEAN attestation gets seq 5 — the refusal left no gap */
    attest_result_t ok; memset(&ok, 0, sizeof ok);
    TEST_ASSERT_EQUAL_INT(BNS_OK, auto_exec_linter_attestor_attest(a, &RELEASE, CLEAN, CLEAN_N, &ok));
    TEST_ASSERT_TRUE(ok.attested);
    TEST_ASSERT_EQUAL_UINT64(5u, ok.seq);
    attest_result_free(&ok);

    auto_exec_linter_attestor_free(a);
}

static void test_attestor_start_seq_zero_rejected(void)
{
    /* startSeq < 1 throws in the TS constructor -> C BNS_EINVAL */
    auto_exec_linter_attestor_t *a = NULL;
    int rc = auto_exec_linter_attestor_new(&g_key, 0, &a);
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, rc);
    TEST_ASSERT_NULL(a);
}

/* ----------------------------------------------------------------------------
 * Stake-floor consumer policy
 * ------------------------------------------------------------------------- */
static void test_validator_stake_floor_accepts(void)
{
    TEST_ASSERT_TRUE(meets_validator_stake_floor(400000, 100000));  /* exactly 4x */
    TEST_ASSERT_TRUE(meets_validator_stake_floor(500000, 100000));
}
static void test_validator_understaked_treated_unstaked(void)
{
    TEST_ASSERT_FALSE(meets_validator_stake_floor(399999, 100000));
    TEST_ASSERT_FALSE(meets_validator_stake_floor(1, 100000));
    TEST_ASSERT_FALSE(meets_validator_stake_floor(0, 100000));
}
static void test_validator_degenerate_inputs(void)
{
    TEST_ASSERT_FALSE(meets_validator_stake_floor(-1, 100000));
    TEST_ASSERT_FALSE(meets_validator_stake_floor(400000, 0));
}
static void test_attestor_bond_floor(void)
{
    TEST_ASSERT_TRUE(meets_attestor_bond_floor(10000000));
    TEST_ASSERT_FALSE(meets_attestor_bond_floor(9999999));
}

int main(void)
{
    g_key_ready = (generate_attestor_key(&g_key) == BNS_OK);
    if (!g_key_ready)
        fprintf(stderr, "WARN: Rabin keygen failed; attestor tests will IGNORE\n");

    UNITY_BEGIN();
    RUN_TEST(test_passes_clean_manifest);
    RUN_TEST(test_catches_every_miasma_vector);
    RUN_TEST(test_catches_nested_subdir_vector);
    RUN_TEST(test_catches_case_variant_vectors);
    RUN_TEST(test_case_variant_packagejson_install_hook);
    RUN_TEST(test_windows_path_equivalence_vectors);
    RUN_TEST(test_backslash_trailing_dot_packagejson_hook);
    RUN_TEST(test_install_hook_in_packagejson_content);
    RUN_TEST(test_fails_closed_on_unparseable_packagejson);
    RUN_TEST(test_does_not_flag_benign_lookalikes);
    RUN_TEST(test_reports_every_violation_in_one_pass);
    RUN_TEST(test_attest_clean_release_verifiable_signature);
    RUN_TEST(test_attest_refuses_poisoned_release_with_violations);
    RUN_TEST(test_attest_never_reuses_seq);
    RUN_TEST(test_refused_attestation_consumes_no_seq);
    RUN_TEST(test_attestor_start_seq_zero_rejected);
    RUN_TEST(test_validator_stake_floor_accepts);
    RUN_TEST(test_validator_understaked_treated_unstaked);
    RUN_TEST(test_validator_degenerate_inputs);
    RUN_TEST(test_attestor_bond_floor);
    int rc = UNITY_END();
    if (g_key_ready) rabin_key_free(&g_key);
    return rc;
}
