/*
 * test_manifest_registry.c — Unity port of
 *   chain/tests/priscilla/manifestRegistry.test.ts
 *
 * Mirrors the KEY behaviors the TS pins for the atomic port of
 * manifest_registry.zig: install/list/count, duplicate rejection without
 * mutation, persistence + replay across a restart, install->uninstall->reinstall
 * replay (latest install wins), not_found on absent uninstall, the two
 * PERSIST-THEN-COMMIT failure invariants (install failure leaves NO active
 * entry; uninstall failure leaves the entry STILL installed), single-line +
 * newline JSONL framing, and replay skipping malformed lines.
 *
 * Build+run directly (avoids the shared cmake race):
 *   gcc -std=c11 -D_GNU_SOURCE -Iinclude -Ithird_party/unity -Ithird_party/cJSON \
 *       -Ithird_party/ripemd160 -Ithird_party/mimc7_consts -Itests/helpers \
 *       tests/test_manifest_registry.c third_party/unity/unity.c \
 *       $(ls tests/helpers/[a-z]*.c) -Lbuild -lbonsai_chain \
 *       $(pkg-config --libs libsecp256k1 libcrypto libcurl) -lm -lpthread \
 *       -o /tmp/test_manifest_registry && /tmp/test_manifest_registry
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ftw.h>

#include "unity.h"
#include "cJSON.h"
#include "common/error.h"
#include "verifier/manifest_registry.h"

/* ---- per-test temp dir (mkdtemp) ---------------------------------------- */

static char g_dir[256];

static int rm_cb(const char *p, const struct stat *s, int t, struct FTW *f)
{
    (void)s; (void)t; (void)f;
    return remove(p);
}
static void rmrf(const char *path)
{
    nftw(path, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
}

void setUp(void)
{
    snprintf(g_dir, sizeof g_dir, "/tmp/priscilla-reg-XXXXXX");
    char *d = mkdtemp(g_dir);
    TEST_ASSERT_NOT_NULL(d);
}
void tearDown(void)
{
    if (g_dir[0]) rmrf(g_dir);
    g_dir[0] = '\0';
}

/* a fixed clock returning 1 (TS: now: () => 1) */
static int64_t clock_one(void *u) { (void)u; return 1; }

/* rec(id): the TS fixture { extensionId:id, version:"1.0.0", source:"anchor",
 * manifestJson: {id,name:id}, publishRef:"txid:0" }. */
static void make_rec(manifest_install_args_t *out, const char *id,
                     char *json_buf, size_t json_sz, const char *version)
{
    snprintf(json_buf, json_sz, "{\"id\":\"%s\",\"name\":\"%s\"}", id, id);
    memset(out, 0, sizeof *out);
    out->extension_id  = id;
    out->version       = version ? version : "1.0.0";
    out->source        = "anchor";
    out->manifest_json = json_buf;
    out->publish_ref   = "txid:0";
}

static char *join_log(char *buf, size_t sz, const char *leaf)
{
    snprintf(buf, sz, "%s/%s", g_dir, leaf);
    return buf;
}

/* ---- tests -------------------------------------------------------------- */

/* installs, lists, and counts */
static void test_install_list_count(void)
{
    char log[300]; join_log(log, sizeof log, "log.jsonl");
    manifest_registry_opts_t opts = { .log_path = log, .clock = clock_one };
    manifest_registry_t *reg = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_new(&opts, &reg));

    char ja[128], jb[128];
    manifest_install_args_t a, b;
    make_rec(&a, "a", ja, sizeof ja, NULL);
    make_rec(&b, "b", jb, sizeof jb, NULL);
    manifest_record_t r;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_install(reg, &a, &r));
    manifest_record_free(&r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_install(reg, &b, &r));
    manifest_record_free(&r);

    TEST_ASSERT_EQUAL_UINT(2, manifest_registry_count(reg));

    manifest_record_t *list = NULL; size_t n = 0;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_list(reg, &list, &n));
    TEST_ASSERT_EQUAL_UINT(2, n);
    /* insertion order: a then b (TS sorts, but insertion order is a,b here) */
    bool saw_a = false, saw_b = false;
    for (size_t i = 0; i < n; i++) {
        if (strcmp(list[i].extension_id, "a") == 0) saw_a = true;
        if (strcmp(list[i].extension_id, "b") == 0) saw_b = true;
    }
    TEST_ASSERT_TRUE(saw_a && saw_b);
    manifest_records_free(list, n);
    manifest_registry_free(reg);
}

/* rejects duplicate installs without mutating the existing entry */
static void test_duplicate_no_mutate(void)
{
    char log[300]; join_log(log, sizeof log, "log.jsonl");
    manifest_registry_opts_t opts = { .log_path = log, .clock = clock_one };
    manifest_registry_t *reg = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_new(&opts, &reg));

    char ja[128];
    manifest_install_args_t a;
    make_rec(&a, "a", ja, sizeof ja, "1.0.0");
    manifest_record_t r;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_install(reg, &a, &r));
    manifest_record_free(&r);

    /* duplicate install with a different version -> DuplicateExtensionError
     * (BNS_EINVAL) and the stored version must NOT change. */
    char ja2[128];
    manifest_install_args_t a2;
    make_rec(&a2, "a", ja2, sizeof ja2, "9.9.9");
    manifest_record_t r2; memset(&r2, 0, sizeof r2);
    TEST_ASSERT_EQUAL_INT(BNS_EINVAL, manifest_registry_install(reg, &a2, &r2));

    manifest_record_t got; bool found = false;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_get(reg, "a", &got, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_STRING("1.0.0", got.version);
    manifest_record_free(&got);
    manifest_registry_free(reg);
}

/* persists across a restart (replay from the log): install a,b; uninstall a;
 * a fresh instance over the same log lists only [b]. */
static void test_persist_across_restart(void)
{
    char log[300]; join_log(log, sizeof log, "log.jsonl");
    manifest_registry_opts_t opts = { .log_path = log, .clock = clock_one };
    manifest_registry_t *reg = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_new(&opts, &reg));

    char ja[128], jb[128];
    manifest_install_args_t a, b;
    make_rec(&a, "a", ja, sizeof ja, NULL);
    make_rec(&b, "b", jb, sizeof jb, NULL);
    manifest_record_t r;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_install(reg, &a, &r)); manifest_record_free(&r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_install(reg, &b, &r)); manifest_record_free(&r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_uninstall(reg, "a"));
    manifest_registry_free(reg);

    /* fresh instance replays the same log */
    manifest_registry_opts_t opts2 = { .log_path = log };
    manifest_registry_t *reg2 = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_new(&opts2, &reg2));
    TEST_ASSERT_EQUAL_UINT(1, manifest_registry_count(reg2));
    manifest_record_t *list = NULL; size_t n = 0;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_list(reg2, &list, &n));
    TEST_ASSERT_EQUAL_UINT(1, n);
    TEST_ASSERT_EQUAL_STRING("b", list[0].extension_id);
    manifest_records_free(list, n);
    manifest_registry_free(reg2);
}

/* replay handles install -> uninstall -> reinstall of the same id
 * (latest install wins; intervening uninstall clears the dedupe guard). */
static void test_replay_reinstall_latest_wins(void)
{
    char log[300]; join_log(log, sizeof log, "log.jsonl");
    manifest_registry_opts_t opts = { .log_path = log, .clock = clock_one };
    manifest_registry_t *reg = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_new(&opts, &reg));

    char ja[128];
    manifest_install_args_t a1;
    make_rec(&a1, "a", ja, sizeof ja, "1.0.0");
    manifest_record_t r;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_install(reg, &a1, &r)); manifest_record_free(&r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_uninstall(reg, "a"));
    char ja2[128];
    manifest_install_args_t a2;
    make_rec(&a2, "a", ja2, sizeof ja2, "2.0.0");
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_install(reg, &a2, &r)); manifest_record_free(&r);

    manifest_record_t got; bool found = false;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_get(reg, "a", &got, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_STRING("2.0.0", got.version);
    manifest_record_free(&got);
    manifest_registry_free(reg);

    /* fresh instance over the SAME log must reach v2.0.0, count 1 */
    manifest_registry_opts_t opts2 = { .log_path = log };
    manifest_registry_t *reg2 = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_new(&opts2, &reg2));
    TEST_ASSERT_EQUAL_UINT(1, manifest_registry_count(reg2));
    found = false;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_get(reg2, "a", &got, &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_STRING("2.0.0", got.version);
    manifest_record_free(&got);
    manifest_registry_free(reg2);
}

/* uninstall throws not_found for an absent id */
static void test_uninstall_not_found(void)
{
    char log[300]; join_log(log, sizeof log, "log.jsonl");
    manifest_registry_opts_t opts = { .log_path = log };
    manifest_registry_t *reg = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_new(&opts, &reg));
    TEST_ASSERT_EQUAL_INT(BNS_ENOTFOUND, manifest_registry_uninstall(reg, "nope"));
    manifest_registry_free(reg);
}

/* PERSIST-THEN-COMMIT: an install-time persist failure leaves NO failed-but-
 * active install (the fixed bug). Make the parent dir a FILE so append fails. */
static void test_persist_fail_install_no_active(void)
{
    char sub[300]; join_log(sub, sizeof sub, "sub");
    char log[400]; snprintf(log, sizeof log, "%s/log.jsonl", sub);

    /* construct with a not-yet-existing log dir so replay sees ENOENT (no throw) */
    manifest_registry_opts_t opts = { .log_path = log };
    manifest_registry_t *reg = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_new(&opts, &reg));

    /* turn the parent into a FILE -> the install-time append must fail */
    int fd = open(sub, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, fd);
    TEST_ASSERT_EQUAL_INT(1, write(fd, "x", 1));
    close(fd);

    char ja[128];
    manifest_install_args_t a;
    make_rec(&a, "a", ja, sizeof ja, NULL);
    manifest_record_t r; memset(&r, 0, sizeof r);
    TEST_ASSERT_EQUAL_INT(BNS_EPERSIST, manifest_registry_install(reg, &a, &r));

    /* the persist-then-commit fix must NOT leave 'a' active */
    TEST_ASSERT_EQUAL_UINT(0, manifest_registry_count(reg));
    manifest_record_t got; bool found = true;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_get(reg, "a", &got, &found));
    TEST_ASSERT_FALSE(found);
    manifest_registry_free(reg);
}

/* PERSIST-THEN-COMMIT on uninstall: a persist failure leaves the entry STILL
 * installed (mirror bug). Replace the log file with a DIRECTORY so the next
 * append throws EISDIR inside persist(). */
static void test_persist_fail_uninstall_still_installed(void)
{
    char log[300]; join_log(log, sizeof log, "log.jsonl");
    manifest_registry_opts_t opts = { .log_path = log, .clock = clock_one };
    manifest_registry_t *reg = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_new(&opts, &reg));

    char ja[128];
    manifest_install_args_t a;
    make_rec(&a, "a", ja, sizeof ja, NULL);
    manifest_record_t r;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_install(reg, &a, &r)); manifest_record_free(&r);

    /* make the next append fail: replace the log file with a directory */
    TEST_ASSERT_EQUAL_INT(0, remove(log));
    TEST_ASSERT_EQUAL_INT(0, mkdir(log, 0700));

    TEST_ASSERT_EQUAL_INT(BNS_EPERSIST, manifest_registry_uninstall(reg, "a"));

    /* the durable removal failed, so 'a' must still be installed */
    manifest_record_t got; bool found = false;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_get(reg, "a", &got, &found));
    TEST_ASSERT_TRUE(found);
    manifest_record_free(&got);
    TEST_ASSERT_EQUAL_UINT(1, manifest_registry_count(reg));
    manifest_registry_free(reg);
}

/* writes each record as a single line + newline (no partial-line corruption):
 * two installs => exactly two non-empty lines, each valid JSON. */
static void test_single_line_framing(void)
{
    char log[300]; join_log(log, sizeof log, "log.jsonl");
    manifest_registry_opts_t opts = { .log_path = log, .clock = clock_one };
    manifest_registry_t *reg = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_new(&opts, &reg));

    char ja[128], jb[128];
    manifest_install_args_t a, b;
    make_rec(&a, "a", ja, sizeof ja, NULL);
    make_rec(&b, "b", jb, sizeof jb, NULL);
    manifest_record_t r;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_install(reg, &a, &r)); manifest_record_free(&r);
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_install(reg, &b, &r)); manifest_record_free(&r);
    manifest_registry_free(reg);

    /* read the whole file, split on '\n', skip empties, parse each */
    FILE *f = fopen(log, "rb");
    TEST_ASSERT_NOT_NULL(f);
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)sz + 1);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_EQUAL_UINT((size_t)sz, fread(buf, 1, (size_t)sz, f));
    buf[sz] = '\0';
    fclose(f);

    int nlines = 0;
    char *save = NULL;
    for (char *line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        if (line[0] == '\0') continue;
        cJSON *j = cJSON_Parse(line);
        TEST_ASSERT_NOT_NULL_MESSAGE(j, "each JSONL line must be valid JSON");
        cJSON_Delete(j);
        nlines++;
    }
    TEST_ASSERT_EQUAL_INT(2, nlines);
    free(buf);
}

/* replay skips malformed lines without aborting: install a, append a corrupt
 * line, a fresh instance installs b, and both a + b survive. */
static void test_replay_skips_malformed(void)
{
    char log[300]; join_log(log, sizeof log, "log.jsonl");
    manifest_registry_opts_t opts = { .log_path = log, .clock = clock_one };
    manifest_registry_t *reg = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_new(&opts, &reg));

    char ja[128];
    manifest_install_args_t a;
    make_rec(&a, "a", ja, sizeof ja, NULL);
    manifest_record_t r;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_install(reg, &a, &r)); manifest_record_free(&r);
    manifest_registry_free(reg);

    /* inject a corrupt line */
    FILE *f = fopen(log, "ab");
    TEST_ASSERT_NOT_NULL(f);
    fputs("{not json\n", f);
    fclose(f);

    /* a second instance replays (skipping the bad line) and installs b */
    manifest_registry_opts_t opts2 = { .log_path = log, .clock = clock_one };
    manifest_registry_t *reg2 = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_new(&opts2, &reg2));
    char jb[128];
    manifest_install_args_t b;
    make_rec(&b, "b", jb, sizeof jb, NULL);
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_install(reg2, &b, &r)); manifest_record_free(&r);

    manifest_record_t *list = NULL; size_t n = 0;
    TEST_ASSERT_EQUAL_INT(BNS_OK, manifest_registry_list(reg2, &list, &n));
    TEST_ASSERT_EQUAL_UINT(2, n);
    bool saw_a = false, saw_b = false;
    for (size_t i = 0; i < n; i++) {
        if (strcmp(list[i].extension_id, "a") == 0) saw_a = true;
        if (strcmp(list[i].extension_id, "b") == 0) saw_b = true;
    }
    TEST_ASSERT_TRUE(saw_a && saw_b);
    manifest_records_free(list, n);
    manifest_registry_free(reg2);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_install_list_count);
    RUN_TEST(test_duplicate_no_mutate);
    RUN_TEST(test_persist_across_restart);
    RUN_TEST(test_replay_reinstall_latest_wins);
    RUN_TEST(test_uninstall_not_found);
    RUN_TEST(test_persist_fail_install_no_active);
    RUN_TEST(test_persist_fail_uninstall_still_installed);
    RUN_TEST(test_single_line_framing);
    RUN_TEST(test_replay_skips_malformed);
    return UNITY_END();
}
