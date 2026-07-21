/* Offline tests for agentd's crash-durable state and txid journal helpers. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "unity.h"
#include "common/error.h"
#include "scripts/agentd_persistence.h"

static char g_dir[] = "/tmp/bonsai-agentd-persist-XXXXXX";
static char g_state[256];
static char g_journal[280];

void setUp(void)
{
    strcpy(g_dir, "/tmp/bonsai-agentd-persist-XXXXXX");
    TEST_ASSERT_NOT_NULL(mkdtemp(g_dir));
    snprintf(g_state, sizeof g_state, "%s/identity.json", g_dir);
    snprintf(g_journal, sizeof g_journal, "%s.broadcasts", g_state);
}

void tearDown(void)
{
    unsetenv("AGENTD_BROADCAST_JOURNAL");
    unlink(g_state);
    unlink(g_journal);
    rmdir(g_dir);
}

static char *read_text(const char *path)
{
    FILE *f = fopen(path, "rb");
    TEST_ASSERT_NOT_NULL(f);
    TEST_ASSERT_EQUAL_INT(0, fseek(f, 0, SEEK_END));
    long n = ftell(f);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, n);
    rewind(f);
    char *out = malloc((size_t)n + 1);
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_EQUAL_size_t((size_t)n, fread(out, 1, (size_t)n, f));
    out[n] = '\0';
    fclose(f);
    return out;
}

static void test_atomic_state_replacement_is_private_and_leaves_no_temp(void)
{
    TEST_ASSERT_EQUAL_INT(BNS_OK, agentd_write_file_atomic(g_state, "{\"tip\":1}\n"));
    TEST_ASSERT_EQUAL_INT(BNS_OK, agentd_write_file_atomic(g_state, "{\"tip\":2}\n"));
    char *actual = read_text(g_state);
    TEST_ASSERT_EQUAL_STRING("{\"tip\":2}\n", actual);
    free(actual);

    struct stat st;
    TEST_ASSERT_EQUAL_INT(0, stat(g_state, &st));
    TEST_ASSERT_EQUAL_UINT(0600, st.st_mode & 0777);

    DIR *dir = opendir(g_dir);
    TEST_ASSERT_NOT_NULL(dir);
    size_t files = 0;
    for (struct dirent *entry = readdir(dir); entry != NULL; entry = readdir(dir))
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) files++;
    closedir(dir);
    TEST_ASSERT_EQUAL_size_t(1, files);
}

static void test_broadcast_journal_appends_complete_private_records(void)
{
    const char *first = "11aabb";
    const char *second = "22ccdd";
    TEST_ASSERT_EQUAL_INT(BNS_OK, agentd_journal_broadcast(g_state, "deploy", first));
    TEST_ASSERT_EQUAL_INT(BNS_OK, agentd_journal_broadcast(g_state, "action", second));
    char *actual = read_text(g_journal);
    TEST_ASSERT_EQUAL_STRING("deploy 11aabb\naction 22ccdd\n", actual);
    free(actual);

    struct stat st;
    TEST_ASSERT_EQUAL_INT(0, stat(g_journal, &st));
    TEST_ASSERT_EQUAL_UINT(0600, st.st_mode & 0777);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_atomic_state_replacement_is_private_and_leaves_no_temp);
    RUN_TEST(test_broadcast_journal_appends_complete_private_records);
    return UNITY_END();
}
