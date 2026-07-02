/*
 * test_agentd.c — Unity port of chain/tests/agentd.test.ts.
 *
 * agentd.test.ts proves the RESUMABLE Pillar-B lifecycle: deploy a stateful
 * AgentTea identity once, then run N metered actions across what would be SEPARATE
 * process invocations (simulated by JSON-serializing the AgentState between steps),
 * each reconstructing the instance from the previous tx via AgentTea.fromTx so the
 * txCount carry-forward proves cross-process state recovery — all against a
 * DummyProvider (no network).
 *
 * THE key pin (cluster guidance + the first TS `it`): the cross-language golden
 * action-receipt hash
 *   cdc6a3e1b4bfd4ac931e25d31aa0309938d10900807cd403f74222ed2a00a33d
 * over the fixed receipt inputs. The SAME vector is pinned in the Python verifier,
 * so a drift on either side fails CI.
 *
 * What the chain_c agentd CLI ships is a real-broadcast-or-dry-run dispatcher
 * (agentd_run -> broadcast_unavailable) that deliberately does NOT replicate the
 * TS in-memory DummyProvider deploy/action/revoke that returns
 * record.receiptHashOnChain / advances state.txCount. So the TS lifecycle's
 * EXECUTION (building each tx, the live AgentTea.fromTx restore, the revoke
 * broadcast) is exercised here against the REPRODUCIBLE C surface:
 *   - the cross-language golden receipt hash (fixture preimage + the real
 *     agent_tea_receipt_hash builder);
 *   - expectedReceiptHash(amount, actionHash, provenanceHash, txCount) at the
 *     pre-increment txCount carried across steps (the heart of the carry-forward);
 *   - the AgentState JSON round-trip (the reload(JSON.parse(JSON.stringify(state)))
 *     trick that survives an invocation boundary), incl. txCount and status;
 *   - AgentTea.fromTx restoring txCount across the boundary (agent_tea_from_tx).
 *
 * The TS "refuses to action a revoked identity" rejection lives in the contract/
 * agentAction guard which the dry-run C CLI does not execute; it is TEST_IGNORE'd
 * with a reason (status round-trips correctly, which is the C-checkable half).
 *
 * Build+run (from chain_c/):
 *   gcc -std=c11 -D_GNU_SOURCE -Iinclude -Ithird_party/unity -Ithird_party/cJSON \
 *       -Ithird_party/ripemd160 -Ithird_party/mimc7_consts -Itests/helpers \
 *       tests/test_agentd.c third_party/unity/unity.c (tests/helpers/ .c files) \
 *       -Lbuild -lbonsai_chain $(pkg-config --libs libsecp256k1 libcrypto libcurl) \
 *       -lm -lpthread -o /tmp/test_agentd && /tmp/test_agentd
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

#include "unity.h"

#include "common/error.h"
#include "common/bytes.h"
#include "common/hex.h"
#include "crypto/hash.h"
#include "crypto/bignum.h"
#include "crypto/ecdsa.h"
#include "bsv/address.h"
#include "scrypt/scrypt_contract.h"
#include "scrypt/artifact_loader.h"
#include "contracts_next/agent_tea.h"
#include "scripts/agent_state.h"
#include "scripts/agentd.h"

#include "fixtures.h"
#include "tx_helper.h"

static const char *AGENT_TEA_ARTIFACT = "artifacts/src/contracts-next/agentTea.json";

/* The TS fixed lifecycle parameters. */
#define NOW_LOCKTIME 1700000000

void setUp(void) {}
void tearDown(void) {}

static bn_t *bn_dec(const char *dec)
{
    bn_t *bn = NULL;
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, bn_parse_dec(dec, &bn), dec);
    return bn;
}

/* ============================================================================
 * THE KEY PIN — cross-language golden action-receipt hash.
 *
 * agentd.test.ts:
 *   const receipt = 'aa'*32 + '02' + 'bb'*32 + '03' + 'cc'*32 +
 *       int2ByteString(1234,8) + 'dd'*32 + 'ee'*32 +
 *       int2ByteString(7,8) + int2ByteString(1700000000,4)
 *   expect(sha256(receipt)).to.equal('cdc6a3e1...a33d')
 * ========================================================================= */

/* (1) sha256(the fixture preimage hex) == golden — pins the byte layout. */
static void test_golden_receipt_hash_from_preimage(void)
{
    byte_buf_t pre; byte_buf_init(&pre);
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        hex_decode(FIX_AGENTD_GOLDEN_RECEIPT_PREIMAGE_HEX, &pre));

    uint8_t dig[BONSAI_SHA256_LEN];
    sha256(pre.data, pre.len, dig);
    char *hex = hex_encode(dig, sizeof dig);
    TEST_ASSERT_NOT_NULL(hex);
    TEST_ASSERT_EQUAL_STRING(FIX_AGENTD_GOLDEN_RECEIPT_HASH, hex);

    free(hex);
    byte_buf_free(&pre);
}

/* (2) the REAL agent_tea_receipt_hash builder reproduces the golden when fed the
 * exact fixed inputs:
 *   ricardianHash = aa*32
 *   agent         = 02 || bb*32   (33 bytes)
 *   counterparty  = 03 || cc*32   (33 bytes)
 *   amount        = 1234
 *   actionHash    = dd*32
 *   provenance    = ee*32
 *   txCount       = 7   (committed PRE-increment, here via state.tx_count)
 *   now           = 1700000000
 * This proves the contract->builder->Python triple agrees byte-for-byte. */
static void test_golden_receipt_hash_via_builder(void)
{
    uint8_t rh[32], agent33[33], cp33[33], ah[32], ph[32];
    memset(rh, 0xaa, 32);
    agent33[0] = 0x02; memset(agent33 + 1, 0xbb, 32);
    cp33[0]    = 0x03; memset(cp33 + 1, 0xcc, 32);
    memset(ah, 0xdd, 32);
    memset(ph, 0xee, 32);

    agent_tea_t c; memset(&c, 0, sizeof c);
    byte_buf_init(&c.params.ricardian_hash);
    byte_buf_init(&c.params.agent);
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_from(&c.params.ricardian_hash, rh, 32));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_from(&c.params.agent, agent33, 33));
    c.state.tx_count = bn_dec("7");

    bn_t *amount = bn_dec("1234");
    char *got = NULL;
    int rc = agent_tea_receipt_hash(&c, cp33, amount, ah, ph, NOW_LOCKTIME, &got);
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, rc, "agent_tea_receipt_hash");
    TEST_ASSERT_EQUAL_STRING(FIX_AGENTD_GOLDEN_RECEIPT_HASH, got);

    free(got);
    bn_free(amount);
    agent_tea_free(&c);
}

/* ============================================================================
 * Resumable carry-forward: expectedReceiptHash(amount, ah, ph, txCount).
 * The TS lifecycle commits txCount=0 in action #1's receipt and txCount=1 in
 * action #2's (fromTx restored 1 across JSON). We reproduce both receipt hashes
 * for two distinct (amount, txCount) action steps and assert they differ and are
 * each reproducible — the byte-level evidence of the carry-forward.
 * ========================================================================= */

/* Helper: receipt hash for the agentd test's fixed identity at (amount,txCount). */
static char *agentd_receipt(const uint8_t rh[32], const uint8_t agent33[33],
                            const uint8_t cp33[33], const char *amount_dec,
                            const uint8_t ah[32], const uint8_t ph[32],
                            const char *txcount_dec)
{
    agent_tea_t c; memset(&c, 0, sizeof c);
    byte_buf_init(&c.params.ricardian_hash);
    byte_buf_init(&c.params.agent);
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_from(&c.params.ricardian_hash, rh, 32));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_from(&c.params.agent, agent33, 33));
    c.state.tx_count = bn_dec(txcount_dec);
    bn_t *amount = bn_dec(amount_dec);
    char *got = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        agent_tea_receipt_hash(&c, cp33, amount, ah, ph, NOW_LOCKTIME, &got));
    bn_free(amount);
    agent_tea_free(&c);
    return got;
}

static void test_action_carry_forward_receipts(void)
{
    uint8_t rh[32], agent33[33], cp33[33], ah1[32], ah2[32], ph[32];
    memset(rh, 0x77, 32);
    agent33[0] = 0x02; memset(agent33 + 1, 0x11, 32);
    cp33[0]    = 0x03; memset(cp33 + 1, 0x22, 32);
    memset(ah1, 0x31, 32);   /* actionHash #1 */
    memset(ah2, 0x32, 32);   /* actionHash #2 */
    memset(ph, 0x40, 32);

    /* action #1: amount 1000, txCount 0 (pre-increment committed). */
    char *r1 = agentd_receipt(rh, agent33, cp33, "1000", ah1, ph, "0");
    /* action #2: amount 2000, txCount 1 (fromTx restored 1). */
    char *r2 = agentd_receipt(rh, agent33, cp33, "2000", ah2, ph, "1");

    /* the two steps produce distinct, well-formed 64-hex receipts. */
    TEST_ASSERT_EQUAL_UINT(64, strlen(r1));
    TEST_ASSERT_EQUAL_UINT(64, strlen(r2));
    TEST_ASSERT_NOT_EQUAL_INT(0, strcmp(r1, r2));

    /* reproducibility: recomputing r1 yields the identical hash. */
    char *r1b = agentd_receipt(rh, agent33, cp33, "1000", ah1, ph, "0");
    TEST_ASSERT_EQUAL_STRING(r1, r1b);

    free(r1); free(r2); free(r1b);
}

/* ============================================================================
 * AgentState JSON round-trip — the reload() trick.
 * agentd.test.ts: reload(state) = JSON.parse(JSON.stringify(state)). Only the
 * serialized AgentState survives an invocation boundary; the C analogue is
 * agent_state_to_json / agent_state_from_json. We build a state, serialize it,
 * parse it back, and assert the carried fields (txCount, status, genesisTxid)
 * survive — and that status='actioned'/'revoked' round-trip.
 * ========================================================================= */

/* Build a minimal-but-complete agent_state_t (owned). */
static void make_state(agent_state_t *st, int64_t tx_count, agent_status_t status)
{
    memset(st, 0, sizeof *st);
    st->schema               = strdup(BONSAI_AGENT_STATE_SCHEMA);
    st->network              = strdup("testnet");
    st->genesis_txid         = strdup(FIX_TXID_A);
    st->ricardian_hash       = strdup(FIX_ZERO32_HEX);
    st->owner                = strdup(FIX_PUBKEY_COMPRESSED_HEX);
    st->agent_pub_key        = strdup(FIX_PUBKEY_COMPRESSED_HEX);
    st->counterparty_pub_key = strdup(FIX_PUBKEY_COMPRESSED_HEX);
    st->charter              = strdup("bonsai agent charter");
    agent_params_defaults(&st->params);
    st->rabin_pub.guardian      = strdup("3");
    st->rabin_pub.own_validator = strdup("5");
    st->rabin_pub.recovery      = calloc(3, sizeof(char *));
    st->rabin_pub.recovery[0]   = strdup("7");
    st->rabin_pub.recovery[1]   = strdup("11");
    st->rabin_pub.recovery[2]   = strdup("13");
    st->rabin_pub.num_recovery  = 3;
    st->identity_sats           = 1;
    st->tip.txid                = strdup(FIX_TXID_A);
    st->tip.vout                = 0;
    st->tip.raw_tx_hex          = strdup("00");
    st->state.tx_count          = tx_count;
    st->state.spent_in_window   = 0;
    st->state.window_start      = 0;
    st->state.tier              = 1;
    st->state.recovery_count    = 0;
    st->status                  = status;
    st->history                 = NULL;
    st->num_history             = 0;
}

static void roundtrip_state(int64_t tx_count, agent_status_t status,
                            int64_t *out_tx_count, agent_status_t *out_status,
                            char **out_genesis)
{
    agent_state_t st;
    make_state(&st, tx_count, status);

    char *json = NULL;
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, agent_state_to_json(&st, &json),
                                  "agent_state_to_json");
    TEST_ASSERT_NOT_NULL(json);
    /* schema literal is present in the serialized JSON. */
    TEST_ASSERT_NOT_NULL(strstr(json, BONSAI_AGENT_STATE_SCHEMA));

    agent_state_t back; memset(&back, 0, sizeof back);
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, agent_state_from_json(json, &back),
                                  "agent_state_from_json");

    *out_tx_count = back.state.tx_count;
    *out_status   = back.status;
    *out_genesis  = back.genesis_txid ? strdup(back.genesis_txid) : NULL;

    free(json);
    agent_state_free(&st);
    agent_state_free(&back);
}

static void test_state_json_roundtrip_deployed(void)
{
    int64_t tc; agent_status_t status; char *genesis = NULL;
    roundtrip_state(0, AGENT_STATUS_DEPLOYED, &tc, &status, &genesis);
    /* deployed identity: txCount 0, status deployed, genesis preserved. */
    TEST_ASSERT_EQUAL_INT64(0, tc);
    TEST_ASSERT_EQUAL_INT(AGENT_STATUS_DEPLOYED, status);
    TEST_ASSERT_EQUAL_STRING(FIX_TXID_A, genesis);
    free(genesis);
}

static void test_state_json_roundtrip_actioned_txcount(void)
{
    int64_t tc; agent_status_t status; char *genesis = NULL;
    /* after action #2: txCount carried as 2, status actioned. */
    roundtrip_state(2, AGENT_STATUS_ACTIONED, &tc, &status, &genesis);
    TEST_ASSERT_EQUAL_INT64(2, tc);
    TEST_ASSERT_EQUAL_INT(AGENT_STATUS_ACTIONED, status);
    free(genesis);
}

static void test_state_json_roundtrip_revoked(void)
{
    int64_t tc; agent_status_t status; char *genesis = NULL;
    roundtrip_state(2, AGENT_STATUS_REVOKED, &tc, &status, &genesis);
    /* revoke sets status='revoked'; it survives the boundary. */
    TEST_ASSERT_EQUAL_INT(AGENT_STATUS_REVOKED, status);
    free(genesis);
}

/* ============================================================================
 * AgentTea.fromTx restores txCount across the invocation boundary.
 * The TS step reconstructs the instance from the previous tx's recreated locking
 * script (AgentTea.fromTx) — that is what carries txCount from action #1 (1) into
 * action #2 (it reads 1). The C analogue: build the recreated locking script at
 * txCount=1, then agent_tea_from_tx must decode txCount=1 back out.
 * ========================================================================= */
static void test_fromtx_restores_txcount(void)
{
    /* a minimal-but-valid genesis instance from the golden inputs is heavy to
     * hand-build; instead reuse agent_tea_locking_script with a full params set.
     * We need a real artifact + full ctor params for the codec, so build them. */
    scrypt_artifact_t art; memset(&art, 0, sizeof art);
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, load_artifact(AGENT_TEA_ARTIFACT, &art),
                                  "load AgentTea artifact");

    agent_tea_t c; memset(&c, 0, sizeof c);
    c.artifact = &art;
    byte_buf_init(&c.params.owner);
    byte_buf_init(&c.params.agent);
    byte_buf_init(&c.params.ricardian_hash);

    uint8_t owner[33], agent[33], rh[32];
    owner[0] = 0x02; memset(owner + 1, 0x01, 32);
    agent[0] = 0x02; memset(agent + 1, 0x02, 32);
    memset(rh, 0xcd, 32);
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_from(&c.params.owner, owner, 33));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_from(&c.params.agent, agent, 33));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_from(&c.params.ricardian_hash, rh, 32));

    c.params.per_tx_limit                = bn_dec("100000");
    c.params.daily_limit                 = bn_dec("1000000");
    c.params.window_duration             = bn_dec("86400");
    c.params.graduation_threshold        = bn_dec("10000");
    c.params.validator_threshold         = bn_dec("50000");
    c.params.designated_validator_pubkey = bn_dec("3");
    c.params.validator_rabin_pubkey      = bn_dec("5");
    c.params.recovery_keys[0]            = bn_dec("7");
    c.params.recovery_keys[1]            = bn_dec("11");
    c.params.recovery_keys[2]            = bn_dec("13");
    c.params.recovery_threshold          = bn_dec("2");

    TEST_ASSERT_EQUAL_INT(BNS_OK, agent_tea_genesis_state(&c.state));
    /* action #1 advanced txCount to 1; the recreated script carries it. */
    bn_free(c.state.tx_count);
    c.state.tx_count = bn_dec("1");

    byte_buf_t ls; byte_buf_init(&ls);
    TEST_ASSERT_EQUAL_INT(BNS_OK, agent_tea_locking_script(&c, false, &ls));

    agent_tea_state_t dec; memset(&dec, 0, sizeof dec);
    int rc = agent_tea_from_tx(ls.data, ls.len, &art, &dec, NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, rc, "agent_tea_from_tx");

    char *d = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_to_dec(dec.tx_count, &d));
    TEST_ASSERT_EQUAL_STRING("1", d);   /* txCount carried across the boundary */
    free(d);

    agent_tea_state_free(&dec);
    byte_buf_free(&ls);
    agent_tea_free(&c);
    scrypt_artifact_free(&art);
}

/* ============================================================================
 * Contract/agentAction guard: refusing to action a revoked identity needs the
 * agentAction lifecycle executor (DummyProvider tx build + contract guard) the
 * dry-run C CLI does not replicate. Ignored with a reason. The serialization
 * half (status='revoked' survives the JSON boundary) IS covered above.
 * ========================================================================= */
static void test_refuse_revoked_action_ignored(void)
{
    TEST_IGNORE_MESSAGE(
        "agentAction refusing a revoked identity (/revoked/) requires the in-memory "
        "DummyProvider agentAction executor + the AgentTea contract guard; the chain_c "
        "agentd CLI is a real-broadcast-or-dry-run dispatcher with no contract "
        "interpreter, so it never runs that path. status='revoked' round-trips through "
        "the AgentState JSON (covered by test_state_json_roundtrip_revoked).");
}

/* ============================================================================
 * recover via the agentd CLI dispatcher (agentd_run): arg-validation + DRY RUN.
 *
 * Unlike the lifecycle pins above (which exercise the reproducible builder/state
 * surface), these drive the real env-var CLI entry point agentd_run("recover")
 * with stdout/stderr captured, asserting:
 *   (i)  recover with STATE_FILE set but NEW_AGENT_KEY_FILE unset -> the
 *        "NEW_AGENT_KEY_FILE ... is required" failure (exit nonzero);
 *   (ii) recover DRY-RUN (no CONFIRM_MAINNET_BROADCAST) with STATE_FILE +
 *        a valid {wif,address} NEW_AGENT_KEY_FILE -> the "recover plan" line,
 *        STATE_FILE left byte-identical, exit 0.
 * No network is touched (the dry-run gate returns before any WoC/broadcast).
 * ========================================================================= */

/* Read an entire file into a freshly malloc'd NUL-terminated string (NULL on
 * error). */
static char *read_whole(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[rd] = '\0';
    return buf;
}

/* Write `contents` to a fresh mkstemp temp file; returns a malloc'd path
 * (caller unlink()s + free()s). NULL on failure. */
static char *write_temp_file(const char *contents)
{
    char tmpl[] = "/tmp/bonsai_agentd_recover_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return NULL;
    size_t n = strlen(contents);
    ssize_t w = write(fd, contents, n);
    close(fd);
    if (w < 0 || (size_t)w != n) { unlink(tmpl); return NULL; }
    return strdup(tmpl);
}

/* Serialize a fresh deployed agent_state (via make_state) to a temp STATE_FILE. */
static char *write_temp_statefile(void)
{
    agent_state_t st;
    make_state(&st, 0, AGENT_STATUS_DEPLOYED);
    char *json = NULL;
    if (agent_state_to_json(&st, &json) != BNS_OK) { agent_state_free(&st); return NULL; }
    char *path = write_temp_file(json);
    free(json);
    agent_state_free(&st);
    return path;
}

/* Write a valid bonsai-notary {wif,address} keyfile (deterministic testnet key)
 * to a temp file. Returns a malloc'd path (caller unlink()s + free()s). */
static char *write_temp_keyfile(void)
{
    ecdsa_key_t *k = NULL;
    if (tx_helper_key(TX_KEY_AGENT, &k) != BNS_OK) return NULL;
    uint8_t secret[32];
    if (ecdsa_key_to_bytes(k, secret) != BNS_OK) { ecdsa_key_free(k); return NULL; }

    char *wif = NULL;
    if (wif_encode(secret, true, BSV_TESTNET, &wif) != BNS_OK) { ecdsa_key_free(k); return NULL; }

    ecdsa_pubkey_t *pub = NULL;
    char *addr = NULL;
    if (ecdsa_key_derive_pubkey(k, &pub) != BNS_OK) { free(wif); ecdsa_key_free(k); return NULL; }
    int rc = address_from_pubkey(pub, BSV_TESTNET, &addr);
    ecdsa_pubkey_free(pub);
    ecdsa_key_free(k);
    if (rc != BNS_OK) { free(wif); return NULL; }

    char json[512];
    snprintf(json, sizeof json, "{\"wif\":\"%s\",\"address\":\"%s\"}", wif, addr);
    free(wif); free(addr);
    return write_temp_file(json);
}

/* Run agentd_run(argc,argv) with stdout+stderr redirected to temp files; returns
 * the agentd_run rc, sets *exit_code, and (when non-NULL) fills *out_stdout /
 * *out_stderr with malloc'd captured text (caller frees). */
static int run_agentd_capture(int argc, char **argv, int *exit_code,
                              char **out_stdout, char **out_stderr)
{
    if (out_stdout) *out_stdout = NULL;
    if (out_stderr) *out_stderr = NULL;

    char op[] = "/tmp/bonsai_agentd_out_XXXXXX";
    char ep[] = "/tmp/bonsai_agentd_err_XXXXXX";
    int ofd = mkstemp(op);
    int efd = mkstemp(ep);
    if (ofd < 0 || efd < 0) {
        if (ofd >= 0) { close(ofd); unlink(op); }
        if (efd >= 0) { close(efd); unlink(ep); }
        return BNS_EPERSIST;
    }

    fflush(stdout); fflush(stderr);
    int saved_out = dup(fileno(stdout));
    int saved_err = dup(fileno(stderr));
    dup2(ofd, fileno(stdout));
    dup2(efd, fileno(stderr));

    int ec = 0;
    int rc = agentd_run(argc, argv, &ec);

    fflush(stdout); fflush(stderr);
    dup2(saved_out, fileno(stdout)); close(saved_out);
    dup2(saved_err, fileno(stderr)); close(saved_err);
    close(ofd); close(efd);

    if (exit_code) *exit_code = ec;
    if (out_stdout) *out_stdout = read_whole(op);
    if (out_stderr) *out_stderr = read_whole(ep);
    unlink(op); unlink(ep);
    return rc;
}

/* (i) recover requires NEW_AGENT_KEY_FILE. */
static void test_recover_requires_new_agent_key_file(void)
{
    char *sf = write_temp_statefile();
    TEST_ASSERT_NOT_NULL_MESSAGE(sf, "temp STATE_FILE");

    setenv("STATE_FILE", sf, 1);
    unsetenv("NEW_AGENT_KEY_FILE");
    unsetenv("CONFIRM_MAINNET_BROADCAST");

    char *argv[] = { (char *)"agentd", (char *)"recover" };
    int ec = 0; char *err = NULL;
    int rc = run_agentd_capture(2, argv, &ec, NULL, &err);

    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, rc, "agentd_run returns BNS_OK (exit via code)");
    TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(0, ec,
        "recover without NEW_AGENT_KEY_FILE exits nonzero");
    TEST_ASSERT_NOT_NULL(err);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(err, "NEW_AGENT_KEY_FILE"),
        "failure names NEW_AGENT_KEY_FILE");
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(err, "is required"),
        "failure says it is required");

    free(err);
    unsetenv("STATE_FILE");
    unlink(sf); free(sf);
}

/* (ii) recover DRY-RUN prints the plan and leaves STATE_FILE unchanged. */
static void test_recover_dry_run_plan_and_state_unchanged(void)
{
    char *sf = write_temp_statefile();
    char *kf = write_temp_keyfile();
    TEST_ASSERT_NOT_NULL_MESSAGE(sf, "temp STATE_FILE");
    TEST_ASSERT_NOT_NULL_MESSAGE(kf, "temp NEW_AGENT_KEY_FILE");

    char *before = read_whole(sf);
    TEST_ASSERT_NOT_NULL(before);

    setenv("STATE_FILE", sf, 1);
    setenv("NEW_AGENT_KEY_FILE", kf, 1);
    unsetenv("CONFIRM_MAINNET_BROADCAST");

    char *argv[] = { (char *)"agentd", (char *)"recover" };
    int ec = -1; char *out = NULL; char *err = NULL;
    int rc = run_agentd_capture(2, argv, &ec, &out, &err);

    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, rc, "agentd_run returns BNS_OK");
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ec, "recover dry-run exits 0");
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(out, "recover plan"),
        "dry-run prints the 'recover plan' line");
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(out, "DRY RUN"),
        "dry-run prints the DRY RUN gate");

    /* STATE_FILE must be byte-identical: a dry-run writes nothing. */
    char *after = read_whole(sf);
    TEST_ASSERT_NOT_NULL(after);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(before, after,
        "STATE_FILE unchanged by recover dry-run");

    free(before); free(after); free(out); free(err);
    unsetenv("STATE_FILE"); unsetenv("NEW_AGENT_KEY_FILE");
    unlink(sf); free(sf);
    unlink(kf); free(kf);
}

/* ============================================================================ */
int main(void)
{
    UNITY_BEGIN();

    /* THE key pin: cross-language golden receipt hash (two routes). */
    RUN_TEST(test_golden_receipt_hash_from_preimage);
    RUN_TEST(test_golden_receipt_hash_via_builder);

    /* resumable carry-forward receipts. */
    RUN_TEST(test_action_carry_forward_receipts);

    /* AgentState JSON round-trip (the reload() trick). */
    RUN_TEST(test_state_json_roundtrip_deployed);
    RUN_TEST(test_state_json_roundtrip_actioned_txcount);
    RUN_TEST(test_state_json_roundtrip_revoked);

    /* AgentTea.fromTx restores txCount. */
    RUN_TEST(test_fromtx_restores_txcount);

    /* revoked-action guard (ignored — no contract executor). */
    RUN_TEST(test_refuse_revoked_action_ignored);

    /* recover via the agentd CLI: arg-validation + DRY RUN (no network). */
    RUN_TEST(test_recover_requires_new_agent_key_file);
    RUN_TEST(test_recover_dry_run_plan_and_state_unchanged);

    return UNITY_END();
}
