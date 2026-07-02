/*
 * test_agent_tea.c — Unity port of chain/tests/agentTea.test.ts.
 *
 * AgentTea is the Pillar-B sovereign-agent STATEFUL contract. The TS suite is an
 * adversarial harness that EXECUTES the compiled scrypt contract against a
 * DummyProvider and asserts on its method-call accept/reject behaviour (per-tx
 * limit, rolling window, graduation, guardian attestation, burn-split slashing,
 * Elder kill-switch, M-of-3 social recovery).
 *
 * The chain_c port does NOT ship a scrypt VM that EXECUTES the contract — it
 * reconstructs the locking script from the compiled artifact and owns the
 * byte-exact preimage builders + the from_tx state decoder + the unsigned tx
 * builders. So this file mirrors the parts of the TS suite that are reproducible
 * against the real C public API:
 *
 *   - the AgentTea locking script byte-exact (54528-hex golden);
 *   - the executeAction receipt hash byte-exactness (receiptHashOf), and the
 *     "provenance genuinely changes the receipt" pin;
 *   - attestationMsg / recoveryMsg byte-exact preimages;
 *   - from_tx state decode round-trip (AgentTea.fromTx);
 *   - the burn-split slashing OUTPUT SHAPE (bounty = floor(total/2), burn =
 *     total - bounty in an OP_FALSE OP_RETURN 'SLASHED\0'), incl. the odd-sat
 *     rounding pin — via the real slashValidator tx builder.
 *
 * Every TS assertion that depends on RUNNING the contract's internal checks
 * (rejections like /exceeds per-action limit/, /invalid guardian attestation/,
 * graduation tier transitions, input-0 pin enforcement, recovery-quorum
 * enforcement) is TEST_IGNORE'd with a reason: the C surface has no contract
 * interpreter, so asserting them would be asserting something false.
 *
 * Build+run (from chain_c/):
 *   gcc -std=c11 -D_GNU_SOURCE -Iinclude -Ithird_party/unity -Ithird_party/cJSON \
 *       -Ithird_party/ripemd160 -Ithird_party/mimc7_consts -Itests/helpers \
 *       tests/test_agent_tea.c third_party/unity/unity.c (tests/helpers/ .c files) \
 *       -Lbuild -lbonsai_chain $(pkg-config --libs libsecp256k1 libcrypto libcurl) \
 *       -lm -lpthread -o /tmp/test_agent_tea && /tmp/test_agent_tea
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
#include "cJSON.h"

#include "common/error.h"
#include "common/bytes.h"
#include "common/hex.h"
#include "crypto/hash.h"
#include "crypto/bignum.h"
#include "bsv/tx.h"
#include "bsv/tx_builder.h"
#include "scrypt/scrypt_contract.h"
#include "scrypt/artifact_loader.h"
#include "contracts_next/agent_tea.h"
#include "txbuilders/agent_tea_tx_builder.h"

#include "fixtures.h"

/* ------------------------------------------------------------------------- */

static const char *AGENT_TEA_ARTIFACT = "artifacts/src/contracts-next/agentTea.json";
static const char *GOLDEN_PATH        = "tests/golden/golden.json";

void setUp(void) {}
void tearDown(void) {}

/* read a whole file into a malloc'd NUL-terminated buffer */
static char *read_file_all(const char *path)
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
    return buf;
}

static const cJSON *jobj(const cJSON *o, const char *k)
{
    return cJSON_GetObjectItemCaseSensitive(o, k);
}
static const char *jstr(const cJSON *o, const char *k)
{
    const cJSON *i = jobj(o, k);
    return (i && cJSON_IsString(i)) ? i->valuestring : NULL;
}

/* parse decimal into a bn_t, fatal on failure */
static bn_t *bn_dec(const char *dec)
{
    bn_t *bn = NULL;
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, bn_parse_dec(dec, &bn), dec);
    TEST_ASSERT_NOT_NULL(bn);
    return bn;
}

/* ============================================================================
 * Locking script — the 54528-hex golden (KEY pin per cluster guidance).
 * Mirrors agentTea.test.ts deploy: every freshInstance() builds this same
 * AgentTea locking script; the golden vector pins it byte-exact.
 * ========================================================================= */

/* Build an agent_tea_t from the golden lockingScripts.agentTea inputs. The
 * artifact is borrowed and must outlive `c`. Genesis state (txCount=0,
 * spentInWindow=0, windowStart=0, tier=1, recoveryCount=0). */
static void build_golden_instance(const scrypt_artifact_t *art, const cJSON *in,
                                  agent_tea_t *c)
{
    memset(c, 0, sizeof *c);
    c->artifact = art;

    byte_buf_init(&c->params.owner);
    byte_buf_init(&c->params.agent);
    byte_buf_init(&c->params.ricardian_hash);

    byte_buf_t tmp; byte_buf_init(&tmp);
    TEST_ASSERT_EQUAL_INT(BNS_OK, hex_decode(jstr(in, "owner_hex"), &tmp));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_from(&c->params.owner, tmp.data, tmp.len));
    byte_buf_free(&tmp); byte_buf_init(&tmp);

    TEST_ASSERT_EQUAL_INT(BNS_OK, hex_decode(jstr(in, "agent_hex"), &tmp));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_from(&c->params.agent, tmp.data, tmp.len));
    byte_buf_free(&tmp); byte_buf_init(&tmp);

    TEST_ASSERT_EQUAL_INT(BNS_OK, hex_decode(jstr(in, "ricardianHash_hex"), &tmp));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_from(&c->params.ricardian_hash, tmp.data, tmp.len));
    byte_buf_free(&tmp);

    c->params.per_tx_limit                = bn_dec(jstr(in, "perTxLimit"));
    c->params.daily_limit                 = bn_dec(jstr(in, "dailyLimit"));
    c->params.window_duration             = bn_dec(jstr(in, "windowDuration"));
    c->params.graduation_threshold        = bn_dec(jstr(in, "graduationThreshold"));
    c->params.validator_threshold         = bn_dec(jstr(in, "validatorThreshold"));
    c->params.designated_validator_pubkey = bn_dec(jstr(in, "designatedValidatorPubKey_decimal"));
    c->params.validator_rabin_pubkey      = bn_dec(jstr(in, "validatorRabinPubKey_decimal"));

    const cJSON *rk = jobj(in, "recoveryKeys_decimal");
    for (int i = 0; i < BONSAI_AGENT_TEA_RECOVERY_KEYS; i++)
        c->params.recovery_keys[i] = bn_dec(cJSON_GetArrayItem(rk, i)->valuestring);
    c->params.recovery_threshold = bn_dec(jstr(in, "recoveryThreshold"));

    TEST_ASSERT_EQUAL_INT(BNS_OK, agent_tea_genesis_state(&c->state));
}

static void test_locking_script_golden_54528(void)
{
    char *gj = read_file_all(GOLDEN_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(gj, "cannot read golden.json");
    cJSON *root = cJSON_Parse(gj);
    free(gj);
    TEST_ASSERT_NOT_NULL(root);

    const cJSON *at = jobj(jobj(root, "lockingScripts"), "agentTea");
    const cJSON *in = jobj(at, "inputs");
    const char *exp_hex = jstr(at, "lockingScript_hex");
    TEST_ASSERT_NOT_NULL(exp_hex);

    scrypt_artifact_t art; memset(&art, 0, sizeof art);
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, load_artifact(AGENT_TEA_ARTIFACT, &art),
                                  "load AgentTea artifact");

    agent_tea_t c;
    build_golden_instance(&art, in, &c);

    byte_buf_t out; byte_buf_init(&out);
    int rc = agent_tea_locking_script(&c, /*is_genesis=*/false, &out);
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, rc, "agent_tea_locking_script");

    char *got_hex = hex_encode(out.data, out.len);
    TEST_ASSERT_NOT_NULL(got_hex);
    /* 54528 hex chars == 27264 bytes. */
    TEST_ASSERT_EQUAL_UINT(strlen(exp_hex), strlen(got_hex));
    TEST_ASSERT_EQUAL_STRING(exp_hex, got_hex);

    free(got_hex);
    byte_buf_free(&out);
    agent_tea_free(&c);
    scrypt_artifact_free(&art);
    cJSON_Delete(root);
}

/* ============================================================================
 * Receipt hash byte-exactness (receiptHashOf) — the executeAction receipt the
 * OP_RETURN commits. agentTea.test.ts pins it via Utils.buildOpreturnScript(
 * receiptHashOf(amount, txCount, now)).
 *
 * We build a small instance whose ricardianHash/agent/counterparty we control,
 * compute the receipt hash, and re-derive the expected sha256 independently.
 * Also pins: provenance genuinely changes the receipt (not.to.equal).
 * ========================================================================= */

/* Build a minimal agent_tea_t carrying only the fields the receipt preimage
 * reads: ricardianHash(32), agent(33) and a state.tx_count. No artifact needed
 * (agent_tea_receipt_* does not touch it). */
static void build_receipt_instance(agent_tea_t *c, const uint8_t rh[32],
                                   const uint8_t agent33[33], const char *tx_count_dec)
{
    memset(c, 0, sizeof *c);
    byte_buf_init(&c->params.ricardian_hash);
    byte_buf_init(&c->params.agent);
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_from(&c->params.ricardian_hash, rh, 32));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_from(&c->params.agent, agent33, 33));
    c->state.tx_count = bn_dec(tx_count_dec);
}

/* Independently recompute sha256(receipt preimage) the way the TS receiptHashOf
 * assembles it, returning a malloc'd 64-hex digest. */
static char *ref_receipt_hash(const uint8_t rh[32], const uint8_t agent33[33],
                              const uint8_t cp33[33], uint64_t amount,
                              const uint8_t action_hash[32],
                              const uint8_t prov_hash[32], uint64_t tx_count,
                              uint32_t now)
{
    byte_buf_t pre; byte_buf_init(&pre);
    uint8_t le8[8], le4[4];
    byte_buf_append(&pre, rh, 32);
    byte_buf_append(&pre, agent33, 33);
    byte_buf_append(&pre, cp33, 33);
    for (int i = 0; i < 8; i++) le8[i] = (uint8_t)(amount >> (8 * i));
    byte_buf_append(&pre, le8, 8);
    byte_buf_append(&pre, action_hash, 32);
    byte_buf_append(&pre, prov_hash, 32);
    for (int i = 0; i < 8; i++) le8[i] = (uint8_t)(tx_count >> (8 * i));
    byte_buf_append(&pre, le8, 8);
    for (int i = 0; i < 4; i++) le4[i] = (uint8_t)(now >> (8 * i));
    byte_buf_append(&pre, le4, 4);

    uint8_t dig[BONSAI_SHA256_LEN];
    sha256(pre.data, pre.len, dig);
    byte_buf_free(&pre);
    return hex_encode(dig, sizeof dig);
}

static void test_receipt_hash_byte_exact(void)
{
    /* deterministic-but-arbitrary inputs (TS uses sha256 of prose; we use raw
     * 32-byte literals — the byte layout is what is pinned). */
    uint8_t rh[32], agent33[33], cp33[33], ah[32], ph[32];
    memset(rh, 0x11, 32);
    agent33[0] = 0x02; memset(agent33 + 1, 0x22, 32);
    cp33[0] = 0x03;    memset(cp33 + 1, 0x33, 32);
    memset(ah, 0x44, 32);
    memset(ph, 0x55, 32);

    const uint64_t amount = 40000, txc = 0, now = 1700000000;

    agent_tea_t c;
    build_receipt_instance(&c, rh, agent33, "0");

    bn_t *amt = bn_dec("40000");
    char *got = NULL;
    int rc = agent_tea_receipt_hash(&c, cp33, amt, ah, ph, (int64_t)now, &got);
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, rc, "agent_tea_receipt_hash");

    char *ref = ref_receipt_hash(rh, agent33, cp33, amount, ah, ph, txc, (uint32_t)now);
    TEST_ASSERT_EQUAL_STRING(ref, got);

    free(ref); free(got);
    bn_free(amt);
    agent_tea_free(&c);
}

static void test_receipt_provenance_changes_hash(void)
{
    uint8_t rh[32], agent33[33], cp33[33], ah[32], zero_ph[32], prov_ph[32];
    memset(rh, 0x11, 32);
    agent33[0] = 0x02; memset(agent33 + 1, 0x22, 32);
    cp33[0] = 0x03;    memset(cp33 + 1, 0x33, 32);
    memset(ah, 0x44, 32);
    memset(zero_ph, 0x00, 32);     /* ZERO_PROVENANCE */
    memset(prov_ph, 0xee, 32);     /* a real provenance hash */

    agent_tea_t c;
    build_receipt_instance(&c, rh, agent33, "0");
    bn_t *amt = bn_dec("40000");

    char *with_zero = NULL, *with_prov = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        agent_tea_receipt_hash(&c, cp33, amt, ah, zero_ph, 1700000000, &with_zero));
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        agent_tea_receipt_hash(&c, cp33, amt, ah, prov_ph, 1700000000, &with_prov));

    /* provenance is genuinely committed: a different provenanceHash => a
     * different receipt (TS: .to.not.equal). */
    TEST_ASSERT_NOT_EQUAL_INT(0, strcmp(with_zero, with_prov));

    free(with_zero); free(with_prov);
    bn_free(amt);
    agent_tea_free(&c);
}

/* The pre-increment txCount commitment: receiptHashOf(.., txCount, ..) at
 * txCount=0 vs txCount=1 differ — the heart of the resumable lifecycle's
 * carry-forward (also pinned in agentd.test.ts). */
static void test_receipt_txcount_distinguishes(void)
{
    uint8_t rh[32], agent33[33], cp33[33], ah[32], ph[32];
    memset(rh, 0x11, 32);
    agent33[0] = 0x02; memset(agent33 + 1, 0x22, 32);
    cp33[0] = 0x03;    memset(cp33 + 1, 0x33, 32);
    memset(ah, 0x44, 32);
    memset(ph, 0x00, 32);
    bn_t *amt = bn_dec("1000");

    agent_tea_t c0, c1;
    build_receipt_instance(&c0, rh, agent33, "0");
    build_receipt_instance(&c1, rh, agent33, "1");

    char *h0 = NULL, *h1 = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, agent_tea_receipt_hash(&c0, cp33, amt, ah, ph, 1700000000, &h0));
    TEST_ASSERT_EQUAL_INT(BNS_OK, agent_tea_receipt_hash(&c1, cp33, amt, ah, ph, 1700000000, &h1));
    TEST_ASSERT_NOT_EQUAL_INT(0, strcmp(h0, h1));

    free(h0); free(h1);
    bn_free(amt);
    agent_tea_free(&c0);
    agent_tea_free(&c1);
}

/* ============================================================================
 * attestationMsg / recoveryMsg byte-exact preimages.
 * agentTea.test.ts builds these exact byte strings (attestationMsg/recoveryMsg)
 * and feeds them to rabinSign; the contract reconstructs the same bytes. We pin
 * the C builders against an independent re-assembly of the documented layout.
 * ========================================================================= */

/* int2ByteString minimal (BN.toSM, LE, sign-magnitude) of a non-negative small
 * value — for the test we only need the modulus-style large value via the
 * library, so we reconstruct the EXPECTED message via the C minimal/sized
 * encoders' counterpart: append the library's own minimal encoding. Instead of
 * re-deriving minimal LE here we assert the domain tag + fixed-width fields and
 * the overall length / sha is stable & nonempty, plus that changing a field
 * changes the bytes. */
static void test_attestation_msg_layout(void)
{
    uint8_t rh[32], agent33[33], recv[32];
    memset(rh, 0xaa, 32);
    agent33[0] = 0x02; memset(agent33 + 1, 0xbb, 32);
    memset(recv, 0xcc, 32);

    /* a modest validator pubkey value so int2ByteString_minimal is short. */
    bn_t *vpk    = bn_dec("65793");      /* 0x010101 -> minimal LE 010101 */
    bn_t *amount = bn_dec("100000");
    bn_t *limit  = bn_dec("100000");

    byte_buf_t out; byte_buf_init(&out);
    int rc = agent_tea_attestation_msg(rh, agent33, vpk, amount, limit, recv, &out);
    TEST_ASSERT_EQUAL_INT(BNS_OK, rc);

    /* Documented layout (see agent_tea.h):
     *   "AGNT_ATTEST_V1"(14) || rh(32) || agent(33) || minimal(vpk) ||
     *   sized(amount,8) || sized(limit,8) || receiptHash(32).
     * minimal(65793) == 01 01 01 (3 bytes) => total = 14+32+33+3+8+8+32 = 130. */
    TEST_ASSERT_EQUAL_UINT(130, out.len);

    /* domain tag prefix "AGNT_ATTEST_V1". */
    TEST_ASSERT_EQUAL_INT(0, memcmp(out.data, "AGNT_ATTEST_V1", 14));
    /* ricardianHash directly after the tag. */
    TEST_ASSERT_EQUAL_INT(0, memcmp(out.data + 14, rh, 32));
    /* agent after the ricardianHash. */
    TEST_ASSERT_EQUAL_INT(0, memcmp(out.data + 14 + 32, agent33, 33));
    /* minimal(vpk) = 01 01 01. */
    TEST_ASSERT_EQUAL_HEX8(0x01, out.data[14 + 32 + 33 + 0]);
    TEST_ASSERT_EQUAL_HEX8(0x01, out.data[14 + 32 + 33 + 1]);
    TEST_ASSERT_EQUAL_HEX8(0x01, out.data[14 + 32 + 33 + 2]);
    /* receiptHash is the trailing 32 bytes. */
    TEST_ASSERT_EQUAL_INT(0, memcmp(out.data + out.len - 32, recv, 32));

    byte_buf_free(&out);
    bn_free(vpk); bn_free(amount); bn_free(limit);
}

static void test_attestation_msg_amount_binding(void)
{
    /* per-action receipt binding: changing amount changes the preimage bytes. */
    uint8_t rh[32], agent33[33], recv[32];
    memset(rh, 0xaa, 32);
    agent33[0] = 0x02; memset(agent33 + 1, 0xbb, 32);
    memset(recv, 0xcc, 32);
    bn_t *vpk = bn_dec("65793");
    bn_t *a1 = bn_dec("100000"), *a2 = bn_dec("100001");
    bn_t *limit = bn_dec("100000");

    byte_buf_t m1, m2; byte_buf_init(&m1); byte_buf_init(&m2);
    TEST_ASSERT_EQUAL_INT(BNS_OK, agent_tea_attestation_msg(rh, agent33, vpk, a1, limit, recv, &m1));
    TEST_ASSERT_EQUAL_INT(BNS_OK, agent_tea_attestation_msg(rh, agent33, vpk, a2, limit, recv, &m2));
    TEST_ASSERT_EQUAL_UINT(m1.len, m2.len);
    TEST_ASSERT_NOT_EQUAL_INT(0, memcmp(m1.data, m2.data, m1.len));

    byte_buf_free(&m1); byte_buf_free(&m2);
    bn_free(vpk); bn_free(a1); bn_free(a2); bn_free(limit);
}

static void test_recovery_msg_layout(void)
{
    uint8_t rh[32], new_agent[33];
    memset(rh, 0xaa, 32);
    new_agent[0] = 0x02; memset(new_agent + 1, 0xdd, 32);
    bn_t *count = bn_dec("0");

    byte_buf_t out; byte_buf_init(&out);
    int rc = agent_tea_recovery_msg(rh, new_agent, count, &out);
    TEST_ASSERT_EQUAL_INT(BNS_OK, rc);

    /* "AGNT_RECOVER_V1"(15) || rh(32) || newAgent(33) || sized(count,8)
     *  => 15+32+33+8 = 88 bytes. */
    TEST_ASSERT_EQUAL_UINT(88, out.len);
    TEST_ASSERT_EQUAL_INT(0, memcmp(out.data, "AGNT_RECOVER_V1", 15));
    TEST_ASSERT_EQUAL_INT(0, memcmp(out.data + 15, rh, 32));
    TEST_ASSERT_EQUAL_INT(0, memcmp(out.data + 15 + 32, new_agent, 33));
    /* recoveryCount=0 sized 8 => eight zero bytes. */
    for (int i = 0; i < 8; i++) TEST_ASSERT_EQUAL_HEX8(0x00, out.data[15 + 32 + 33 + i]);

    byte_buf_free(&out);
    bn_free(count);
}

/* recoveryMsg binds recoveryCount (single-use / anti-replay) and ricardianHash
 * (cross-identity replay): different counter / rh => different bytes. */
static void test_recovery_msg_counter_and_rh_binding(void)
{
    uint8_t rh[32], rh2[32], new_agent[33];
    memset(rh, 0xaa, 32);
    memset(rh2, 0xab, 32);
    new_agent[0] = 0x02; memset(new_agent + 1, 0xdd, 32);
    bn_t *c0 = bn_dec("0"), *c1 = bn_dec("1");

    byte_buf_t m_c0, m_c1, m_rh2; byte_buf_init(&m_c0); byte_buf_init(&m_c1); byte_buf_init(&m_rh2);
    TEST_ASSERT_EQUAL_INT(BNS_OK, agent_tea_recovery_msg(rh,  new_agent, c0, &m_c0));
    TEST_ASSERT_EQUAL_INT(BNS_OK, agent_tea_recovery_msg(rh,  new_agent, c1, &m_c1));
    TEST_ASSERT_EQUAL_INT(BNS_OK, agent_tea_recovery_msg(rh2, new_agent, c0, &m_rh2));

    /* counter binding (single-use). */
    TEST_ASSERT_NOT_EQUAL_INT(0, memcmp(m_c0.data, m_c1.data, m_c0.len));
    /* cross-identity binding. */
    TEST_ASSERT_NOT_EQUAL_INT(0, memcmp(m_c0.data, m_rh2.data, m_c0.len));

    byte_buf_free(&m_c0); byte_buf_free(&m_c1); byte_buf_free(&m_rh2);
    bn_free(c0); bn_free(c1);
}

/* ============================================================================
 * from_tx state decode round-trip (AgentTea.fromTx).
 * The TS resumable lifecycle reconstructs the instance from the previous tx via
 * AgentTea.fromTx; the C analogue is agent_tea_from_tx, decoding the @prop(true)
 * state suffix out of the recreated locking script. We build a NON-genesis
 * locking script (rotated agent + advanced txCount/tier/...), then decode it and
 * assert every state field + the agent key survive the round-trip.
 * ========================================================================= */
static void test_from_tx_state_roundtrip(void)
{
    char *gj = read_file_all(GOLDEN_PATH);
    TEST_ASSERT_NOT_NULL(gj);
    cJSON *root = cJSON_Parse(gj);
    free(gj);
    TEST_ASSERT_NOT_NULL(root);
    const cJSON *in = jobj(jobj(jobj(root, "lockingScripts"), "agentTea"), "inputs");

    scrypt_artifact_t art; memset(&art, 0, sizeof art);
    TEST_ASSERT_EQUAL_INT(BNS_OK, load_artifact(AGENT_TEA_ARTIFACT, &art));

    agent_tea_t c;
    build_golden_instance(&art, in, &c);

    /* Advance state to a non-genesis tip and ROTATE the agent key, the exact
     * thing fromTx must recover across an invocation boundary. */
    bn_free(c.state.tx_count);        c.state.tx_count        = bn_dec("7");
    bn_free(c.state.spent_in_window); c.state.spent_in_window = bn_dec("40000");
    bn_free(c.state.window_start);    c.state.window_start    = bn_dec("1700000000");
    bn_free(c.state.tier);            c.state.tier            = bn_dec("2");
    bn_free(c.state.recovery_count);  c.state.recovery_count  = bn_dec("1");

    uint8_t rotated[33];
    rotated[0] = 0x02; memset(rotated + 1, 0x9a, 32);
    byte_buf_free(&c.params.agent);
    byte_buf_init(&c.params.agent);
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_from(&c.params.agent, rotated, 33));

    byte_buf_t ls; byte_buf_init(&ls);
    TEST_ASSERT_EQUAL_INT(BNS_OK, agent_tea_locking_script(&c, /*is_genesis=*/false, &ls));

    /* Decode it back. */
    agent_tea_state_t dec; memset(&dec, 0, sizeof dec);
    byte_buf_t dec_agent; byte_buf_init(&dec_agent);
    int rc = agent_tea_from_tx(ls.data, ls.len, &art, &dec, &dec_agent);
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, rc, "agent_tea_from_tx");

    /* every numeric state field survives. */
    char *d = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_to_dec(dec.tx_count, &d));        TEST_ASSERT_EQUAL_STRING("7", d);          free(d);
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_to_dec(dec.spent_in_window, &d)); TEST_ASSERT_EQUAL_STRING("40000", d);      free(d);
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_to_dec(dec.window_start, &d));    TEST_ASSERT_EQUAL_STRING("1700000000", d); free(d);
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_to_dec(dec.tier, &d));            TEST_ASSERT_EQUAL_STRING("2", d);          free(d);
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_to_dec(dec.recovery_count, &d));  TEST_ASSERT_EQUAL_STRING("1", d);          free(d);

    /* the rotated agent key survives. */
    TEST_ASSERT_EQUAL_UINT(33, dec_agent.len);
    TEST_ASSERT_EQUAL_INT(0, memcmp(dec_agent.data, rotated, 33));

    byte_buf_free(&dec_agent);
    agent_tea_state_free(&dec);
    byte_buf_free(&ls);
    agent_tea_free(&c);
    scrypt_artifact_free(&art);
    cJSON_Delete(root);
}

/* ============================================================================
 * Burn-split slashing OUTPUT SHAPE (the testable part of slashValidator).
 * agentTea.test.ts pins: bounty = ⌊total/2⌋ to reporter P2PKH; burn = total -
 * bounty in an OP_FALSE OP_RETURN ('006a' prefix) carrying 'SLASHED\0'
 * (534c415348454400). Odd collateral: bounty rounds DOWN, burn keeps the extra.
 * We exercise the REAL slashValidator tx builder and assert both amounts and the
 * burn script bytes.
 * ========================================================================= */

static void run_slash_shape(uint64_t total, uint64_t exp_bounty, uint64_t exp_burn)
{
    /* slashValidator builds no state output, so it needs only minimal params. */
    agent_tea_t c; memset(&c, 0, sizeof c);

    agent_tea_utxo_t id; memset(&id, 0, sizeof id);
    memcpy(id.txid_display, FIX_TXID_A, 64);
    id.txid_display[64] = '\0';
    id.vout = 0;
    id.value = total;

    uint8_t reporter[33];
    reporter[0] = 0x02; memset(reporter + 1, 0x55, 32);

    agent_tea_builder_opts_t opts; memset(&opts, 0, sizeof opts);
    /* no funding, no change override: outputs are exactly bounty+burn. */

    tx_builder_t b; tx_builder_init(&b);
    int rc = build_agent_tea_slash_validator(&c, &id, reporter, &opts, &b);
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, rc, "build_agent_tea_slash_validator");

    /* at least output[0]=bounty, output[1]=burn. */
    TEST_ASSERT_TRUE(b.tx.num_outputs >= 2);

    /* output[0]: bounty to reporter (P2PKH 76a914..88ac). */
    TEST_ASSERT_EQUAL_UINT64(exp_bounty, b.tx.outputs[0].satoshis);
    char *o0 = hex_encode(b.tx.outputs[0].script.data, b.tx.outputs[0].script.len);
    TEST_ASSERT_NOT_NULL(o0);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, strncmp(o0, "76a914", 6), "bounty is P2PKH");

    /* output[1]: OP_FALSE OP_RETURN 'SLASHED\0' carrying burn. */
    TEST_ASSERT_EQUAL_UINT64(exp_burn, b.tx.outputs[1].satoshis);
    char *o1 = hex_encode(b.tx.outputs[1].script.data, b.tx.outputs[1].script.len);
    TEST_ASSERT_NOT_NULL(o1);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, strncmp(o1, "006a", 4), "burn is OP_FALSE OP_RETURN");
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(o1, "534c415348454400"), "burn carries SLASHED\\0");

    free(o0); free(o1);
    tx_builder_free(&b);
    agent_tea_free(&c);
}

static void test_slash_even_collateral(void)
{
    /* 100000 -> 50000 bounty / 50000 burn. */
    run_slash_shape(100000, 50000, 50000);
}

static void test_slash_odd_collateral(void)
{
    /* 100001 -> 50000 bounty (floor) / 50001 burn (extra sat burned). */
    run_slash_shape(100001, 50000, 50001);
}

/* ============================================================================
 * Contract-EXECUTION rejections — cannot be reproduced without a scrypt VM.
 * The C port has no contract interpreter to run executeAction/stake/
 * slashValidator/recover/revoke's internal require()s, so these TS assertions
 * (which expect the call to be REJECTED with a specific message) are ignored
 * rather than asserted falsely.
 * ========================================================================= */
static void test_execution_rejections_ignored(void)
{
    TEST_IGNORE_MESSAGE(
        "executeAction/stake/slashValidator/recover/revoke accept+reject behaviour "
        "(per-action & rolling-window limits, graduation tiers, input-0 pin, guardian "
        "attestation validity, fraud-proof self-contradiction, M-of-3 recovery quorum, "
        "Elder kill-switch auth) requires running the compiled scrypt contract; the "
        "chain_c surface has no contract interpreter. Byte-exact layout pins (locking "
        "script, receipt/attestation/recovery preimages, from_tx decode, slash output "
        "shape) ARE covered above.");
}

/* ============================================================================ */
int main(void)
{
    UNITY_BEGIN();

    /* KEY pin: locking script byte-exact. */
    RUN_TEST(test_locking_script_golden_54528);

    /* KEY pin: receipt hash byte-exactness + provenance commitment. */
    RUN_TEST(test_receipt_hash_byte_exact);
    RUN_TEST(test_receipt_provenance_changes_hash);
    RUN_TEST(test_receipt_txcount_distinguishes);

    /* attestation / recovery preimages. */
    RUN_TEST(test_attestation_msg_layout);
    RUN_TEST(test_attestation_msg_amount_binding);
    RUN_TEST(test_recovery_msg_layout);
    RUN_TEST(test_recovery_msg_counter_and_rh_binding);

    /* from_tx state decode round-trip. */
    RUN_TEST(test_from_tx_state_roundtrip);

    /* burn-split slashing output shape. */
    RUN_TEST(test_slash_even_collateral);
    RUN_TEST(test_slash_odd_collateral);

    /* execution-dependent rejections (ignored — no scrypt VM). */
    RUN_TEST(test_execution_rejections_ignored);

    return UNITY_END();
}
