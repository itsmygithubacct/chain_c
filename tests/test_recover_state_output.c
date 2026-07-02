/*
 * test_recover_state_output.c — REGRESSION for the AgentTea social-recovery
 * "dual agent pubkey" bug (money-critical; fixed + mainnet-validated 2026-06-29).
 *
 * THE BUG: AgentTea embeds the agent PubKey TWICE in its locking script:
 *   - ctor[1]  : the genesis agent, frozen in the IMMUTABLE CODE PART (a
 *                constructor @prop, near the FRONT of the script);
 *   - state[0] : the @state copy in the trailing stateful suffix (near the END).
 * The on-chain recover() rotates ONLY `this.agent` (== state[0]) and FREEZES the
 * code part (getStateScript). The OLD builder rebuilt the WHOLE script from one
 * `params.agent`, rotating BOTH copies -> the recreated state output's ctor[1] no
 * longer matched the contract's frozen code part -> the hashOutputs assertion
 * failed and the recover spend was REJECTED on-chain (an unspendable recovery).
 *
 * THE FIX: agent_tea_locking_script_ex(c, is_genesis, state_agent, out). When
 * state_agent != NULL (33 raw bytes) it overrides ONLY the @state agent push
 * (state[0]); ctor[1] keeps c->params.agent. The old agent_tea_locking_script()
 * is now a wrapper passing state_agent=NULL (the genesis/executeAction/stake
 * case, which uses params.agent for BOTH copies). build_agent_tea_recover keeps
 * params.agent for the genesis ctor[1] and passes the new agent as the state[0]
 * override.
 *
 * THIS TEST pins the fix at the byte level. With owner O != agent A (so ctor[1]
 * provably carries the AGENT, not the owner), rotating the @state agent to a new
 * key B via the _ex override must change EXACTLY the @state agent's 33-byte push
 * (state[0]) and NOTHING else — ctor[1] stays A in BOTH the plain and overridden
 * scripts. A naive full rebuild (the bug) would also flip ctor[1] from A to B.
 *
 * Build+run (from chain_c/):
 *   cmake --build build -j && ctest --test-dir build -R recover --output-on-failure
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
#include "crypto/bignum.h"
#include "scrypt/scrypt_contract.h"
#include "scrypt/artifact_loader.h"
#include "contracts_next/agent_tea.h"

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

/* Build an agent_tea_t from the golden lockingScripts.agentTea inputs (same
 * recipe as test_agent_tea.c build_golden_instance, including the 2 validator +
 * 3 recovery Rabin pubkeys and all int params from the artifact-driven golden).
 * Genesis state (txCount=0, spentInWindow=0, windowStart=0, tier=1,
 * recoveryCount=0). The artifact is borrowed and must outlive `c`. */
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

/* Overwrite a byte_buf with `n` raw bytes. */
static void set_buf(byte_buf_t *b, const uint8_t *data, size_t n)
{
    byte_buf_free(b);
    byte_buf_init(b);
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_from(b, data, n));
}

/* Find every offset where `needle` (nlen bytes) occurs in `hay` (hlen bytes).
 * Records up to max_off offsets, returns the TOTAL match count. */
static size_t find_all(const uint8_t *hay, size_t hlen,
                       const uint8_t *needle, size_t nlen,
                       size_t *offsets, size_t max_off)
{
    size_t n = 0;
    if (nlen == 0 || hlen < nlen) return 0;
    for (size_t i = 0; i + nlen <= hlen; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) {
            if (n < max_off) offsets[n] = i;
            n++;
        }
    }
    return n;
}

/* ============================================================================
 * The regression: rotating the @state agent overrides ONLY state[0], never
 * ctor[1] or any other byte of the locking script.
 * ========================================================================= */
static void test_recover_override_changes_only_state_agent(void)
{
    /* Three DISTINCT compressed-pubkey-shaped keys (the reconstructor pushes raw
     * bytes; it does not validate curve membership). owner O != agent A so the
     * ctor[1] embedding is provably the AGENT, not the owner. */
    uint8_t O[33], A[33], B[33];
    O[0] = 0x03; memset(O + 1, 0xCC, 32);   /* owner (Elder), distinct from agent */
    A[0] = 0x02; memset(A + 1, 0xAA, 32);   /* genesis agent: ctor[1] AND state[0] */
    B[0] = 0x02; memset(B + 1, 0xBB, 32);   /* rotated (new) agent: state[0] only  */

    /* push-form needles: a 33-byte data push is opcode 0x21 then the 33 bytes. */
    uint8_t pushO[34], pushA[34], pushB[34];
    pushO[0] = 0x21; memcpy(pushO + 1, O, 33);
    pushA[0] = 0x21; memcpy(pushA + 1, A, 33);
    pushB[0] = 0x21; memcpy(pushB + 1, B, 33);

    /* --- build the instance from the golden inputs, then force owner=O, agent=A. */
    char *gj = read_file_all(GOLDEN_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(gj, "cannot read golden.json");
    cJSON *root = cJSON_Parse(gj);
    free(gj);
    TEST_ASSERT_NOT_NULL(root);
    const cJSON *in = jobj(jobj(jobj(root, "lockingScripts"), "agentTea"), "inputs");
    TEST_ASSERT_NOT_NULL(in);

    scrypt_artifact_t art; memset(&art, 0, sizeof art);
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK, load_artifact(AGENT_TEA_ARTIFACT, &art),
                                  "load AgentTea artifact");

    agent_tea_t c;
    build_golden_instance(&art, in, &c);
    set_buf(&c.params.owner, O, 33);   /* owner O = 0x03 || 0xCC*32 */
    set_buf(&c.params.agent, A, 33);   /* agent A = 0x02 || 0xAA*32 */

    /* B as a byte_buf for the _ex override. */
    byte_buf_t B_buf; byte_buf_init(&B_buf);
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_from(&B_buf, B, 33));

    /* --- the two scripts under test ---
     * plain    : agent_tea_locking_script(c,false)   -> A for BOTH ctor[1] & state[0]
     * override : agent_tea_locking_script_ex(c,false,&B) -> A at ctor[1], B at state[0] */
    byte_buf_t plain, override;
    byte_buf_init(&plain);
    byte_buf_init(&override);
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK,
        agent_tea_locking_script(&c, false, &plain), "locking_script (plain)");
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK,
        agent_tea_locking_script_ex(&c, false, &B_buf, &override), "locking_script_ex (override)");

    /* The override may NOT change the script length. */
    TEST_ASSERT_EQUAL_size_t_MESSAGE(plain.len, override.len,
                                     "override must not resize the locking script");

    /* ---- locate the pubkey pushes ---- */
    size_t offO_plain[4], offA_plain[4], offB_plain[4];
    size_t offO_ovr[4],   offA_ovr[4],   offB_ovr[4];
    size_t nO_plain = find_all(plain.data, plain.len, pushO, 34, offO_plain, 4);
    size_t nA_plain = find_all(plain.data, plain.len, pushA, 34, offA_plain, 4);
    size_t nB_plain = find_all(plain.data, plain.len, pushB, 34, offB_plain, 4);
    size_t nO_ovr   = find_all(override.data, override.len, pushO, 34, offO_ovr, 4);
    size_t nA_ovr   = find_all(override.data, override.len, pushA, 34, offA_ovr, 4);
    size_t nB_ovr   = find_all(override.data, override.len, pushB, 34, offB_ovr, 4);

    /* (a) owner appears exactly once (ctor[0]); it is NOT the agent (O != A) so
     *     the agent embeddings below are provably the AGENT, not the owner. */
    TEST_ASSERT_EQUAL_size_t_MESSAGE(1, nO_plain, "owner O appears once in plain");
    TEST_ASSERT_EQUAL_size_t_MESSAGE(1, nO_ovr,   "owner O appears once in override");

    /* (a) the agent A is embedded TWICE in plain (ctor[1] in the frozen code part
     *     + state[0] in the trailer) and ONCE in override (only ctor[1] survives;
     *     state[0] became B). B is absent from plain, present once in override. */
    TEST_ASSERT_EQUAL_size_t_MESSAGE(2, nA_plain, "agent A embedded twice in plain (ctor[1]+state[0])");
    TEST_ASSERT_EQUAL_size_t_MESSAGE(0, nB_plain, "new agent B absent from plain");
    TEST_ASSERT_EQUAL_size_t_MESSAGE(1, nA_ovr,   "agent A remains once in override (ctor[1] only)");
    TEST_ASSERT_EQUAL_size_t_MESSAGE(1, nB_ovr,   "new agent B present once in override (state[0])");

    /* ctor[1] is the FIRST (front) A push; state[0] is the LAST (trailer) A push. */
    size_t ctor1_plain  = offA_plain[0];
    size_t state0_plain = offA_plain[1];
    TEST_ASSERT_TRUE_MESSAGE(ctor1_plain < state0_plain,
                             "ctor[1] precedes state[0] in the script");

    /* (a) CORE: the override does NOT touch ctor[1] — the single surviving A push
     *     in override sits at the SAME offset as plain's ctor[1] A push. */
    TEST_ASSERT_EQUAL_size_t_MESSAGE(ctor1_plain, offA_ovr[0],
                                     "ctor[1] agent must be unchanged by the override");

    /* (b) state[0]: plain carries A there, override carries B there, at the SAME
     *     script offset (only the 33-byte body flipped A->B). */
    size_t state0_ovr = offB_ovr[0];
    TEST_ASSERT_EQUAL_size_t_MESSAGE(state0_plain, state0_ovr,
                                     "@state agent push must occupy the same offset");

    /* (c) THE CORE REGRESSION: byte-diff the two scripts. The differing bytes must
     *     form a single contiguous run lying ENTIRELY inside the state[0] agent
     *     push body — i.e. the override changes ONLY state[0], never ctor[1] or
     *     anything else. (A and B share the 0x02 SEC prefix, so the run is the 32
     *     trailing key bytes; assert <= 33 to bound it to one pubkey push.) */
    size_t lo = (size_t)-1, hi = 0, ndiff = 0;
    for (size_t i = 0; i < plain.len; i++) {
        if (plain.data[i] != override.data[i]) {
            if (lo == (size_t)-1) lo = i;
            hi = i;
            ndiff++;
        }
    }
    TEST_ASSERT_TRUE_MESSAGE(ndiff > 0, "scripts must differ (override took effect)");
    /* single contiguous run: every index in [lo,hi] differs, none in between match. */
    TEST_ASSERT_EQUAL_size_t_MESSAGE(hi - lo + 1, ndiff,
                                     "differences must be one contiguous run");
    TEST_ASSERT_TRUE_MESSAGE(hi - lo + 1 <= 33,
                             "diff run must fit within a single 33-byte pubkey push");
    /* the run lies inside the state[0] push BODY (the 33 bytes after its 0x21). */
    size_t state0_body = state0_plain + 1;
    TEST_ASSERT_TRUE_MESSAGE(lo >= state0_body && hi < state0_body + 33,
                             "the only diff is the @state agent (state[0]) body");

    /* (d) decode the override script: the @state agent must round-trip to B
     *     (and, for contrast, the plain script's @state agent decodes to A). */
    agent_tea_state_t dec_o; memset(&dec_o, 0, sizeof dec_o);
    byte_buf_t agent_o; byte_buf_init(&agent_o);
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK,
        agent_tea_from_tx(override.data, override.len, &art, &dec_o, &agent_o),
        "agent_tea_from_tx (override)");
    TEST_ASSERT_EQUAL_size_t(33, agent_o.len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(B, agent_o.data, 33,
                                         "decoded @state agent of override == B");

    agent_tea_state_t dec_p; memset(&dec_p, 0, sizeof dec_p);
    byte_buf_t agent_p; byte_buf_init(&agent_p);
    TEST_ASSERT_EQUAL_INT_MESSAGE(BNS_OK,
        agent_tea_from_tx(plain.data, plain.len, &art, &dec_p, &agent_p),
        "agent_tea_from_tx (plain)");
    TEST_ASSERT_EQUAL_size_t(33, agent_p.len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(A, agent_p.data, 33,
                                         "decoded @state agent of plain == A");

    /* cleanup */
    byte_buf_free(&agent_o); agent_tea_state_free(&dec_o);
    byte_buf_free(&agent_p); agent_tea_state_free(&dec_p);
    byte_buf_free(&plain);
    byte_buf_free(&override);
    byte_buf_free(&B_buf);
    agent_tea_free(&c);
    scrypt_artifact_free(&art);
    cJSON_Delete(root);
}

/* ============================================================================ */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_recover_override_changes_only_state_agent);
    return UNITY_END();
}
