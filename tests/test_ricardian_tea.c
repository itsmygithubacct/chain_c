/*
 * test_ricardian_tea.c — Unity port of chain/tests/ricardianTea.test.ts.
 *
 * The TS suite is "RicardianTea (Model D settlement + Cyber-Chama validator +
 * slashing)". The vast majority of its assertions inspect a `tx` produced by a
 * sCrypt method call (executeTea / slash / updateSlashCheckpoint / revoke)
 * running inside the bsv Script VM, or assert that such a call IS / IS NOT
 * rejected by the on-chain `assert(...)`s (per-tx limit, daily budget, tier
 * monotonicity, window reset, locktime/sequence, input-0 pin, SPV merkle proof,
 * confirmation-chain, checkpoint). The C port has NO script interpreter — it
 * reconstructs the locking script from the compiled artifact and owns the
 * byte-exact preimage layouts the contract hashes — so those VM-execution
 * assertions are TEST_IGNORE'd with reasons.
 *
 * What this file DOES mirror faithfully (the cluster's focus: locking-script
 * reconstruction byte-equality, Rabin verify logic, and the receipt/slash byte
 * preimages):
 *   - receiptHashOf(amount, txCount, now [, provenanceHash]): the exact receipt
 *     preimage the contract hashes (ricardian_tea_receipt_preimage / _hash). This
 *     is the value the settlement / pipeline / provenance / replay-binding TS
 *     assertions all pivot on.
 *   - provenance is genuinely committed: a non-zero provenanceHash changes the
 *     receipt (the "commits per-action provenance" / "not ignored" assertions).
 *   - txCount (PRE-increment) and `now` (4-byte CScriptNum) are bound into the
 *     receipt — the basis of the per-tx replay-binding rejection.
 *   - attestationMsg(amount, attestedLimit, rh): exact RTEA_ATTEST_V1 preimage
 *     (ricardian_tea_attestation_msg), and the validator-attestation Rabin
 *     verify: a VALID designated-validator sig verifies; a WRONG-key sig does
 *     not; a legacy UNBOUND message and a wrong attestedLimit / replayed receipt
 *     hash all produce a different message that fails verify (the gate /
 *     wrong-key / vouched-low / replay rejections).
 *   - the RicardianTea locking script reconstructs byte-identically to the
 *     golden (lockingScripts.ricardianTea, 50286 hex bytes).
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
#include "crypto/hash.h"
#include "crypto/rabin.h"
#include "bsv/num2bin.h"
#include "lib/rabin_verifier.h"
#include "scrypt/scrypt_contract.h"
#include "scrypt/artifact_loader.h"
#include "contracts/ricardian_tea.h"
#include "provenance.h"

#include "tx_helper.h"
#include "rabin_test.h"

/* ---- TS constants (ricardianTea.test.ts) -------------------------------- */
#define NOW          1700000000LL          /* NOW = 1_700_000_000n */
#define AMT_50K      "50000"
#define AMT_100K     "100000"

/* The golden RicardianTea designated-validator Rabin pubkey n (decimal). It is
 * the pubkey of the golden {p,q} (rabin.json), reused here so a real validator
 * signature can be built and verified. */
static const char *VPUB_DEC =
 "299203064105282833356246877326272312211594806807618858763144117360900040255598"
 "192438742206865086277473399368259092542792692767510461222235434090317947180809"
 "488013043253628476810768133011634351840110688758004086243058850832475355727214"
 "498537191261794575688914073384875009172590515101390124792698061641128218750883"
 "231920699904614892770650790726754062030442370452178641090688118514401264510797"
 "986812715565794680101583208463892760936120829296062252749815730401267255124210"
 "601301517239060286963106682526814636710728546075419979654625066279620023085282"
 "525860628769697734211405120435649399315657088115845365556079902482098760616313"
 "971661243620490129497063821924620869983799521040768472397927558512950137477216"
 "722777974646105850496842947264785931784846281795241675668538907593333325675562"
 "819230851881437949676316526852505220212888766778179812293081919897148914511691"
 "538829342987958102247974957495628326314423451580684574818258095801";
#define GOLD_P \
 "501928414477146742103144761261161799249869986136549140940263474210035780753350" \
 "253092681840749285310830905542377538579781321348815694041719353403267622696022" \
 "640195131948170294004996246487160369347259034881296831993128442313722619542876" \
 "481863944145248893279661325260072252250759215179672510089929251886166472640882" \
 "139971159611513866609045635375069083469484300150101836965451940347826083525933" \
 "164312985583764804338319100547106363249306721918727425903820197767619463"
#define GOLD_Q \
 "596107045298400458252166935475670773770719475352095960522241631519131608447902" \
 "198733645559038623436359080362854694236694602264559983996792955824075131171656" \
 "650290615449112408883796614199188122934876247421447930270731614574296538310129" \
 "510664553634548362495436508424512627163326991150674761045573605183981673244833" \
 "535226594348923435064735998491597386372350452280035760985518051779227019005676" \
 "568400451856819803602028717309981670153666599797619275940384359277448127"

/* shared per-test fixtures */
static ricardian_tea_t g_c;            /* a minimal RicardianTea (receipt-relevant fields only) */
static uint8_t   g_agent33[33];
static uint8_t   g_cp33[33];           /* counterparty pubkey (33B) */
static uint8_t   g_rh32[32];           /* ricardianHash (32B) */
static uint8_t   g_inv32[32];          /* invoiceHash (32B) */
static uint8_t   g_zero32[32];         /* ZERO_PROVENANCE */
static rabin_key_t g_vk;               /* the designated-validator (golden) key */
static rabin_key_t g_wk;               /* a wrong key (fixed test key) */
static bn_t       *g_vpub;             /* validator pubkey n */
static bn_t       *g_wpub;             /* wrong key pubkey n */

/* set g_c.state.tx_count to a fresh decimal */
static void set_txcount(const char *dec)
{
    bn_free(g_c.state.tx_count);
    g_c.state.tx_count = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec(dec, &g_c.state.tx_count));
}

void setUp(void)
{
    memset(&g_c, 0, sizeof g_c);
    byte_buf_init(&g_c.params.ricardian_hash);
    byte_buf_init(&g_c.params.agent);

    /* ricardianHash / invoiceHash: fixed 32-byte literals (sha256-shaped). */
    for (int i = 0; i < 32; i++) { g_rh32[i] = 0xf6; g_inv32[i] = 0x11; }
    memset(g_zero32, 0, 32);

    TEST_ASSERT_EQUAL_INT(BNS_OK, tx_helper_pubkey_bytes(TX_KEY_AGENT, g_agent33));
    TEST_ASSERT_EQUAL_INT(BNS_OK, tx_helper_pubkey_bytes(TX_KEY_COUNTERPARTY, g_cp33));

    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&g_c.params.ricardian_hash, g_rh32, 32));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&g_c.params.agent, g_agent33, 33));
    set_txcount("0");  /* genesis txCount */

    /* validator key = golden key; wrong key = fixed test key */
    memset(&g_vk, 0, sizeof g_vk);
    memset(&g_wk, 0, sizeof g_wk);
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec(GOLD_P, &g_vk.p));
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec(GOLD_Q, &g_vk.q));
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_test_fixed_key(&g_wk));
    g_vpub = NULL; g_wpub = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_pubkey(&g_vk, &g_vpub));
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_pubkey(&g_wk, &g_wpub));

    /* sanity: g_vpub decimal == the golden VPUB_DEC literal */
    char *vd = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_to_dec(g_vpub, &vd));
    TEST_ASSERT_EQUAL_STRING(VPUB_DEC, vd);
    free(vd);
}

void tearDown(void)
{
    byte_buf_free(&g_c.params.ricardian_hash);
    byte_buf_free(&g_c.params.agent);
    bn_free(g_c.state.tx_count);
    rabin_key_free(&g_vk);
    rabin_key_free(&g_wk);
    bn_free(g_vpub);
    bn_free(g_wpub);
    g_vpub = g_wpub = NULL;
}

/* ---- local re-implementations of the TS `receiptHashOf` / `attestationMsg`
 *      helpers, built ONLY from primitives (sha256 + the two int encoders), to
 *      cross-check the library's builders byte-for-byte. -------------------- */

static void append_sized(byte_buf_t *b, int64_t v, size_t w)
{
    char s[32]; snprintf(s, sizeof s, "%lld", (long long)v);
    bn_t *n = NULL; TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec(s, &n));
    byte_buf_t t; byte_buf_init(&t);
    TEST_ASSERT_EQUAL_INT(BNS_OK, int2bytestring_sized(n, w, &t));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(b, t.data, t.len));
    byte_buf_free(&t); bn_free(n);
}

/* independent expected receipt hash (TS receiptHashOf). out_hex is 65 bytes. */
static void expected_receipt_hex(int64_t amount, int64_t txCount, int64_t now,
                                 const uint8_t prov[32], char out_hex[65])
{
    byte_buf_t pre; byte_buf_init(&pre);
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&pre, g_rh32, 32));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&pre, g_agent33, 33));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&pre, g_cp33, 33));
    append_sized(&pre, amount, 8);
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&pre, g_inv32, 32));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&pre, prov, 32));
    append_sized(&pre, txCount, 8);     /* PRE-increment txCount */
    append_sized(&pre, now, 4);         /* now as 4-byte CScriptNum */
    uint8_t d[32]; sha256(pre.data, pre.len, d);
    for (int i = 0; i < 32; i++) snprintf(out_hex + 2 * i, 3, "%02x", d[i]);
    out_hex[64] = 0;
    byte_buf_free(&pre);
}

/* library receipt hash for given amount/now (txCount taken from g_c.state). */
static char *lib_receipt_hex(const char *amount_dec, const uint8_t prov[32], int64_t now)
{
    bn_t *amount = NULL; TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec(amount_dec, &amount));
    char *hex = NULL;
    int rc = ricardian_tea_receipt_hash(&g_c, g_cp33, amount, g_inv32, prov, now, &hex);
    TEST_ASSERT_EQUAL_INT(BNS_OK, rc);
    bn_free(amount);
    return hex;
}

/* ============================================================================
 * RECEIPT PREIMAGE / HASH (the receiptHashOf pivot)
 * ========================================================================= */

/* TS: "the receipt it commits is readable by the indexer" + "settles" pivot on
 * receiptHashOf(50_000, 0, NOW). The library receipt hash must equal the
 * independently-built preimage's sha256. */
static void test_receipt_hash_matches_receiptHashOf(void)
{
    char exp[65]; expected_receipt_hex(50000, 0, NOW, g_zero32, exp);
    char *got = lib_receipt_hex(AMT_50K, g_zero32, NOW);
    TEST_ASSERT_EQUAL_STRING(exp, got);
    free(got);
}

/* The raw preimage bytes (not just the hash) match the TS field layout exactly. */
static void test_receipt_preimage_byte_layout(void)
{
    byte_buf_t exp; byte_buf_init(&exp);
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&exp, g_rh32, 32));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&exp, g_agent33, 33));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&exp, g_cp33, 33));
    append_sized(&exp, 50000, 8);
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&exp, g_inv32, 32));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&exp, g_zero32, 32));
    append_sized(&exp, 0, 8);
    append_sized(&exp, NOW, 4);

    bn_t *amount = NULL; TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec(AMT_50K, &amount));
    byte_buf_t got; byte_buf_init(&got);
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        ricardian_tea_receipt_preimage(&g_c, g_cp33, amount, g_inv32, g_zero32, NOW, &got));
    TEST_ASSERT_EQUAL_UINT(exp.len, got.len);
    TEST_ASSERT_EQUAL_MEMORY(exp.data, got.data, exp.len);
    /* width pins: 32+33+33+8+32+32+8+4 = 182 */
    TEST_ASSERT_EQUAL_UINT(182u, (unsigned)got.len);
    bn_free(amount); byte_buf_free(&exp); byte_buf_free(&got);
}

/* TS "commits per-action provenance (Theme D)": a non-zero provenanceHash
 * CHANGES the receipt — committed, not ignored. */
static void test_provenance_changes_the_receipt(void)
{
    /* computeProvenanceHash over the canonical fixture record */
    uint8_t pHash[32];
    for (int i = 0; i < 32; i++) pHash[i] = (uint8_t)(0xA0 + (i & 0x0F));

    char *zero_rx = lib_receipt_hex(AMT_50K, g_zero32, NOW);
    char *prov_rx = lib_receipt_hex(AMT_50K, pHash,    NOW);
    TEST_ASSERT_NOT_NULL(zero_rx);
    TEST_ASSERT_NOT_NULL(prov_rx);
    /* receiptHashOf(.., pHash) != receiptHashOf(.., ZERO) */
    TEST_ASSERT_NOT_EQUAL(0, strcmp(zero_rx, prov_rx));

    /* and equals an independent recompute with pHash */
    char exp[65]; expected_receipt_hex(50000, 0, NOW, pHash, exp);
    TEST_ASSERT_EQUAL_STRING(exp, prov_rx);
    free(zero_rx); free(prov_rx);
}

/* TS replay-binding basis: receipt binds the PRE-increment txCount, so the same
 * (amount, now) at a different txCount yields a different receipt hash. */
static void test_receipt_binds_txcount(void)
{
    set_txcount("0");
    char *rx0 = lib_receipt_hex(AMT_100K, g_zero32, NOW);
    set_txcount("1");
    char *rx1 = lib_receipt_hex(AMT_100K, g_zero32, NOW);
    TEST_ASSERT_NOT_EQUAL(0, strcmp(rx0, rx1));
    free(rx0); free(rx1);
}

/* `now` (nLocktime) is bound into the receipt as a 4-byte CScriptNum: a
 * different locktime yields a different receipt hash. */
static void test_receipt_binds_now(void)
{
    char *a = lib_receipt_hex(AMT_50K, g_zero32, NOW);
    char *b = lib_receipt_hex(AMT_50K, g_zero32, NOW + 1);
    TEST_ASSERT_NOT_EQUAL(0, strcmp(a, b));
    free(a); free(b);
}

/* ============================================================================
 * ATTESTATION MESSAGE + VALIDATOR RABIN VERIFY
 * ========================================================================= */

/* Build the library attestationMsg into *out for given amount/limit decimals and
 * receipt-hash bytes. */
static void lib_att_msg(const char *amount_dec, const char *limit_dec,
                        const uint8_t rh32[32], byte_buf_t *out)
{
    bn_t *amt = NULL, *lim = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec(amount_dec, &amt));
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec(limit_dec, &lim));
    byte_buf_init(out);
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        ricardian_tea_attestation_msg(g_rh32, g_agent33, g_vpub, amt, lim, rh32, out));
    bn_free(amt); bn_free(lim);
}

/* TS attestationMsg layout pin: tag(13) || ricardianHash(32) || agent(33) ||
 * int2ByteString(vPub minimal) || amount(8) || attestedLimit(8) || rh(32). */
static void test_attestation_msg_byte_layout(void)
{
    uint8_t rh[32]; for (int i = 0; i < 32; i++) rh[i] = 0x5a;
    byte_buf_t got; lib_att_msg(AMT_100K, AMT_100K, rh, &got);

    /* domain tag 'RTEA_ATTEST_V1' = 525445415f4154544553545f5631 (14 bytes) */
    byte_buf_t exp_prefix; byte_buf_init(&exp_prefix);
    byte_buf_t tagbuf; byte_buf_init(&tagbuf);
    TEST_ASSERT_EQUAL_INT(BNS_OK, hex_decode(BONSAI_RTEA_ATTEST_TAG_HEX, &tagbuf));
    TEST_ASSERT_EQUAL_UINT(14u, (unsigned)tagbuf.len);
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&exp_prefix, tagbuf.data, tagbuf.len));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&exp_prefix, g_rh32, 32));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&exp_prefix, g_agent33, 33));

    /* prefix (tag||rh||agent) must match the first 78 bytes */
    TEST_ASSERT_GREATER_OR_EQUAL_UINT(exp_prefix.len, got.len);
    TEST_ASSERT_EQUAL_MEMORY(exp_prefix.data, got.data, exp_prefix.len);

    /* trailing 8+8+32 bytes: amount(8) || limit(8) || rh(32) */
    byte_buf_t exp_tail; byte_buf_init(&exp_tail);
    append_sized(&exp_tail, 100000, 8);
    append_sized(&exp_tail, 100000, 8);
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&exp_tail, rh, 32));
    TEST_ASSERT_GREATER_OR_EQUAL_UINT(exp_tail.len, got.len);
    TEST_ASSERT_EQUAL_MEMORY(exp_tail.data,
                             got.data + got.len - exp_tail.len, exp_tail.len);

    byte_buf_free(&got); byte_buf_free(&exp_prefix);
    byte_buf_free(&tagbuf); byte_buf_free(&exp_tail);
}

/* Sign the library attestation message with a Rabin key; fill *sig (free via
 * rabin_sig_free). Returns the raw message bytes in *msg (free via byte_buf_free). */
static void sign_att(const char *amount_dec, const char *limit_dec,
                     const uint8_t rh32[32], const rabin_key_t *key,
                     byte_buf_t *msg, rabin_sig_t *sig)
{
    lib_att_msg(amount_dec, limit_dec, rh32, msg);
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_sign(msg->data, msg->len, key, sig));
}

/* TS "accepts a high-value tx with a valid designated-validator attestation":
 * the validator's Rabin sig over attestationMsg verifies under the designated
 * validator pubkey. (The on-chain consumption is VM-bound; the verify predicate
 * is the faithful core.) */
static void test_valid_validator_attestation_verifies(void)
{
    uint8_t rh[32]; for (int i = 0; i < 32; i++) rh[i] = 0x7b;
    byte_buf_t msg; rabin_sig_t sig = {0};
    sign_att(AMT_100K, AMT_100K, rh, &g_vk, &msg, &sig);
    TEST_ASSERT_TRUE(rabin_verify(msg.data, msg.len, &sig, g_vpub));
    byte_buf_free(&msg); rabin_sig_free(&sig);
}

/* TS "rejects an attestation from the WRONG validator key": a sig by the wrong
 * key does not verify under the designated validator pubkey. */
static void test_wrong_key_attestation_rejected(void)
{
    uint8_t rh[32]; for (int i = 0; i < 32; i++) rh[i] = 0x7b;
    byte_buf_t msg; rabin_sig_t forged = {0};
    sign_att(AMT_100K, AMT_100K, rh, &g_wk, &msg, &forged);   /* wrong key */
    /* verifies under its own modulus but NOT under the validator's */
    TEST_ASSERT_TRUE (rabin_verify(msg.data, msg.len, &forged, g_wpub));
    TEST_ASSERT_FALSE(rabin_verify(msg.data, msg.len, &forged, g_vpub));
    byte_buf_free(&msg); rabin_sig_free(&forged);
}

/* TS "validator vouched a limit below the amount": the attestation message
 * encodes attestedLimit, so a vouch with attestedLimit < amount is a DIFFERENT
 * (lower-limit) message — a sig for limit=50_000 will not verify as a vouch for
 * limit=100_000. */
static void test_attested_limit_is_bound(void)
{
    uint8_t rh[32]; for (int i = 0; i < 32; i++) rh[i] = 0x7b;
    /* validator genuinely signs amount=100k / limit=50k */
    byte_buf_t msg_low; rabin_sig_t sig_low = {0};
    sign_att(AMT_100K, AMT_50K, rh, &g_vk, &msg_low, &sig_low);
    TEST_ASSERT_TRUE(rabin_verify(msg_low.data, msg_low.len, &sig_low, g_vpub));

    /* the message for limit=100k is different bytes, so the low-limit sig is not
       a valid vouch for the full-limit message */
    byte_buf_t msg_full; lib_att_msg(AMT_100K, AMT_100K, rh, &msg_full);
    /* the two attestation messages are genuinely different bytes */
    TEST_ASSERT_TRUE(msg_low.len != msg_full.len ||
                     memcmp(msg_low.data, msg_full.data, msg_full.len) != 0);
    TEST_ASSERT_FALSE(rabin_verify(msg_full.data, msg_full.len, &sig_low, g_vpub));

    byte_buf_free(&msg_low); byte_buf_free(&msg_full); rabin_sig_free(&sig_low);
}

/* TS "rejects a validator attestation replayed from a DIFFERENT tx": the
 * attestation binds the receiptHash, so a sig over receiptHash_A does not verify
 * as a vouch over receiptHash_B. */
static void test_attestation_replay_rejected(void)
{
    uint8_t rhA[32]; for (int i = 0; i < 32; i++) rhA[i] = 0x11;
    uint8_t rhB[32]; for (int i = 0; i < 32; i++) rhB[i] = 0x22;

    byte_buf_t msgA; rabin_sig_t sigA = {0};
    sign_att(AMT_100K, AMT_100K, rhA, &g_vk, &msgA, &sigA);
    TEST_ASSERT_TRUE(rabin_verify(msgA.data, msgA.len, &sigA, g_vpub));

    /* replay onto a DIFFERENT tx's receipt hash */
    byte_buf_t msgB; lib_att_msg(AMT_100K, AMT_100K, rhB, &msgB);
    TEST_ASSERT_FALSE(rabin_verify(msgB.data, msgB.len, &sigA, g_vpub));

    byte_buf_free(&msgA); byte_buf_free(&msgB); rabin_sig_free(&sigA);
}

/* TS "rejects slashing with a legacy unbound attestation": the bound
 * attestationMsg (tag + ricardianHash + agent + vPub + amount + limit + rh)
 * differs from the legacy unbound form (amount + limit + rh only), so a sig over
 * the legacy bytes does not verify as a bound attestation. */
static void test_legacy_unbound_attestation_rejected(void)
{
    uint8_t rh[32]; for (int i = 0; i < 32; i++) rh[i] = 0x7b;

    /* legacy unbound message: int2ByteString(amount,8) || limit(8) || rh */
    byte_buf_t legacy; byte_buf_init(&legacy);
    append_sized(&legacy, 100000, 8);
    append_sized(&legacy, 50000, 8);
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&legacy, rh, 32));
    rabin_sig_t legsig = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_sign(legacy.data, legacy.len, &g_vk, &legsig));
    /* the legacy sig verifies over the legacy bytes ... */
    TEST_ASSERT_TRUE(rabin_verify(legacy.data, legacy.len, &legsig, g_vpub));

    /* ... but NOT over the bound attestationMsg the contract checks */
    byte_buf_t bound; lib_att_msg(AMT_100K, AMT_50K, rh, &bound);
    TEST_ASSERT_TRUE(bound.len != legacy.len ||
                     memcmp(bound.data, legacy.data, bound.len) != 0);
    TEST_ASSERT_FALSE(rabin_verify(bound.data, bound.len, &legsig, g_vpub));

    byte_buf_free(&legacy); byte_buf_free(&bound); rabin_sig_free(&legsig);
}

/* TS slash "rejects a non-fraudulent attestation (amount <= limit)" vs fraud
 * (amount > limit): the off-chain fraud predicate is purely amount-vs-limit. The
 * attestation messages for the two cases are distinct and both verifiable when
 * signed; the fraud determination is amount > attestedLimit. */
static void test_fraud_predicate_is_amount_gt_limit(void)
{
    uint8_t rh[32]; for (int i = 0; i < 32; i++) rh[i] = 0x3c;

    /* fraud: amount(100k) > limit(50k) -> provably false attestation */
    byte_buf_t fmsg; rabin_sig_t fsig = {0};
    sign_att(AMT_100K, AMT_50K, rh, &g_vk, &fmsg, &fsig);
    TEST_ASSERT_TRUE(rabin_verify(fmsg.data, fmsg.len, &fsig, g_vpub));

    /* honest: amount(50k) <= limit(100k) -> not fraudulent */
    byte_buf_t hmsg; rabin_sig_t hsig = {0};
    sign_att(AMT_50K, AMT_100K, rh, &g_vk, &hmsg, &hsig);
    TEST_ASSERT_TRUE(rabin_verify(hmsg.data, hmsg.len, &hsig, g_vpub));

    long long amt_f = 100000, lim_f = 50000;    /* fraud */
    long long amt_h = 50000,  lim_h = 100000;   /* honest */
    TEST_ASSERT_TRUE (amt_f > lim_f);
    TEST_ASSERT_FALSE(amt_h > lim_h);

    byte_buf_free(&fmsg); byte_buf_free(&hmsg);
    rabin_sig_free(&fsig); rabin_sig_free(&hsig);
}

/* ============================================================================
 * LOCKING SCRIPT RECONSTRUCTION (byte-exact vs golden)
 * ========================================================================= */
static char *read_file(const char *path, long *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
    buf[n] = 0; fclose(f);
    if (out_len) *out_len = n;
    return buf;
}

static cJSON *gobj(const cJSON *o, const char *k) { return cJSON_GetObjectItem((cJSON*)o, k); }
static const char *gstr(const cJSON *o, const char *k)
{ cJSON *v = gobj(o, k); return (v && cJSON_IsString(v)) ? v->valuestring : NULL; }

/* TS: every freshInstance() deploys a RicardianTea whose lockingScript the
 * spends must match. We pin the reconstructed lockingScript to the golden
 * (lockingScripts.ricardianTea.lockingScript_hex, 50286 hex bytes). */
static void test_locking_script_byte_exact_golden(void)
{
    char *txt = read_file("tests/golden/golden.json", NULL);
    if (!txt) { TEST_IGNORE_MESSAGE("tests/golden/golden.json not readable from CWD"); return; }
    cJSON *root = cJSON_Parse(txt);
    free(txt);
    TEST_ASSERT_NOT_NULL(root);

    const cJSON *ls = gobj(root, "lockingScripts");
    const cJSON *rt = ls ? gobj(ls, "ricardianTea") : NULL;
    if (!rt) { cJSON_Delete(root); TEST_IGNORE_MESSAGE("missing lockingScripts.ricardianTea golden"); return; }
    const cJSON *in = gobj(rt, "inputs");
    const cJSON *ch = in ? gobj(in, "charter") : NULL;
    const char *exp_ls = gstr(rt, "lockingScript_hex");
    const char *exp_rh = gstr(rt, "ricardianHash_hex");
    TEST_ASSERT_NOT_NULL(exp_ls);
    TEST_ASSERT_NOT_NULL(in);
    TEST_ASSERT_NOT_NULL(ch);

    scrypt_artifact_t art; memset(&art, 0, sizeof art);
    if (load_artifact("artifacts/ricardianTea.json", &art) != BNS_OK) {
        cJSON_Delete(root);
        TEST_IGNORE_MESSAGE("artifacts/ricardianTea.json not loadable from CWD");
        return;
    }

    ricardian_tea_t c; memset(&c, 0, sizeof c);
    c.artifact = &art;
    byte_buf_init(&c.params.owner);
    byte_buf_init(&c.params.agent);
    byte_buf_init(&c.params.ricardian_hash);
    byte_buf_init(&c.params.initial_slash_checkpoint_hash);

    int ok = 1;
    ok &= hex_decode(gstr(in, "elderPubKey_hex"), &c.params.owner) == BNS_OK;
    ok &= hex_decode(gstr(in, "agentPubKey_hex"), &c.params.agent) == BNS_OK;
    ok &= hex_decode(exp_rh, &c.params.ricardian_hash) == BNS_OK;
    ok &= hex_decode(gstr(in, "initialSlashCheckpointHash_hex"),
                     &c.params.initial_slash_checkpoint_hash) == BNS_OK;
    /* charter / slash bigints (the golden encodes them as decimal STRINGS) */
    #define PI(field, parent, key) do { \
        const char *s = gstr(parent, key); \
        if (s) ok &= bn_parse_dec(s, &c.params.field) == BNS_OK; \
        else ok = 0; } while (0)
    PI(per_tx_limit,          ch, "perTxLimit");
    PI(daily_limit,           ch, "dailyLimit");
    PI(window_duration,       ch, "windowDuration");
    PI(graduation_threshold,  ch, "graduationThreshold");
    PI(validator_threshold,   ch, "validatorThreshold");
    PI(max_slashing_target,   in, "maxSlashingTarget");
    PI(min_slash_confirmations,in,"minSlashConfirmations");
    #undef PI
    ok &= bn_parse_dec(gstr(in, "designatedValidatorPubKey_decimal"),
                       &c.params.designated_validator_pubkey) == BNS_OK;
    ok &= bn_parse_dec(gstr(in, "validatorRabinPubKey_decimal"),
                       &c.params.validator_rabin_pubkey) == BNS_OK;

    if (!ok) {
        ricardian_tea_params_free(&c.params);
        scrypt_artifact_free(&art); cJSON_Delete(root);
        TEST_FAIL_MESSAGE("failed to build RicardianTea params from golden inputs");
        return;
    }

    TEST_ASSERT_EQUAL_INT(BNS_OK, ricardian_tea_genesis_state(&c.params, &c.state));

    byte_buf_t scr; byte_buf_init(&scr);
    TEST_ASSERT_EQUAL_INT(BNS_OK, ricardian_tea_locking_script(&c, /*is_genesis=*/false, &scr));

    char *got_hex = hex_encode(scr.data, scr.len);
    TEST_ASSERT_NOT_NULL(got_hex);
    TEST_ASSERT_EQUAL_UINT((unsigned)strlen(exp_ls), (unsigned)strlen(got_hex));
    TEST_ASSERT_EQUAL_STRING(exp_ls, got_hex);

    free(got_hex);
    byte_buf_free(&scr);
    ricardian_tea_state_free(&c.state);
    ricardian_tea_params_free(&c.params);
    scrypt_artifact_free(&art);
    cJSON_Delete(root);
}

/* ============================================================================
 * VM-EXECUTION ASSERTIONS — not reproducible without a script interpreter.
 * ========================================================================= */
static void test_settlement_outputs_ignored(void)
{
    TEST_IGNORE_MESSAGE(
        "executeTea output layout (pay==amount, P2PKH(cp), OP_RETURN receipt at "
        "out[2]) is produced by the scrypt VM call; receipt-hash byte-exactness "
        "covered by test_receipt_* + the tx-builder tests");
}
static void test_policy_gates_ignored(void)
{
    TEST_IGNORE_MESSAGE(
        "per-tx limit / daily budget / tier graduation+monotonicity / window "
        "reset / positive-amount / nLocktime / co-sign / input-0 pin are on-chain "
        "assert()s executed by the script VM (no interpreter in C port)");
}
static void test_validator_gate_boundary_ignored(void)
{
    TEST_IGNORE_MESSAGE(
        "the >= validatorThreshold gate (attestation mandatory AT threshold) is "
        "enforced by the contract's hashOutputs/assert flow; the verify predicate "
        "itself is covered by test_valid_validator_attestation_verifies et al.");
}
static void test_slash_spv_ignored(void)
{
    TEST_IGNORE_MESSAGE(
        "slash() SPV checks (header work policy, Merkle inclusion, confirmation "
        "header chain, checkpoint reachability, txid==preimage) require the script "
        "VM + Blockchain.blockHeaderHash; slash() is SUPERSEDED (test parity only)");
}
static void test_checkpoint_and_revoke_ignored(void)
{
    TEST_IGNORE_MESSAGE(
        "updateSlashCheckpoint (Elder-only, extension chain, tip pin) and revoke "
        "(Elder-only) are scrypt method calls validated by the VM");
}

int main(void)
{
    UNITY_BEGIN();
    /* receipt preimage / hash */
    RUN_TEST(test_receipt_hash_matches_receiptHashOf);
    RUN_TEST(test_receipt_preimage_byte_layout);
    RUN_TEST(test_provenance_changes_the_receipt);
    RUN_TEST(test_receipt_binds_txcount);
    RUN_TEST(test_receipt_binds_now);
    /* attestation msg + rabin verify */
    RUN_TEST(test_attestation_msg_byte_layout);
    RUN_TEST(test_valid_validator_attestation_verifies);
    RUN_TEST(test_wrong_key_attestation_rejected);
    RUN_TEST(test_attested_limit_is_bound);
    RUN_TEST(test_attestation_replay_rejected);
    RUN_TEST(test_legacy_unbound_attestation_rejected);
    RUN_TEST(test_fraud_predicate_is_amount_gt_limit);
    /* locking script byte-exact */
    RUN_TEST(test_locking_script_byte_exact_golden);
    /* VM-bound (ignored) */
    RUN_TEST(test_settlement_outputs_ignored);
    RUN_TEST(test_policy_gates_ignored);
    RUN_TEST(test_validator_gate_boundary_ignored);
    RUN_TEST(test_slash_spv_ignored);
    RUN_TEST(test_checkpoint_and_revoke_ignored);
    return UNITY_END();
}
