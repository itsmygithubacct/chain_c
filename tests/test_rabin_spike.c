/*
 * test_rabin_spike.c — Unity port of chain/tests/rabinSpike.test.ts.
 *
 * The TS test is the RabinSpike off-chain-sign / on-chain-verify roundtrip:
 *   1) accepts a valid Rabin signature  (instance.methods.unlock(msg, sign(msg)))
 *   2) rejects a tampered message       (sig for msgA, unlock with msgB -> reject)
 *
 * The TS `unlock` runs inside the sCrypt VM and its sole assertion is
 * `assert(RabinVerifier.verifySig(msg, sig, this.oraclePubKey))`. The C port
 * exposes that predicate directly as rabin_spike_unlock_verify (and the lower
 * lib/rabin_verifier.h rabin_verifier_verify_sig). We mirror the two behaviours
 * against that predicate, and additionally pin the byte-exact golden Rabin
 * signature (tests/golden rabin area) — the TS uses a RANDOM key so it can only
 * assert accept/reject; the C golden lets us pin the exact wire bytes too.
 *
 * The actual scrypt bytecode interpretation of unlock() (deploy + methods.unlock
 * driving the bsv Script VM) is NOT reproduced — there is no script interpreter
 * in the C port — so that layer is TEST_IGNORE'd with a reason. What IS faithful:
 * the verifySig predicate (the only thing unlock asserts) and the locking-script
 * reconstruction from the compiled artifact.
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
#include "common/bytes.h"
#include "common/hex.h"
#include "crypto/bignum.h"
#include "crypto/rabin.h"
#include "lib/rabin_verifier.h"
#include "scrypt/scrypt_contract.h"
#include "scrypt/artifact_loader.h"
#include "contracts/rabin_spike.h"

#include "rabin_test.h"

/* ----------------------------------------------------------------------------
 * The byte-exact golden Rabin vector (tests/golden/by-area/rabin.json).
 * Captured from rabinsig Rabin(6).generatePrivKeyFromSeed(42*64): the key {p,q},
 * the pubkey n, and the canonical sign of message 00010203 -> s + paddingByteCount.
 * ------------------------------------------------------------------------- */
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
#define GOLD_N \
 "299203064105282833356246877326272312211594806807618858763144117360900040255598" \
 "192438742206865086277473399368259092542792692767510461222235434090317947180809" \
 "488013043253628476810768133011634351840110688758004086243058850832475355727214" \
 "498537191261794575688914073384875009172590515101390124792698061641128218750883" \
 "231920699904614892770650790726754062030442370452178641090688118514401264510797" \
 "986812715565794680101583208463892760936120829296062252749815730401267255124210" \
 "601301517239060286963106682526814636710728546075419979654625066279620023085282" \
 "525860628769697734211405120435649399315657088115845365556079902482098760616313" \
 "971661243620490129497063821924620869983799521040768472397927558512950137477216" \
 "722777974646105850496842947264785931784846281795241675668538907593333325675562" \
 "819230851881437949676316526852505220212888766778179812293081919897148914511691" \
 "538829342987958102247974957495628326314423451580684574818258095801"
#define GOLD_MSG_HEX  "00010203"
#define GOLD_PADDING  1u
#define GOLD_S_HEX \
 "bed4deb87d7b83b13bd7227d0ac3c3f78e61370c3c27d6e071fbef8d37b1bfcc1199595600965e34" \
 "f436ecd13c3081321c338e015a6834d6f923298dee28d5916237b980f0bde76275496cd5542e03e8" \
 "e2a04d728ffa4650d6e25272833c22bd5c68cb31340f197199edd148b781e7524e01305beba852fb" \
 "d5ee0d67988572f01ba955ecd27d27b29c0e64a21ddb75642cc56d202f582ce84a377db94de2bf29" \
 "191b4b49e9785dfd8e21a67aa8bd1ae267db2e9a0079195ead122272fd272c5672b2568a9ca16525" \
 "2fec92562266d8d3e7305e505dac3a39a3bc1533b90e4663e001509bcad05526c27b1c5ac616eebb" \
 "f044136546a9f5df5ee1da64dd63ed62970c1620764cdc02af8322c827a09e0789ea8cdeec26f15c" \
 "5a461333b423f04f980567311f563a140d32d9b174d0cc623da4582e9e819d536c85bb90b6fce551" \
 "c2f4b13035dd0eb8ffd4ea2b2db5c2f31374d63864ab22a572a714b19ca736b107a8e4adf3a627d1" \
 "330721b75a2f14b70a2fdaca2993e82ec38a58aa5c5fecd"

/* ----------------------------------------------------------------------------
 * Shared golden-key fixtures
 * ------------------------------------------------------------------------- */
static rabin_key_t g_key;   /* the golden {p,q} */
static bn_t       *g_n;     /* the golden pubkey n */

void setUp(void)
{
    memset(&g_key, 0, sizeof g_key);
    g_n = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec(GOLD_P, &g_key.p));
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec(GOLD_Q, &g_key.q));
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_pubkey(&g_key, &g_n));
}

void tearDown(void)
{
    rabin_key_free(&g_key);
    bn_free(g_n);
    g_n = NULL;
}

/* Sign a hex message with the golden key; caller frees *sig via rabin_sig_free. */
static void golden_sign(const char *msg_hex, rabin_sig_t *sig)
{
    byte_buf_t m; byte_buf_init(&m);
    TEST_ASSERT_EQUAL_INT(BNS_OK, hex_decode(msg_hex, &m));
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_sign(m.data, m.len, &g_key, sig));
    byte_buf_free(&m);
}

/* ----------------------------------------------------------------------------
 * 0. The pubkey n derived from the golden {p,q} is the captured RabinPubKey.
 *    (rabinPubKey(key) in the TS helper; pins the contract @prop wire value.)
 * ------------------------------------------------------------------------- */
static void test_golden_pubkey_n_is_byte_exact(void)
{
    char *ndec = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_to_dec(g_n, &ndec));
    TEST_ASSERT_EQUAL_STRING(GOLD_N, ndec);
    free(ndec);
}

/* ----------------------------------------------------------------------------
 * 1. The golden sign(00010203) is byte-exact: s == GOLD_S_HEX, padding == 1.
 *    (rabinSign(msgHex, key) -> { s, padding }; the wire bytes the TS would hand
 *    to methods.unlock.)
 * ------------------------------------------------------------------------- */
static void test_golden_sign_is_byte_exact(void)
{
    rabin_sig_t sig = {0};
    golden_sign(GOLD_MSG_HEX, &sig);

    TEST_ASSERT_EQUAL_UINT(GOLD_PADDING, (unsigned)sig.padding_byte_count);

    char *shex = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_to_hex(sig.s, &shex)); /* lowercase, no pad */
    TEST_ASSERT_EQUAL_STRING(GOLD_S_HEX, shex);
    free(shex);
    rabin_sig_free(&sig);
}

/* ----------------------------------------------------------------------------
 * 2. TS "accepts a valid Rabin signature": unlock(msg, sign(msg)) is NOT
 *    rejected. The unlock body is assert(RabinVerifier.verifySig(msg, sig, n)),
 *    so the faithful C assertion is rabin_verifier_verify_sig(...) == true.
 * ------------------------------------------------------------------------- */
static void test_accepts_a_valid_rabin_signature(void)
{
    byte_buf_t msg; byte_buf_init(&msg);
    TEST_ASSERT_EQUAL_INT(BNS_OK, hex_decode("00112233aabbccdd", &msg));

    rabin_sig_t sig = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_sign(msg.data, msg.len, &g_key, &sig));

    /* padding as raw 0x00 bytes (the contract-side RabinSig.padding ByteString) */
    uint8_t pad[8] = {0};
    rabin_verifier_sig_t vsig = {
        .s = sig.s, .padding = pad, .padding_len = sig.padding_byte_count,
    };
    TEST_ASSERT_TRUE(rabin_verifier_verify_sig(msg.data, msg.len, &vsig, g_n));

    /* And via crypto/rabin.h's predicate (must agree). */
    TEST_ASSERT_TRUE(rabin_verify(msg.data, msg.len, &sig, g_n));

    rabin_sig_free(&sig);
    byte_buf_free(&msg);
}

/* ----------------------------------------------------------------------------
 * 3. TS "rejects a tampered message": a sig for msgA verified against a
 *    DIFFERENT msgB must fail. unlock(wrongMsg, sigForRightMsg) -> rejected.
 * ------------------------------------------------------------------------- */
static void test_rejects_a_tampered_message(void)
{
    byte_buf_t msg; byte_buf_init(&msg);
    TEST_ASSERT_EQUAL_INT(BNS_OK, hex_decode("00112233aabbccdd", &msg));
    rabin_sig_t sig = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_sign(msg.data, msg.len, &g_key, &sig));

    byte_buf_t wrong; byte_buf_init(&wrong);
    TEST_ASSERT_EQUAL_INT(BNS_OK, hex_decode("deadbeefdeadbeef", &wrong));

    uint8_t pad[8] = {0};
    rabin_verifier_sig_t vsig = {
        .s = sig.s, .padding = pad, .padding_len = sig.padding_byte_count,
    };
    TEST_ASSERT_FALSE(rabin_verifier_verify_sig(wrong.data, wrong.len, &vsig, g_n));
    TEST_ASSERT_FALSE(rabin_verify(wrong.data, wrong.len, &sig, g_n));

    rabin_sig_free(&sig);
    byte_buf_free(&wrong);
    byte_buf_free(&msg);
}

/* ----------------------------------------------------------------------------
 * 4. A signature from the WRONG key must not verify against the golden n
 *    (forgery rejection — implicit in "accepts a VALID signature").
 * ------------------------------------------------------------------------- */
static void test_rejects_signature_from_wrong_key(void)
{
    rabin_key_t wk;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_test_fixed_key(&wk)); /* a different key */

    byte_buf_t msg; byte_buf_init(&msg);
    TEST_ASSERT_EQUAL_INT(BNS_OK, hex_decode("00112233aabbccdd", &msg));
    rabin_sig_t forged = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_sign(msg.data, msg.len, &wk, &forged));

    /* forged sig verifies under ITS OWN modulus but NOT under the golden n */
    bn_t *wn = NULL; TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_pubkey(&wk, &wn));
    TEST_ASSERT_TRUE (rabin_verify(msg.data, msg.len, &forged, wn));
    TEST_ASSERT_FALSE(rabin_verify(msg.data, msg.len, &forged, g_n));

    bn_free(wn);
    rabin_sig_free(&forged);
    rabin_key_free(&wk);
    byte_buf_free(&msg);
}

/* ----------------------------------------------------------------------------
 * 5. The RabinSpike locking script reconstructs from the compiled artifact with
 *    the oracle pubkey substituted (the lockingScript the TS instance carries).
 *    Pure structural pin: a non-empty script whose template-substitution does
 *    not error. (No lockingScript golden is captured for rabinSpike, so we pin
 *    determinism: two reconstructions are byte-identical and stable.)
 * ------------------------------------------------------------------------- */
static void test_locking_script_reconstructs_deterministically(void)
{
    scrypt_artifact_t art; memset(&art, 0, sizeof art);
    if (load_artifact("artifacts/rabinSpike.json", &art) != BNS_OK) {
        TEST_IGNORE_MESSAGE("artifacts/rabinSpike.json not loadable from CWD");
        return;
    }

    rabin_spike_t c = { .artifact = &art, .oracle_pubkey = NULL };
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec(GOLD_N, &c.oracle_pubkey));

    byte_buf_t s1; byte_buf_init(&s1);
    byte_buf_t s2; byte_buf_init(&s2);
    int rc1 = rabin_spike_locking_script(&c, &s1);
    int rc2 = rabin_spike_locking_script(&c, &s2);
    TEST_ASSERT_EQUAL_INT(BNS_OK, rc1);
    TEST_ASSERT_EQUAL_INT(BNS_OK, rc2);
    TEST_ASSERT_GREATER_THAN_UINT(0, (unsigned)s1.len);
    TEST_ASSERT_EQUAL_UINT(s1.len, s2.len);
    TEST_ASSERT_EQUAL_MEMORY(s1.data, s2.data, s1.len);

    byte_buf_free(&s1);
    byte_buf_free(&s2);
    rabin_spike_free(&c);
    scrypt_artifact_free(&art);
}

/* ----------------------------------------------------------------------------
 * 6. rabin_spike_unlock_verify is the faithful off-chain model of unlock():
 *    it must agree with the lib predicate for both accept and reject.
 * ------------------------------------------------------------------------- */
static void test_unlock_verify_predicate_matches_unlock_semantics(void)
{
    scrypt_artifact_t art; memset(&art, 0, sizeof art);
    if (load_artifact("artifacts/rabinSpike.json", &art) != BNS_OK) {
        TEST_IGNORE_MESSAGE("artifacts/rabinSpike.json not loadable from CWD");
        return;
    }
    rabin_spike_t c = { .artifact = &art, .oracle_pubkey = NULL };
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec(GOLD_N, &c.oracle_pubkey));

    byte_buf_t msg; byte_buf_init(&msg);
    TEST_ASSERT_EQUAL_INT(BNS_OK, hex_decode("00112233aabbccdd", &msg));
    rabin_sig_t sig = {0};
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_sign(msg.data, msg.len, &g_key, &sig));
    uint8_t pad[8] = {0};
    rabin_verifier_sig_t vsig = {
        .s = sig.s, .padding = pad, .padding_len = sig.padding_byte_count,
    };

    /* accept */
    TEST_ASSERT_TRUE(rabin_spike_unlock_verify(&c, msg.data, msg.len, &vsig));

    /* reject (tampered) */
    byte_buf_t wrong; byte_buf_init(&wrong);
    TEST_ASSERT_EQUAL_INT(BNS_OK, hex_decode("deadbeefdeadbeef", &wrong));
    TEST_ASSERT_FALSE(rabin_spike_unlock_verify(&c, wrong.data, wrong.len, &vsig));

    byte_buf_free(&wrong);
    byte_buf_free(&msg);
    rabin_sig_free(&sig);
    rabin_spike_free(&c);
    scrypt_artifact_free(&art);
}

/* ----------------------------------------------------------------------------
 * 7. The on-chain VM execution of unlock() (deploy + methods.unlock driving the
 *    bsv Script interpreter, the "not.to.be.rejected" / "to.be.rejected" of the
 *    scrypt call) cannot be reproduced: the C port has no script interpreter and
 *    deliberately models unlock() as the verifySig predicate (tests 2/3/6).
 * ------------------------------------------------------------------------- */
static void test_scrypt_vm_methodcall_ignored(void)
{
    TEST_IGNORE_MESSAGE(
        "methods.unlock VM execution not reproducible (no script interpreter "
        "in C port); unlock's sole assertion verifySig is covered by tests 2/3/6");
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_golden_pubkey_n_is_byte_exact);
    RUN_TEST(test_golden_sign_is_byte_exact);
    RUN_TEST(test_accepts_a_valid_rabin_signature);
    RUN_TEST(test_rejects_a_tampered_message);
    RUN_TEST(test_rejects_signature_from_wrong_key);
    RUN_TEST(test_locking_script_reconstructs_deterministically);
    RUN_TEST(test_unlock_verify_predicate_matches_unlock_semantics);
    RUN_TEST(test_scrypt_vm_methodcall_ignored);
    return UNITY_END();
}
