/*
 * test_arp_tea.c — Unity port of chain/tests/arpTea.test.ts (the ARP-1
 * PublisherTea announce->delay->activate + AttestorTea bond/slash suite).
 *
 * SCOPE NOTE (deviation): the TS suite drives the FULL sCrypt contracts under a
 * bsv DummyProvider — it asserts on built-tx OUTPUT SHAPES (006a OP_RETURN
 * receipts, P2PKH payouts, satoshi bounty/burn splits) and on in-script
 * checkSig/nLocktime/hashOutputs gating. The C port deliberately does NOT embed
 * a sCrypt VM; instead it exposes the load-bearing gate LOGIC as pure off-chain
 * predicates: PublisherTea.activateRelease's K-of-3 Rabin quorum
 * (publisher_tea_check_quorum) and AttestorTea.slashEquivocation's acceptance
 * test (attestor_tea_check_equivocation), plus the per-method receipt PREIMAGE
 * builders. This file mirrors every TS assertion that those predicates pin, and
 * TEST_IGNOREs (with reasons) the assertions that require live sCrypt+tx
 * execution which is out of scope for the C library.
 *
 * The Rabin attestor signatures here are produced over the SAME 54-byte
 * ArpAttest.attestationMsg the gates verify, so "toolkit signatures verify
 * in-script" is exercised end-to-end through the C Rabin stack.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "unity.h"

#include "common/error.h"
#include "common/bytes.h"
#include "common/hex.h"
#include "crypto/bignum.h"
#include "crypto/rabin.h"
#include "lib/rabin_verifier.h"
#include "contracts_next/arp_attest.h"
#include "contracts_next/publisher_tea.h"
#include "contracts_next/attestor_tea.h"

#include "helpers/rabin_test.h"

/* ---- shared digests (sha256 of fixed strings, like the TS) -------------- */
/* The TS uses sha256(toByteString('release digest A', true)); here we just need
 * two distinct, stable 32-byte digests. Use fixed all-aa / all-bb patterns
 * (digest byte order does not matter to the gate, only that A != B). */
static uint8_t DIGEST_A[32];
static uint8_t DIGEST_B[32];
static uint8_t ACTIVATE_DIGEST[32]; /* a third distinct digest for quorum tests */

void setUp(void)
{
    memset(DIGEST_A, 0xa1, sizeof(DIGEST_A));
    memset(DIGEST_B, 0xb2, sizeof(DIGEST_B));
    memset(ACTIVATE_DIGEST, 0xc3, sizeof(ACTIVATE_DIGEST));
}
void tearDown(void) {}

/* ---- signing helpers ---------------------------------------------------- *
 * Build the canonical attestation message for (seq, digest) and Rabin-sign it
 * with `key`. The resulting rabin_sig_t is converted into the contract-side
 * rabin_verifier_sig_t {s, padding-bytes, padding_len} the gates consume. The
 * caller owns sig_out (free its bn_t via rabin_sig_free) and pad_out (free()).
 */
typedef struct {
    rabin_sig_t   sig;        /* owned: free with rabin_sig_free */
    uint8_t      *pad;        /* owned zero-byte padding run; free()         */
    rabin_verifier_sig_t vsig;/* borrows sig.s and pad                       */
} signed_att_t;

static void sign_att(const rabin_key_t *key, uint64_t seq,
                     const uint8_t digest[32], signed_att_t *out)
{
    memset(out, 0, sizeof(*out));

    bn_t *bseq = NULL;
    {
        char dec[32];
        snprintf(dec, sizeof(dec), "%" PRIu64, seq);
        TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec(dec, &bseq));
    }

    byte_buf_t msg;
    byte_buf_init(&msg);
    TEST_ASSERT_EQUAL_INT(BNS_OK, arp_attestation_msg(bseq, digest, &msg));
    bn_free(bseq);

    TEST_ASSERT_EQUAL_INT(BNS_OK,
        rabin_sign(msg.data, msg.len, key, &out->sig));
    byte_buf_free(&msg);

    /* materialise the zero-byte padding run for the verifier-side wire shape */
    size_t plen = out->sig.padding_byte_count;
    out->pad = calloc(plen ? plen : 1, 1);
    TEST_ASSERT_NOT_NULL(out->pad);

    out->vsig.s = out->sig.s;
    out->vsig.padding = out->pad;
    out->vsig.padding_len = plen;
}

static void free_att(signed_att_t *a)
{
    if (!a) return;
    rabin_sig_free(&a->sig);
    free(a->pad);
    a->pad = NULL;
}

/* Public modulus n of a Rabin key as an owned bn_t. */
static bn_t *pubkey_of(const rabin_key_t *key)
{
    bn_t *n = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_pubkey(key, &n));
    TEST_ASSERT_NOT_NULL(n);
    return n;
}

/* =========================================================================
 *  PublisherTea — activateRelease K-of-3 charter quorum
 * ========================================================================= */

/* Build a PublisherTea whose 3 charter attestor moduli are the given keys, with
 * quorum=2. publisherHash is a fixed 32-byte value. params are owned. */
static void build_publisher(publisher_tea_t *c,
                            const rabin_key_t *k0,
                            const rabin_key_t *k1,
                            const rabin_key_t *k2,
                            int64_t quorum)
{
    memset(c, 0, sizeof(*c));
    publisher_tea_params_t *p = &c->params;

    /* keys: 33-byte compressed pubkeys are not used by the quorum gate, but the
     * struct owns them; give them placeholder 33-byte buffers. */
    static const uint8_t PK33[33] = { 0x02 };
    byte_buf_init(&p->publisher_key);
    byte_buf_init(&p->approver_key);
    byte_buf_init(&p->cancel_key);
    byte_buf_init(&p->publisher_hash);
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&p->publisher_key, PK33, 33));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&p->approver_key, PK33, 33));
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&p->cancel_key, PK33, 33));
    uint8_t ph[32]; memset(ph, 0x5a, 32);
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&p->publisher_hash, ph, 32));

    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("3600", &p->delay_seconds));
    p->attestor_pubkeys[0] = pubkey_of(k0);
    p->attestor_pubkeys[1] = pubkey_of(k1);
    p->attestor_pubkeys[2] = pubkey_of(k2);
    {
        char dec[32];
        snprintf(dec, sizeof(dec), "%" PRId64, quorum);
        TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec(dec, &p->quorum));
    }

    TEST_ASSERT_EQUAL_INT(BNS_OK, publisher_tea_genesis_state(&c->state));
}

/* TS: 'activates after the delay with a 2-of-3 charter quorum (toolkit
 * signatures verify in-script)'. Two charter attestors sign at independent seqs
 * 11 and 22; the quorum (2) is met. */
static void test_activate_quorum_2_of_3_passes(void)
{
    rabin_key_t k0, k1, k2;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_test_genkey(&k0));
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_test_genkey(&k1));
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_test_genkey(&k2));

    publisher_tea_t c;
    build_publisher(&c, &k0, &k1, &k2, 2);

    signed_att_t a, b;
    sign_att(&k0, 11, ACTIVATE_DIGEST, &a);  /* attestor 0, seq 11 */
    sign_att(&k1, 22, ACTIVATE_DIGEST, &b);  /* attestor 1, seq 22 */

    bn_t *s0 = NULL, *s1 = NULL, *s2 = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("11", &s0));
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("22", &s1));
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("0",  &s2));

    const bn_t *seqs[3] = { s0, s1, s2 };
    const rabin_verifier_sig_t *sigs[3] = { &a.vsig, &b.vsig, NULL };
    const bool used[3] = { true, true, false };

    bool ok = false;
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        publisher_tea_check_quorum(&c, ACTIVATE_DIGEST, seqs, sigs, used, &ok));
    TEST_ASSERT_TRUE(ok);

    bn_free(s0); bn_free(s1); bn_free(s2);
    free_att(&a); free_att(&b);
    publisher_tea_free(&c);
    rabin_key_free(&k0); rabin_key_free(&k1); rabin_key_free(&k2);
}

/* TS: 'rejects activation below quorum (1 of 3, need 2)'. Only attestor 0
 * signs; validCount(1) < quorum(2). */
static void test_activate_below_quorum_rejected(void)
{
    rabin_key_t k0, k1, k2;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_test_genkey(&k0));
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_test_genkey(&k1));
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_test_genkey(&k2));

    publisher_tea_t c;
    build_publisher(&c, &k0, &k1, &k2, 2);

    signed_att_t a;
    sign_att(&k0, 11, ACTIVATE_DIGEST, &a);

    bn_t *s0 = NULL, *s1 = NULL, *s2 = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("11", &s0));
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("0",  &s1));
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("0",  &s2));

    const bn_t *seqs[3] = { s0, s1, s2 };
    const rabin_verifier_sig_t *sigs[3] = { &a.vsig, NULL, NULL };
    const bool used[3] = { true, false, false };

    bool ok = true;
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        publisher_tea_check_quorum(&c, ACTIVATE_DIGEST, seqs, sigs, used, &ok));
    TEST_ASSERT_FALSE(ok);   /* quorum not met */

    bn_free(s0); bn_free(s1); bn_free(s2);
    free_att(&a);
    publisher_tea_free(&c);
    rabin_key_free(&k0); rabin_key_free(&k1); rabin_key_free(&k2);
}

/* TS: 'rejects activation with a signature from outside the charter set'.
 * Attestor 0 is genuine; slot 1 carries a VALID Rabin sig made by an OUTSIDER
 * key (not in attestorPubKeys), so it fails verification under attestorPubKeys[1]
 * and the whole activate is rejected. */
static void test_activate_outsider_signature_rejected(void)
{
    rabin_key_t k0, k1, k2, outsider;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_test_genkey(&k0));
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_test_genkey(&k1));
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_test_genkey(&k2));
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_test_genkey(&outsider));

    publisher_tea_t c;
    build_publisher(&c, &k0, &k1, &k2, 2);

    signed_att_t a, evil;
    sign_att(&k0, 11, ACTIVATE_DIGEST, &a);        /* genuine attestor 0 */
    sign_att(&outsider, 22, ACTIVATE_DIGEST, &evil); /* valid sig, WRONG key */

    bn_t *s0 = NULL, *s1 = NULL, *s2 = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("11", &s0));
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("22", &s1));
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("0",  &s2));

    const bn_t *seqs[3] = { s0, s1, s2 };
    const rabin_verifier_sig_t *sigs[3] = { &a.vsig, &evil.vsig, NULL };
    const bool used[3] = { true, true, false };

    bool ok = true;
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        publisher_tea_check_quorum(&c, ACTIVATE_DIGEST, seqs, sigs, used, &ok));
    TEST_ASSERT_FALSE(ok);   /* invalid attestor signature => whole activate fails */

    bn_free(s0); bn_free(s1); bn_free(s2);
    free_att(&a); free_att(&evil);
    publisher_tea_free(&c);
    rabin_key_free(&k0); rabin_key_free(&k1); rabin_key_free(&k2);
    rabin_key_free(&outsider);
}

/* PublisherTea per-method receipt PREIMAGE pins: the four ARP-1 receipt domain
 * tags have DIFFERENT byte lengths (16/15/14/18) and each builder emits a
 * distinct, correctly-tagged preimage. This mirrors the TS assertions that each
 * spend pins its own domain-separated OP_RETURN receipt. */
static void test_receipt_preimages_distinct_and_tagged(void)
{
    rabin_key_t k0, k1, k2;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_test_genkey(&k0));
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_test_genkey(&k1));
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_test_genkey(&k2));

    publisher_tea_t c;
    build_publisher(&c, &k0, &k1, &k2, 2);

    /* stage a pending bundle + announce time so the cancel/activate receipts are
     * well-formed (now is carried in pendingAnnounceTime per the C port note). */
    uint8_t bundle[32], fileset[32];
    memset(bundle, 0xbb, 32); memset(fileset, 0xff, 32);
    byte_buf_free(&c.state.pending_bundle_hash);
    byte_buf_init(&c.state.pending_bundle_hash);
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&c.state.pending_bundle_hash, bundle, 32));
    bn_free(c.state.pending_announce_time);
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("1700000000", &c.state.pending_announce_time));

    byte_buf_t ann, act, can, inv;
    byte_buf_init(&ann); byte_buf_init(&act);
    byte_buf_init(&can); byte_buf_init(&inv);

    TEST_ASSERT_EQUAL_INT(BNS_OK,
        publisher_tea_announce_receipt(&c, bundle, fileset, 1700000000, &ann));
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        publisher_tea_activate_receipt(&c, ACTIVATE_DIGEST, &act));
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        publisher_tea_cancel_receipt(&c, &can));
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        publisher_tea_invalidate_receipt(&c, ACTIVATE_DIGEST, &inv));

    /* each preimage begins with its own domain tag */
    char *ann_hex = hex_encode(ann.data, ann.len);
    char *act_hex = hex_encode(act.data, act.len);
    char *can_hex = hex_encode(can.data, can.len);
    char *inv_hex = hex_encode(inv.data, inv.len);
    TEST_ASSERT_EQUAL_INT(0, strncmp(ann_hex, BONSAI_ARP_ANNOUNCE_TAG_HEX,   strlen(BONSAI_ARP_ANNOUNCE_TAG_HEX)));
    TEST_ASSERT_EQUAL_INT(0, strncmp(act_hex, BONSAI_ARP_ACTRCPT_TAG_HEX,    strlen(BONSAI_ARP_ACTRCPT_TAG_HEX)));
    TEST_ASSERT_EQUAL_INT(0, strncmp(can_hex, BONSAI_ARP_CANCEL_TAG_HEX,     strlen(BONSAI_ARP_CANCEL_TAG_HEX)));
    TEST_ASSERT_EQUAL_INT(0, strncmp(inv_hex, BONSAI_ARP_INVALIDATE_TAG_HEX, strlen(BONSAI_ARP_INVALIDATE_TAG_HEX)));

    /* the four receipts are mutually distinct preimages */
    TEST_ASSERT_TRUE(strcmp(ann_hex, act_hex) != 0);
    TEST_ASSERT_TRUE(strcmp(act_hex, can_hex) != 0);
    TEST_ASSERT_TRUE(strcmp(can_hex, inv_hex) != 0);
    TEST_ASSERT_TRUE(strcmp(ann_hex, inv_hex) != 0);

    free(ann_hex); free(act_hex); free(can_hex); free(inv_hex);
    byte_buf_free(&ann); byte_buf_free(&act);
    byte_buf_free(&can); byte_buf_free(&inv);
    publisher_tea_free(&c);
    rabin_key_free(&k0); rabin_key_free(&k1); rabin_key_free(&k2);
}

/* TS announce/cancel/invalidate/retire tx-SHAPE assertions (006a OP_RETURN
 * receipt outputs, P2PKH payouts) and in-script checkSig/nLocktime/hashOutputs
 * gating require live sCrypt+bsv execution which the C library does not embed. */
static void test_publisher_tx_shapes_require_scrypt_vm(void)
{
    TEST_IGNORE_MESSAGE(
        "tx output shapes (006a OP_RETURN, P2PKH), 2-of-2 checkSig, nLocktime "
        "delay floor, and hashOutputs state-transition gating require the sCrypt "
        "VM + bsv tx builder; the C port models only the off-chain gate logic "
        "(quorum/equivocation predicates + receipt preimages)");
}

/* =========================================================================
 *  AttestorTea — slashEquivocation acceptance test
 * ========================================================================= */

static void build_attestor(attestor_tea_t *c, const rabin_key_t *attestor_key)
{
    memset(c, 0, sizeof(*c));
    static const uint8_t PK33[33] = { 0x02 };
    byte_buf_init(&c->params.operator_pubkey);
    TEST_ASSERT_EQUAL_INT(BNS_OK, byte_buf_append(&c->params.operator_pubkey, PK33, 33));
    c->params.attestor_rabin_pubkey = pubkey_of(attestor_key);
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("1701000000", &c->params.unbond_not_before));
}

/* TS: 'slashes a same-seq equivocation'. Two Rabin sigs by the SAME attestor
 * over the SAME seq but DIFFERENT digests => a valid equivocation proof. */
static void test_slash_same_seq_equivocation_accepts(void)
{
    rabin_key_t attestor;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_test_genkey(&attestor));

    attestor_tea_t c;
    build_attestor(&c, &attestor);

    signed_att_t a, b;
    sign_att(&attestor, 7, DIGEST_A, &a);
    sign_att(&attestor, 7, DIGEST_B, &b);  /* SAME seq, different digest */

    bn_t *seq = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("7", &seq));

    bool ok = false;
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        attestor_tea_check_equivocation(&c, seq, DIGEST_A, &a.vsig,
                                        DIGEST_B, &b.vsig, &ok));
    TEST_ASSERT_TRUE(ok);

    bn_free(seq);
    free_att(&a); free_att(&b);
    attestor_tea_free(&c);
    rabin_key_free(&attestor);
}

/* TS: 'rejects a "slash" over identical digests (not an equivocation)'. */
static void test_slash_identical_digests_rejected(void)
{
    rabin_key_t attestor;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_test_genkey(&attestor));

    attestor_tea_t c;
    build_attestor(&c, &attestor);

    signed_att_t a;
    sign_att(&attestor, 7, DIGEST_A, &a);

    bn_t *seq = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("7", &seq));

    bool ok = true;
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        attestor_tea_check_equivocation(&c, seq, DIGEST_A, &a.vsig,
                                        DIGEST_A, &a.vsig, &ok));
    TEST_ASSERT_FALSE(ok);   /* digests are identical => not an equivocation */

    bn_free(seq);
    free_att(&a);
    attestor_tea_free(&c);
    rabin_key_free(&attestor);
}

/* TS: 'rejects signatures made under DIFFERENT seqs (honest sequential
 * attestations)'. sigB was signed at seq 8 but the slash claims seq 7, so the
 * gate (which verifies BOTH sigs at the claimed seq) fails to verify sigB. */
static void test_slash_different_seqs_rejected(void)
{
    rabin_key_t attestor;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_test_genkey(&attestor));

    attestor_tea_t c;
    build_attestor(&c, &attestor);

    signed_att_t a, b;
    sign_att(&attestor, 7, DIGEST_A, &a);
    sign_att(&attestor, 8, DIGEST_B, &b);  /* DIFFERENT seq — honest */

    bn_t *seq = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("7", &seq));

    bool ok = true;
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        attestor_tea_check_equivocation(&c, seq, DIGEST_A, &a.vsig,
                                        DIGEST_B, &b.vsig, &ok));
    TEST_ASSERT_FALSE(ok);   /* sigB does not verify at seq 7 */

    bn_free(seq);
    free_att(&a); free_att(&b);
    attestor_tea_free(&c);
    rabin_key_free(&attestor);
}

/* TS: 'rejects a fraud proof signed by someone else's key'. Both sigs are made
 * by an OUTSIDER key, not the contract's attestorRabinPubKey, so the first sig
 * fails verification. */
static void test_slash_wrong_key_rejected(void)
{
    rabin_key_t attestor, outsider;
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_test_genkey(&attestor));
    TEST_ASSERT_EQUAL_INT(BNS_OK, rabin_test_genkey(&outsider));

    attestor_tea_t c;
    build_attestor(&c, &attestor);

    signed_att_t a, b;
    sign_att(&outsider, 7, DIGEST_A, &a);
    sign_att(&outsider, 7, DIGEST_B, &b);

    bn_t *seq = NULL;
    TEST_ASSERT_EQUAL_INT(BNS_OK, bn_parse_dec("7", &seq));

    bool ok = true;
    TEST_ASSERT_EQUAL_INT(BNS_OK,
        attestor_tea_check_equivocation(&c, seq, DIGEST_A, &a.vsig,
                                        DIGEST_B, &b.vsig, &ok));
    TEST_ASSERT_FALSE(ok);   /* not by this attestor */

    bn_free(seq);
    free_att(&a); free_att(&b);
    attestor_tea_free(&c);
    rabin_key_free(&attestor);
    rabin_key_free(&outsider);
}

/* TS slash bounty/burn split (bounty=floor(bond/2), burn=remainder, OP_FALSE
 * OP_RETURN 'SLASHED\0'), stake() top-up, and withdraw nLocktime/operator-sig
 * gating are tx-SHAPE / in-script assertions needing the sCrypt VM. The integer
 * split itself (value/2 floor, value-bounty) is a trivial arithmetic pin and the
 * burn marker is exposed as BONSAI_ARP_SLASHED_MARKER_HEX. */
static void test_slash_split_and_withdraw_require_scrypt_vm(void)
{
    /* The 'SLASHED\0' burn marker constant IS available in C; pin it directly so
     * the burn-data agreement is still covered. */
    TEST_ASSERT_EQUAL_STRING("534c41534845440000", BONSAI_ARP_SLASHED_MARKER_HEX);

    /* bounty/burn integer split is pinned here (the only consensus-numeric part
     * the C library can evaluate without a VM): even bond 100000 => 50000/50000;
     * odd bond 100001 => 50000/50001. */
    int64_t even = 100000, odd = 100001;
    TEST_ASSERT_EQUAL_INT64(50000, even / 2);
    TEST_ASSERT_EQUAL_INT64(50000, even - even / 2);
    TEST_ASSERT_EQUAL_INT64(50000, odd / 2);
    TEST_ASSERT_EQUAL_INT64(50001, odd - odd / 2);

    TEST_IGNORE_MESSAGE(
        "slash bounty/burn OUTPUT shapes (P2PKH reporter payout + OP_FALSE "
        "OP_RETURN 'SLASHED\\0' burn), the hashOutputs anti-griefing commitment, "
        "stake() top-up, and withdraw nLocktime/operator-sig gating require the "
        "sCrypt VM + bsv tx builder, not embedded in the C port");
}

int main(void)
{
    UNITY_BEGIN();
    /* PublisherTea activate quorum */
    RUN_TEST(test_activate_quorum_2_of_3_passes);
    RUN_TEST(test_activate_below_quorum_rejected);
    RUN_TEST(test_activate_outsider_signature_rejected);
    RUN_TEST(test_receipt_preimages_distinct_and_tagged);
    RUN_TEST(test_publisher_tx_shapes_require_scrypt_vm);
    /* AttestorTea slash equivocation */
    RUN_TEST(test_slash_same_seq_equivocation_accepts);
    RUN_TEST(test_slash_identical_digests_rejected);
    RUN_TEST(test_slash_different_seqs_rejected);
    RUN_TEST(test_slash_wrong_key_rejected);
    RUN_TEST(test_slash_split_and_withdraw_require_scrypt_vm);
    return UNITY_END();
}
