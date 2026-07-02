/*
 * contracts_next/publisher_tea.c — PublisherTea (ARP-1 publisher identity,
 * Pillar A) port.
 *
 * TS origin: src/contracts-next/publisherTea.ts.
 *
 * This module owns:
 *   1. params/state lifecycle + genesis state,
 *   2. stateful locking-script reconstruction (7 ctor @props + the FixedArray
 *      attestorPubKeys[3], plus the 4-field mutable state suffix),
 *   3. the four per-method receipt preimage builders (each a DIFFERENT domain
 *      tag length + field set), and
 *   4. the off-chain model of activateRelease()'s K-of-3 quorum check.
 *
 * Compiled artifact ctor param order/types:
 *   publisherKey :: PubKey, approverKey :: PubKey, cancelKey :: PubKey,
 *   publisherHash :: Sha256, delaySeconds :: int, attestorPubKeys :: int[3],
 *   quorum :: int.
 * stateProps: pendingBundleHash :: Sha256, pendingFileSetRoot :: Sha256,
 *   pendingAnnounceTime :: int, releaseCount :: int.
 *
 * DETERMINISM PINS (header notes):
 *  (1) ACTIVATE commits releaseCount at PRE-increment (the current state value).
 *  (2) CANCEL commits pendingBundleHash BEFORE clearing (current state value).
 *  (3) the 4 domain tags have DIFFERENT byte lengths (16/15/14/18).
 *  (4) int2ByteString(now,4) is a SIGNED 4-byte CScriptNum (num2bin two-arg).
 *  (5) receipts are single sha256 — this module returns the PREIMAGE; the caller
 *      single-sha256's it (mirrors the TS sha256(...) wrapping the preimage).
 *  (7) quorum messages are ArpAttest.attestationMsg(attSeqs[i], activateDigest).
 */
#include "contracts_next/publisher_tea.h"
#include "scrypt/script_codec.h"
#include "bsv/num2bin.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- the 4 receipt domain tags as raw preimage bytes -------------------- */
/* 'ARP1_ANNOUNCE_V1' (16B). */
static const uint8_t ANNOUNCE_TAG[16] = {
    0x41, 0x52, 0x50, 0x31, 0x5f, 0x41, 0x4e, 0x4e,
    0x4f, 0x55, 0x4e, 0x43, 0x45, 0x5f, 0x56, 0x31,
};
/* 'ARP1_ACTRCPT_V1' (15B). */
static const uint8_t ACTRCPT_TAG[15] = {
    0x41, 0x52, 0x50, 0x31, 0x5f, 0x41, 0x43, 0x54,
    0x52, 0x43, 0x50, 0x54, 0x5f, 0x56, 0x31,
};
/* 'ARP1_CANCEL_V1' (14B). */
static const uint8_t CANCEL_TAG[14] = {
    0x41, 0x52, 0x50, 0x31, 0x5f, 0x43, 0x41, 0x4e,
    0x43, 0x45, 0x4c, 0x5f, 0x56, 0x31,
};
/* 'ARP1_INVALIDATE_V1' (18B). */
static const uint8_t INVALIDATE_TAG[18] = {
    0x41, 0x52, 0x50, 0x31, 0x5f, 0x49, 0x4e, 0x56,
    0x41, 0x4c, 0x49, 0x44, 0x41, 0x54, 0x45, 0x5f,
    0x56, 0x31,
};

/* The 32-zero-byte ZERO sentinel (PublisherTea.ZERO raw bytes). */
static const uint8_t ZERO32[32] = { 0 };

/* ---- helpers ------------------------------------------------------------ */

/* Make a fresh bn_t from a signed 64-bit value via its decimal string, matching
 * how the TS treats bigints (so int2bytestring_sized sees the right magnitude
 * and sign). */
static int bn_from_i64(int64_t v, bn_t **out)
{
    char dec[32];
    snprintf(dec, sizeof(dec), "%lld", (long long)v);
    return bn_parse_dec(dec, out);
}

/* Append int2ByteString(now, 4) — signed 4-byte CScriptNum (num2bin two-arg). */
static int append_now4(int64_t now, byte_buf_t *out)
{
    bn_t *bn = NULL;
    int rc = bn_from_i64(now, &bn);
    if (rc != BNS_OK)
        return rc;
    rc = int2bytestring_sized(bn, 4, out);
    bn_free(bn);
    return rc;
}

/* ---- lifecycle ---------------------------------------------------------- */

void publisher_tea_params_free(publisher_tea_params_t *p)
{
    if (p == NULL)
        return;
    byte_buf_free(&p->publisher_key);
    byte_buf_free(&p->approver_key);
    byte_buf_free(&p->cancel_key);
    byte_buf_free(&p->publisher_hash);
    bn_free(p->delay_seconds);
    p->delay_seconds = NULL;
    for (size_t i = 0; i < BONSAI_PUBLISHER_TEA_ATTESTORS; i++) {
        bn_free(p->attestor_pubkeys[i]);
        p->attestor_pubkeys[i] = NULL;
    }
    bn_free(p->quorum);
    p->quorum = NULL;
}

void publisher_tea_state_free(publisher_tea_state_t *s)
{
    if (s == NULL)
        return;
    byte_buf_free(&s->pending_bundle_hash);
    byte_buf_free(&s->pending_file_set_root);
    bn_free(s->pending_announce_time);
    bn_free(s->release_count);
    s->pending_announce_time = NULL;
    s->release_count = NULL;
}

void publisher_tea_free(publisher_tea_t *c)
{
    if (c == NULL)
        return;
    publisher_tea_params_free(&c->params);
    publisher_tea_state_free(&c->state);
    c->artifact = NULL;
}

int publisher_tea_genesis_state(publisher_tea_state_t *out)
{
    if (out == NULL)
        return BNS_EINVAL;

    memset(out, 0, sizeof(*out));
    byte_buf_init(&out->pending_bundle_hash);
    byte_buf_init(&out->pending_file_set_root);

    int rc = byte_buf_append(&out->pending_bundle_hash, ZERO32, 32);
    if (rc != BNS_OK)
        goto fail;
    rc = byte_buf_append(&out->pending_file_set_root, ZERO32, 32);
    if (rc != BNS_OK)
        goto fail;
    rc = bn_from_i64(0, &out->pending_announce_time);
    if (rc != BNS_OK)
        goto fail;
    rc = bn_from_i64(0, &out->release_count);
    if (rc != BNS_OK)
        goto fail;
    return BNS_OK;

fail:
    publisher_tea_state_free(out);
    return rc;
}

/* ---- locking-script reconstruction -------------------------------------- */

int publisher_tea_locking_script(const publisher_tea_t *c, bool is_genesis,
                                 byte_buf_t *out)
{
    if (c == NULL || c->artifact == NULL || out == NULL)
        return BNS_EINVAL;
    const publisher_tea_params_t *p = &c->params;
    const publisher_tea_state_t  *s = &c->state;
    if (p->delay_seconds == NULL || p->quorum == NULL ||
        s->pending_announce_time == NULL || s->release_count == NULL)
        return BNS_EINVAL;
    for (size_t i = 0; i < BONSAI_PUBLISHER_TEA_ATTESTORS; i++)
        if (p->attestor_pubkeys[i] == NULL)
            return BNS_EINVAL;

    /* 7 ctor values in @prop declaration order:
     *   0 publisherKey  :: PubKey
     *   1 approverKey    :: PubKey
     *   2 cancelKey      :: PubKey
     *   3 publisherHash  :: Sha256
     *   4 delaySeconds   :: int
     *   5 attestorPubKeys:: int[3]  (FixedArray of 3 INTs)
     *   6 quorum         :: int
     */
    scrypt_arg_t ctor[7];
    memset(ctor, 0, sizeof(ctor));
    /* 4 state values in stateProps order:
     *   0 pendingBundleHash   :: Sha256
     *   1 pendingFileSetRoot   :: Sha256
     *   2 pendingAnnounceTime  :: int
     *   3 releaseCount         :: int
     */
    scrypt_arg_t state[4];
    memset(state, 0, sizeof(state));
    int rc = BNS_OK;

    /* PubKey ctor args (raw payload via bytes_val). */
    const byte_buf_t *pubkeys[3] = { &p->publisher_key, &p->approver_key,
                                     &p->cancel_key };
    for (size_t i = 0; i < 3; i++) {
        ctor[i].tag = SCRYPT_TYPE_PUBKEY;
        byte_buf_init(&ctor[i].as.bytes_val);
        rc = byte_buf_append(&ctor[i].as.bytes_val, pubkeys[i]->data,
                             pubkeys[i]->len);
        if (rc != BNS_OK)
            goto done;
    }

    /* 3. publisherHash :: Sha256. */
    ctor[3].tag = SCRYPT_TYPE_SHA256;
    byte_buf_init(&ctor[3].as.bytes_val);
    rc = byte_buf_append(&ctor[3].as.bytes_val, p->publisher_hash.data,
                         p->publisher_hash.len);
    if (rc != BNS_OK)
        goto done;

    /* 4. delaySeconds :: int. */
    ctor[4].tag = SCRYPT_TYPE_INT;
    rc = bn_dup(p->delay_seconds, &ctor[4].as.int_val);
    if (rc != BNS_OK)
        goto done;

    /* 5. attestorPubKeys :: int[3] — FixedArray of 3 INT leaves. */
    ctor[5].tag = SCRYPT_TYPE_FIXED_ARRAY;
    ctor[5].as.array.count = BONSAI_PUBLISHER_TEA_ATTESTORS;
    ctor[5].as.array.elems =
        calloc(BONSAI_PUBLISHER_TEA_ATTESTORS, sizeof(scrypt_arg_t));
    if (ctor[5].as.array.elems == NULL) {
        rc = BNS_ENOMEM;
        goto done;
    }
    for (size_t i = 0; i < BONSAI_PUBLISHER_TEA_ATTESTORS; i++) {
        ctor[5].as.array.elems[i].tag = SCRYPT_TYPE_INT;
        rc = bn_dup(p->attestor_pubkeys[i],
                    &ctor[5].as.array.elems[i].as.int_val);
        if (rc != BNS_OK)
            goto done;
    }

    /* 6. quorum :: int. */
    ctor[6].tag = SCRYPT_TYPE_INT;
    rc = bn_dup(p->quorum, &ctor[6].as.int_val);
    if (rc != BNS_OK)
        goto done;

    /* state[0] pendingBundleHash :: Sha256. */
    state[0].tag = SCRYPT_TYPE_SHA256;
    byte_buf_init(&state[0].as.bytes_val);
    rc = byte_buf_append(&state[0].as.bytes_val, s->pending_bundle_hash.data,
                         s->pending_bundle_hash.len);
    if (rc != BNS_OK)
        goto done;

    /* state[1] pendingFileSetRoot :: Sha256. */
    state[1].tag = SCRYPT_TYPE_SHA256;
    byte_buf_init(&state[1].as.bytes_val);
    rc = byte_buf_append(&state[1].as.bytes_val, s->pending_file_set_root.data,
                         s->pending_file_set_root.len);
    if (rc != BNS_OK)
        goto done;

    /* state[2] pendingAnnounceTime :: int. */
    state[2].tag = SCRYPT_TYPE_INT;
    rc = bn_dup(s->pending_announce_time, &state[2].as.int_val);
    if (rc != BNS_OK)
        goto done;

    /* state[3] releaseCount :: int. */
    state[3].tag = SCRYPT_TYPE_INT;
    rc = bn_dup(s->release_count, &state[3].as.int_val);
    if (rc != BNS_OK)
        goto done;

    rc = reconstruct_locking_script(c->artifact, ctor, 7, state, 4,
                                    is_genesis, out);

done:
    for (size_t i = 0; i < 7; i++)
        scrypt_arg_free(&ctor[i]);
    for (size_t i = 0; i < 4; i++)
        scrypt_arg_free(&state[i]);
    return rc;
}

/* ---- per-method receipt preimage builders ------------------------------- */

int publisher_tea_announce_receipt(const publisher_tea_t *c,
                                   const uint8_t bundle_hash[32],
                                   const uint8_t file_set_root[32],
                                   int64_t now, byte_buf_t *out)
{
    if (c == NULL || bundle_hash == NULL || file_set_root == NULL ||
        out == NULL)
        return BNS_EINVAL;
    if (c->params.publisher_hash.data == NULL ||
        c->state.release_count == NULL)
        return BNS_EINVAL;

    /* tag(16) || publisherHash(32) || bundleHash(32) || fileSetRoot(32)
     *   || int2ByteString(releaseCount,8) || int2ByteString(now,4) */
    int rc = byte_buf_append(out, ANNOUNCE_TAG, sizeof(ANNOUNCE_TAG));
    if (rc != BNS_OK)
        return rc;
    rc = byte_buf_append(out, c->params.publisher_hash.data,
                         c->params.publisher_hash.len);
    if (rc != BNS_OK)
        return rc;
    rc = byte_buf_append(out, bundle_hash, 32);
    if (rc != BNS_OK)
        return rc;
    rc = byte_buf_append(out, file_set_root, 32);
    if (rc != BNS_OK)
        return rc;
    rc = int2bytestring_sized(c->state.release_count, 8, out);
    if (rc != BNS_OK)
        return rc;
    return append_now4(now, out);
}

int publisher_tea_activate_receipt(const publisher_tea_t *c,
                                   const uint8_t activate_digest[32],
                                   byte_buf_t *out)
{
    if (c == NULL || activate_digest == NULL || out == NULL)
        return BNS_EINVAL;
    if (c->params.publisher_hash.data == NULL ||
        c->state.release_count == NULL || c->state.pending_announce_time == NULL)
        return BNS_EINVAL;

    /* TS activate receipt:
     *   sha256( tag(15) || publisherHash(32) || activateDigest(32)
     *           || int2ByteString(releaseCount,8) [PRE-increment]
     *           || int2ByteString(now,4) ),  now = this.ctx.locktime.
     *
     * The frozen prototype has no `now` parameter, so `now` (the spend's
     * ctx.locktime) is staged by the caller into state.pendingAnnounceTime
     * before invoking this builder — the only locktime-typed state field. This
     * mirrors arpTea.test.ts, which sets pendingAnnounceTime per spend. See the
     * deviation note in the module's return summary. releaseCount is the current
     * (pre-increment) state value, matching pin (1). */
    int rc = byte_buf_append(out, ACTRCPT_TAG, sizeof(ACTRCPT_TAG));
    if (rc != BNS_OK)
        return rc;
    rc = byte_buf_append(out, c->params.publisher_hash.data,
                         c->params.publisher_hash.len);
    if (rc != BNS_OK)
        return rc;
    rc = byte_buf_append(out, activate_digest, 32);
    if (rc != BNS_OK)
        return rc;
    rc = int2bytestring_sized(c->state.release_count, 8, out);
    if (rc != BNS_OK)
        return rc;
    /* `now` = ctx.locktime; with the frozen signature, the activation locktime
     * is carried in the state's pendingAnnounceTime field (set to the activate
     * tx locktime by the caller before invoking this builder). */
    return int2bytestring_sized(c->state.pending_announce_time, 4, out);
}

int publisher_tea_cancel_receipt(const publisher_tea_t *c, byte_buf_t *out)
{
    if (c == NULL || out == NULL)
        return BNS_EINVAL;
    if (c->params.publisher_hash.data == NULL ||
        c->state.pending_bundle_hash.data == NULL ||
        c->state.pending_announce_time == NULL)
        return BNS_EINVAL;

    /* tag(14) || publisherHash(32) || pendingBundleHash(32) (BEFORE clear)
     *   || int2ByteString(now,4) */
    int rc = byte_buf_append(out, CANCEL_TAG, sizeof(CANCEL_TAG));
    if (rc != BNS_OK)
        return rc;
    rc = byte_buf_append(out, c->params.publisher_hash.data,
                         c->params.publisher_hash.len);
    if (rc != BNS_OK)
        return rc;
    rc = byte_buf_append(out, c->state.pending_bundle_hash.data,
                         c->state.pending_bundle_hash.len);
    if (rc != BNS_OK)
        return rc;
    /* `now` = ctx.locktime, carried in pendingAnnounceTime by the caller. */
    return int2bytestring_sized(c->state.pending_announce_time, 4, out);
}

int publisher_tea_invalidate_receipt(const publisher_tea_t *c,
                                     const uint8_t activate_digest[32],
                                     byte_buf_t *out)
{
    if (c == NULL || activate_digest == NULL || out == NULL)
        return BNS_EINVAL;
    if (c->params.publisher_hash.data == NULL ||
        c->state.pending_announce_time == NULL)
        return BNS_EINVAL;

    /* tag(18) || publisherHash(32) || activateDigest(32) || int2ByteString(now,4) */
    int rc = byte_buf_append(out, INVALIDATE_TAG, sizeof(INVALIDATE_TAG));
    if (rc != BNS_OK)
        return rc;
    rc = byte_buf_append(out, c->params.publisher_hash.data,
                         c->params.publisher_hash.len);
    if (rc != BNS_OK)
        return rc;
    rc = byte_buf_append(out, activate_digest, 32);
    if (rc != BNS_OK)
        return rc;
    /* `now` = ctx.locktime, carried in pendingAnnounceTime by the caller. */
    return int2bytestring_sized(c->state.pending_announce_time, 4, out);
}

/* ---- activate quorum check ---------------------------------------------- */

int publisher_tea_check_quorum(const publisher_tea_t *c,
                               const uint8_t activate_digest[32],
                               const bn_t *att_seqs[BONSAI_PUBLISHER_TEA_ATTESTORS],
                               const rabin_verifier_sig_t *att_sigs[BONSAI_PUBLISHER_TEA_ATTESTORS],
                               const bool att_used[BONSAI_PUBLISHER_TEA_ATTESTORS],
                               bool *out_ok)
{
    if (c == NULL || activate_digest == NULL || att_seqs == NULL ||
        att_sigs == NULL || att_used == NULL || out_ok == NULL)
        return BNS_EINVAL;
    if (c->params.quorum == NULL)
        return BNS_EINVAL;
    for (size_t i = 0; i < BONSAI_PUBLISHER_TEA_ATTESTORS; i++)
        if (c->params.attestor_pubkeys[i] == NULL)
            return BNS_EINVAL;

    *out_ok = false;

    /* For each used attestor, verify att_sigs[i] under attestorPubKeys[i] over
     * ArpAttest.attestationMsg(attSeqs[i], activateDigest). The TS asserts EACH
     * used signature is valid (an invalid used sig fails the whole method), so
     * any invalid used signature => fail-closed (*out_ok stays false). */
    bn_t *valid = NULL;
    int rc = bn_from_i64(0, &valid);
    if (rc != BNS_OK)
        return rc;
    int64_t valid_count = 0;

    for (size_t i = 0; i < BONSAI_PUBLISHER_TEA_ATTESTORS; i++) {
        if (!att_used[i])
            continue;
        if (att_seqs[i] == NULL || att_sigs[i] == NULL) {
            rc = BNS_EINVAL;
            goto done;
        }
        byte_buf_t msg;
        byte_buf_init(&msg);
        rc = arp_attestation_msg(att_seqs[i], activate_digest, &msg);
        if (rc != BNS_OK) {
            byte_buf_free(&msg);
            goto done;
        }
        bool ok = rabin_verifier_verify_sig(msg.data, msg.len, att_sigs[i],
                                            c->params.attestor_pubkeys[i]);
        byte_buf_free(&msg);
        if (!ok) {
            /* TS asserts the used signature is valid => an invalid used sig is a
             * hard failure of activate, not merely "not counted". */
            rc = BNS_OK;
            *out_ok = false;
            goto done;
        }
        valid_count++;
    }

    /* *out_ok = (validCount >= quorum). Build validCount as bn_t for an exact
     * bigint compare against quorum (quorum may exceed int range conceptually). */
    bn_free(valid);
    valid = NULL;
    rc = bn_from_i64(valid_count, &valid);
    if (rc != BNS_OK)
        return rc;
    *out_ok = (bn_cmp(valid, c->params.quorum) >= 0);

done:
    bn_free(valid);
    return rc;
}
