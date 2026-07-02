/*
 * contracts/ricardian_tea.c — RicardianTea legal-technical identity contract:
 * genesis state init, locking-script reconstruction (delegated to
 * scrypt/script_codec.h), and the byte-exact receipt / attestation preimage
 * builders.  Ported from src/contracts/ricardianTea.ts.
 *
 * DETERMINISM (see ricardian_tea.h header notes):
 *  - 13 ctor args in @prop declaration order; ctor ints use the opcode-optimized
 *    CONSTRUCTOR encoder (to_script_hex), wired through reconstruct_locking_script.
 *  - 5 state props use the no-opcode STATE encoder (build_state); locking-script
 *    state body captured with is_genesis selected by the caller (golden: FALSE).
 *  - receipt preimage: ricardianHash(32) || agent(33) || counterparty(33) ||
 *    int2ByteString(amount,8) || invoiceHash(32) || provenanceHash(32) ||
 *    int2ByteString(txCount,8) [PRE-increment] || int2ByteString(now,4 signed).
 *  - attestationMsg: tag(13) || ricardianHash(32) || agent(33) ||
 *    int2ByteString(validatorPubKey) [ONE-ARG minimal] ||
 *    int2ByteString(amount,8) || int2ByteString(attestedLimit,8) || receiptHash(32).
 *  - slash() is SUPERSEDED / DO-NOT-DEPLOY; not exposed (header omits it).
 */
#include "contracts/ricardian_tea.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/hex.h"
#include "crypto/hash.h"
#include "bsv/num2bin.h"
#include "scrypt/script_codec.h"

/* ---- small helpers ------------------------------------------------------- */

/* Build a SCRYPT_TYPE_INT value (owned bn_t) duplicated from src. */
static int arg_int_dup(scrypt_arg_t *out, const bn_t *src)
{
    memset(out, 0, sizeof *out);
    out->tag = SCRYPT_TYPE_INT;
    return bn_dup(src, &out->as.int_val);
}

/* Build a raw-bytes value (BYTES/PUBKEY/SHA256) from a byte_buf_t copy. */
static int arg_bytes_copy(scrypt_arg_t *out, scrypt_type_t tag,
                          const uint8_t *data, size_t len)
{
    memset(out, 0, sizeof *out);
    out->tag = tag;
    byte_buf_init(&out->as.bytes_val);
    return byte_buf_from(&out->as.bytes_val, data, len);
}

/* ---- lifecycle ----------------------------------------------------------- */

void ricardian_tea_params_free(ricardian_tea_params_t *p)
{
    if (!p) return;
    byte_buf_free(&p->owner);
    byte_buf_free(&p->agent);
    byte_buf_free(&p->ricardian_hash);
    bn_free(p->per_tx_limit);
    bn_free(p->daily_limit);
    bn_free(p->window_duration);
    bn_free(p->graduation_threshold);
    bn_free(p->validator_threshold);
    bn_free(p->designated_validator_pubkey);
    bn_free(p->validator_rabin_pubkey);
    bn_free(p->max_slashing_target);
    bn_free(p->min_slash_confirmations);
    byte_buf_free(&p->initial_slash_checkpoint_hash);
    memset(p, 0, sizeof *p);
}

void ricardian_tea_state_free(ricardian_tea_state_t *s)
{
    if (!s) return;
    bn_free(s->tx_count);
    bn_free(s->spent_in_window);
    bn_free(s->window_start);
    bn_free(s->tier);
    byte_buf_free(&s->slash_checkpoint_hash);
    memset(s, 0, sizeof *s);
}

/* Advance the @prop(true) state EXACTLY as RicardianTea.executeTea does (ricardianTea.ts:265-313):
 *   if (now - windowStart >= windowDuration) { windowStart = now; spent = 0 }
 *   spent += amount; txCount += 1;
 *   if (txCount >= graduationThreshold && tier < 2) tier = 2;
 * slashCheckpointHash is unchanged. output[0] of an executeTea spend MUST carry these advances or
 * the contract's assert(hashOutputs == ...) over the POST-spend state fails and the tx is unminable.
 * Mirrors agent_tea_apply_action (which additionally rotates recoveryCount; RicardianTea has none).
 * `next` is filled (caller frees via ricardian_tea_state_free). BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int ricardian_tea_apply_action(const ricardian_tea_t *c, const bn_t *amount, int64_t now,
                               ricardian_tea_state_t *next)
{
    if (c == NULL || amount == NULL || next == NULL) return BNS_EINVAL;
    const ricardian_tea_state_t *s = &c->state;
    const ricardian_tea_params_t *p = &c->params;
    memset(next, 0, sizeof *next);

    int rc;
    bn_t *now_bn = NULL, *delta = NULL, *one = NULL, *two = NULL, *ws = NULL, *spent = NULL;
    char dec[32];
    snprintf(dec, sizeof dec, "%lld", (long long)now);
    if ((rc = bn_parse_dec(dec, &now_bn)) != BNS_OK) goto done;
    if ((rc = bn_parse_dec("1", &one))    != BNS_OK) goto done;
    if ((rc = bn_parse_dec("2", &two))    != BNS_OK) goto done;

    /* window roll */
    if ((rc = bn_sub(now_bn, s->window_start, &delta)) != BNS_OK) goto done;
    if (bn_cmp(delta, p->window_duration) >= 0) {
        if ((rc = bn_dup(now_bn, &ws))       != BNS_OK) goto done;
        if ((rc = bn_parse_dec("0", &spent)) != BNS_OK) goto done;
    } else {
        if ((rc = bn_dup(s->window_start, &ws))       != BNS_OK) goto done;
        if ((rc = bn_dup(s->spent_in_window, &spent)) != BNS_OK) goto done;
    }
    /* spent += amount */
    { bn_t *t = NULL; if ((rc = bn_add(spent, amount, &t)) != BNS_OK) goto done; bn_free(spent); spent = t; }
    /* txCount += 1 */
    if ((rc = bn_add(s->tx_count, one, &next->tx_count)) != BNS_OK) goto done;
    next->spent_in_window = spent; spent = NULL;
    next->window_start    = ws;    ws = NULL;
    /* tier graduation */
    if (bn_cmp(next->tx_count, p->graduation_threshold) >= 0 && bn_cmp(s->tier, two) < 0) {
        if ((rc = bn_parse_dec("2", &next->tier)) != BNS_OK) goto done;
    } else {
        if ((rc = bn_dup(s->tier, &next->tier))   != BNS_OK) goto done;
    }
    /* slashCheckpointHash unchanged (byte_buf_from self-inits over the memset-zeroed field). */
    if ((rc = byte_buf_from(&next->slash_checkpoint_hash,
                            s->slash_checkpoint_hash.data, s->slash_checkpoint_hash.len)) != BNS_OK) goto done;
    rc = BNS_OK;

done:
    bn_free(now_bn); bn_free(delta); bn_free(one); bn_free(two); bn_free(ws); bn_free(spent);
    if (rc != BNS_OK) ricardian_tea_state_free(next);
    return rc;
}

void ricardian_tea_free(ricardian_tea_t *c)
{
    if (!c) return;
    ricardian_tea_params_free(&c->params);
    ricardian_tea_state_free(&c->state);
    /* artifact is borrowed; not freed here */
    memset(c, 0, sizeof *c);
}

/* ---- genesis state ------------------------------------------------------- */

int ricardian_tea_genesis_state(const ricardian_tea_params_t *params,
                                ricardian_tea_state_t *out)
{
    if (!params || !out) return BNS_EINVAL;
    memset(out, 0, sizeof *out);
    byte_buf_init(&out->slash_checkpoint_hash);

    out->tx_count        = bn_new();
    out->spent_in_window = bn_new();
    out->window_start    = bn_new();
    out->tier            = bn_new();
    if (!out->tx_count || !out->spent_in_window || !out->window_start || !out->tier) {
        ricardian_tea_state_free(out);
        return BNS_ENOMEM;
    }
    /* txCount=0, spentInWindow=0, windowStart=0 are the bn_new() zeros; tier=1 */
    bn_t *one = NULL;
    if (bn_parse_dec("1", &one) != BNS_OK) {
        ricardian_tea_state_free(out);
        return BNS_ENOMEM;
    }
    bn_free(out->tier);
    out->tier = one;

    /* slashCheckpointHash = initialSlashCheckpointHash */
    if (byte_buf_from(&out->slash_checkpoint_hash,
                      params->initial_slash_checkpoint_hash.data,
                      params->initial_slash_checkpoint_hash.len) != BNS_OK) {
        ricardian_tea_state_free(out);
        return BNS_ENOMEM;
    }
    return BNS_OK;
}

/* ---- locking-script reconstruction --------------------------------------- */

int ricardian_tea_locking_script(const ricardian_tea_t *c, bool is_genesis,
                                 byte_buf_t *out)
{
    if (!c || !c->artifact || !out) return BNS_EINVAL;
    const ricardian_tea_params_t *p = &c->params;
    const ricardian_tea_state_t  *s = &c->state;

    /* 13 ctor args, @prop declaration order. PubKeys/Sha256 as raw bytes; the
     * bigint policy/Rabin params as SCRYPT_TYPE_INT (RabinPubKey is an int
     * alias and is encoded by the opcode-optimized ctor int encoder). */
    scrypt_arg_t cv[13];
    memset(cv, 0, sizeof cv);
    int rc = BNS_OK;
    int built = 0;
#define ARGB(expr) do { if (rc == BNS_OK) { rc = (expr); if (rc == BNS_OK) built++; } } while (0)
    ARGB(arg_bytes_copy(&cv[0], SCRYPT_TYPE_PUBKEY, p->owner.data, p->owner.len));
    ARGB(arg_bytes_copy(&cv[1], SCRYPT_TYPE_PUBKEY, p->agent.data, p->agent.len));
    ARGB(arg_bytes_copy(&cv[2], SCRYPT_TYPE_SHA256, p->ricardian_hash.data, p->ricardian_hash.len));
    ARGB(arg_int_dup(&cv[3],  p->per_tx_limit));
    ARGB(arg_int_dup(&cv[4],  p->daily_limit));
    ARGB(arg_int_dup(&cv[5],  p->window_duration));
    ARGB(arg_int_dup(&cv[6],  p->graduation_threshold));
    ARGB(arg_int_dup(&cv[7],  p->validator_threshold));
    ARGB(arg_int_dup(&cv[8],  p->designated_validator_pubkey));
    ARGB(arg_int_dup(&cv[9],  p->validator_rabin_pubkey));
    ARGB(arg_int_dup(&cv[10], p->max_slashing_target));
    ARGB(arg_int_dup(&cv[11], p->min_slash_confirmations));
    ARGB(arg_bytes_copy(&cv[12], SCRYPT_TYPE_SHA256,
                        p->initial_slash_checkpoint_hash.data,
                        p->initial_slash_checkpoint_hash.len));

    /* 5 state values, declaration order. */
    scrypt_arg_t sv[5];
    memset(sv, 0, sizeof sv);
    int sbuilt = 0;
#define SARGB(expr) do { if (rc == BNS_OK) { rc = (expr); if (rc == BNS_OK) sbuilt++; } } while (0)
    SARGB(arg_int_dup(&sv[0], s->tx_count));
    SARGB(arg_int_dup(&sv[1], s->spent_in_window));
    SARGB(arg_int_dup(&sv[2], s->window_start));
    SARGB(arg_int_dup(&sv[3], s->tier));
    SARGB(arg_bytes_copy(&sv[4], SCRYPT_TYPE_SHA256,
                         s->slash_checkpoint_hash.data, s->slash_checkpoint_hash.len));
#undef SARGB
#undef ARGB

    if (rc == BNS_OK)
        rc = reconstruct_locking_script(c->artifact, cv, 13, sv, 5, is_genesis, out);

    for (int i = 0; i < built;  i++) scrypt_arg_free(&cv[i]);
    for (int i = 0; i < sbuilt; i++) scrypt_arg_free(&sv[i]);
    return rc;
}

/* ---- attestation preimage ------------------------------------------------ */

int ricardian_tea_attestation_msg(const uint8_t ricardian_hash[32],
                                  const uint8_t agent[33],
                                  const bn_t *validator_pubkey,
                                  const bn_t *amount,
                                  const bn_t *attested_limit,
                                  const uint8_t receipt_hash[32],
                                  byte_buf_t *out)
{
    if (!ricardian_hash || !agent || !validator_pubkey || !amount ||
        !attested_limit || !receipt_hash || !out)
        return BNS_EINVAL;

    byte_buf_t tag; byte_buf_init(&tag);
    int rc = hex_decode(BONSAI_RTEA_ATTEST_TAG_HEX, &tag);
    if (rc != BNS_OK) { byte_buf_free(&tag); return rc; }

    /* tag(13) || ricardianHash(32) || agent(33) */
    if ((rc = byte_buf_append_buf(out, &tag)) != BNS_OK) goto done;
    if ((rc = byte_buf_append(out, ricardian_hash, 32)) != BNS_OK) goto done;
    if ((rc = byte_buf_append(out, agent, 33)) != BNS_OK) goto done;
    /* int2ByteString(validatorPubKey) — ONE-ARG minimal sign-magnitude */
    if ((rc = int2bytestring_minimal(validator_pubkey, out)) != BNS_OK) goto done;
    /* int2ByteString(amount,8) and int2ByteString(attestedLimit,8) — TWO-ARG */
    if ((rc = int2bytestring_sized(amount, 8, out)) != BNS_OK) goto done;
    if ((rc = int2bytestring_sized(attested_limit, 8, out)) != BNS_OK) goto done;
    /* receiptHash(32) */
    rc = byte_buf_append(out, receipt_hash, 32);

done:
    byte_buf_free(&tag);
    return rc;
}

/* ---- receipt preimage ---------------------------------------------------- */

int ricardian_tea_receipt_preimage(const ricardian_tea_t *c,
                                   const uint8_t counterparty[33],
                                   const bn_t *amount,
                                   const uint8_t invoice_hash[32],
                                   const uint8_t provenance_hash[32],
                                   int64_t now,
                                   byte_buf_t *out)
{
    if (!c || !counterparty || !amount || !invoice_hash || !provenance_hash || !out)
        return BNS_EINVAL;
    const ricardian_tea_params_t *p = &c->params;
    const ricardian_tea_state_t  *s = &c->state;
    if (p->ricardian_hash.len != 32 || p->agent.len != 33)
        return BNS_EINVAL;

    int rc;
    /* ricardianHash(32) || agent(33) || counterparty(33) */
    if ((rc = byte_buf_append(out, p->ricardian_hash.data, 32)) != BNS_OK) return rc;
    if ((rc = byte_buf_append(out, p->agent.data, 33)) != BNS_OK) return rc;
    if ((rc = byte_buf_append(out, counterparty, 33)) != BNS_OK) return rc;
    /* int2ByteString(amount,8) */
    if ((rc = int2bytestring_sized(amount, 8, out)) != BNS_OK) return rc;
    /* invoiceHash(32) || provenanceHash(32) */
    if ((rc = byte_buf_append(out, invoice_hash, 32)) != BNS_OK) return rc;
    if ((rc = byte_buf_append(out, provenance_hash, 32)) != BNS_OK) return rc;
    /* int2ByteString(txCount,8) — PRE-increment value from current state */
    if ((rc = int2bytestring_sized(s->tx_count, 8, out)) != BNS_OK) return rc;
    /* int2ByteString(now,4) — signed 4-byte CScriptNum */
    {
        char dec[32];
        snprintf(dec, sizeof dec, "%lld", (long long)now);
        bn_t *bn_now = NULL;
        if ((rc = bn_parse_dec(dec, &bn_now)) != BNS_OK) return rc;
        rc = int2bytestring_sized(bn_now, 4, out);
        bn_free(bn_now);
        if (rc != BNS_OK) return rc;
    }
    return BNS_OK;
}

int ricardian_tea_receipt_hash(const ricardian_tea_t *c,
                               const uint8_t counterparty[33],
                               const bn_t *amount,
                               const uint8_t invoice_hash[32],
                               const uint8_t provenance_hash[32],
                               int64_t now,
                               char **out_hex)
{
    if (!out_hex) return BNS_EINVAL;
    *out_hex = NULL;

    byte_buf_t pre; byte_buf_init(&pre);
    int rc = ricardian_tea_receipt_preimage(c, counterparty, amount, invoice_hash,
                                            provenance_hash, now, &pre);
    if (rc != BNS_OK) { byte_buf_free(&pre); return rc; }

    uint8_t dig[BONSAI_SHA256_LEN];
    sha256(pre.data, pre.len, dig);
    byte_buf_free(&pre);

    char *h = hex_encode(dig, sizeof dig);
    if (!h) return BNS_ENOMEM;
    *out_hex = h;
    return BNS_OK;
}
