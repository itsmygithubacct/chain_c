/*
 * contracts_next/agent_tea.c — AgentTea (Pillar-B sovereign-agent identity).
 *
 * Implements include/contracts_next/agent_tea.h: genesis state init, locking-
 * script reconstruction (delegating to scrypt/script_codec.h), the resumable
 * from_tx state DECODER, and the byte-exact attestation / recovery / receipt
 * preimage builders.
 *
 * TS origin: src/contracts-next/agentTea.ts.
 *
 * Determinism pins (see header):
 *   - ctor ints use the opcode-optimized CONSTRUCTOR encoder (script_codec A);
 *   - state ints use the no-opcode STATE encoder (script_codec B);
 *   - attestationMsg / recoveryMsg validatorPubKey & recoveryCount counters use
 *     the ONE-ARG minimal LE encoder (num2bin int2bytestring_minimal);
 *   - amount/attestedLimit (8B), txCount (8B), now (signed 4B) in the receipt and
 *     amount/attestedLimit (8B) in attestationMsg use the TWO-ARG fixed-width LE
 *     encoder (num2bin int2bytestring_sized);
 *   - receipt commits txCount at PRE-increment; the mutable agent key is committed
 *     at its CURRENT value.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "contracts_next/agent_tea.h"
#include "common/hex.h"
#include "crypto/hash.h"
#include "bsv/num2bin.h"
#include "scrypt/script_codec.h"

/* AGNT_ATTEST_V1 / AGNT_RECOVER_V1 domain tags (raw preimage bytes). */
static const uint8_t AGNT_ATTEST_TAG[] = {
    0x41,0x47,0x4e,0x54,0x5f,0x41,0x54,0x54,0x45,0x53,0x54,0x5f,0x56,0x31 /* "AGNT_ATTEST_V1" */
};
static const uint8_t AGNT_RECOVER_TAG[] = {
    0x41,0x47,0x4e,0x54,0x5f,0x52,0x45,0x43,0x4f,0x56,0x45,0x52,0x5f,0x56,0x31 /* "AGNT_RECOVER_V1" */
};

/* ---- lifecycle ---------------------------------------------------------- */

void agent_tea_params_free(agent_tea_params_t *p)
{
    if (p == NULL) return;
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
    for (size_t i = 0; i < BONSAI_AGENT_TEA_RECOVERY_KEYS; i++)
        bn_free(p->recovery_keys[i]);
    bn_free(p->recovery_threshold);
    memset(p, 0, sizeof *p);
}

void agent_tea_state_free(agent_tea_state_t *s)
{
    if (s == NULL) return;
    bn_free(s->tx_count);
    bn_free(s->spent_in_window);
    bn_free(s->window_start);
    bn_free(s->tier);
    bn_free(s->recovery_count);
    memset(s, 0, sizeof *s);
}

void agent_tea_free(agent_tea_t *c)
{
    if (c == NULL) return;
    agent_tea_params_free(&c->params);
    agent_tea_state_free(&c->state);
    c->artifact = NULL;
}

int agent_tea_genesis_state(agent_tea_state_t *out)
{
    if (out == NULL) return BNS_EINVAL;
    memset(out, 0, sizeof *out);

    if (bn_parse_dec("0", &out->tx_count)        != BNS_OK) goto oom;
    if (bn_parse_dec("0", &out->spent_in_window) != BNS_OK) goto oom;
    if (bn_parse_dec("0", &out->window_start)    != BNS_OK) goto oom;
    if (bn_parse_dec("1", &out->tier)            != BNS_OK) goto oom;
    if (bn_parse_dec("0", &out->recovery_count)  != BNS_OK) goto oom;
    return BNS_OK;

oom:
    agent_tea_state_free(out);
    return BNS_ENOMEM;
}

/* Compute the POST-action state from c->state, EXACTLY as executeAction does on-chain:
 *   if (now - windowStart >= windowDuration) { windowStart = now; spent = 0; }
 *   spent += amount; txCount += 1; spentInWindow = spent; windowStart = windowStart;
 *   if (txCount >= graduationThreshold && tier < 2) tier = 2;
 * The output[0] state MUST carry these advances or the contract's hashOutputs check fails. */
int agent_tea_apply_action(const agent_tea_t *c, const bn_t *amount, int64_t now,
                           agent_tea_state_t *next)
{
    if (c == NULL || amount == NULL || next == NULL) return BNS_EINVAL;
    const agent_tea_state_t *s = &c->state;
    const agent_tea_params_t *p = &c->params;
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
        if ((rc = bn_dup(now_bn, &ws))         != BNS_OK) goto done;
        if ((rc = bn_parse_dec("0", &spent))   != BNS_OK) goto done;
    } else {
        if ((rc = bn_dup(s->window_start, &ws))        != BNS_OK) goto done;
        if ((rc = bn_dup(s->spent_in_window, &spent))  != BNS_OK) goto done;
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
    if ((rc = bn_dup(s->recovery_count, &next->recovery_count)) != BNS_OK) goto done;
    rc = BNS_OK;

done:
    bn_free(now_bn); bn_free(delta); bn_free(one); bn_free(two); bn_free(ws); bn_free(spent);
    if (rc != BNS_OK) agent_tea_state_free(next);
    return rc;
}

/* ---- locking-script reconstruction -------------------------------------- */

/* Helper: dup a bn_t (returns NULL on OOM). */
static bn_t *bn_dup_or_null(const bn_t *src)
{
    bn_t *d = NULL;
    if (src == NULL) return NULL;
    if (bn_dup(src, &d) != BNS_OK) return NULL;
    return d;
}

/* Build a scalar INT/RABIN_PUBKEY scrypt_arg referencing a dup of `src`. */
static int set_int_arg(scrypt_arg_t *a, scrypt_type_t tag, const bn_t *src)
{
    bn_t *d = bn_dup_or_null(src);
    if (d == NULL) return BNS_ENOMEM;
    a->tag = tag;
    if (tag == SCRYPT_TYPE_RABIN_PUBKEY) a->as.rabin_val = d;
    else                                 a->as.int_val   = d;
    return BNS_OK;
}

/* Build a BYTES-family scrypt_arg owning a copy of buf. */
static int set_bytes_arg(scrypt_arg_t *a, scrypt_type_t tag, const byte_buf_t *buf)
{
    byte_buf_init(&a->as.bytes_val);
    a->tag = tag;
    return byte_buf_from(&a->as.bytes_val, buf->data, buf->len);
}

int agent_tea_locking_script_ex(const agent_tea_t *c, bool is_genesis,
                                const byte_buf_t *state_agent, byte_buf_t *out)
{
    int rc;
    /* 12 ctor args (recoveryKeys is a FixedArray<RabinPubKey,3>). */
    scrypt_arg_t ctor[12];
    /* 6 state values, in stateProps order: agent(PubKey), txCount, spentInWindow,
     * windowStart, tier, recoveryCount. */
    scrypt_arg_t state[6];
    size_t nctor = 0, nstate = 0;

    if (c == NULL || c->artifact == NULL || out == NULL) return BNS_EINVAL;

    memset(ctor, 0, sizeof ctor);
    memset(state, 0, sizeof state);

    const agent_tea_params_t *p = &c->params;
    const agent_tea_state_t  *s = &c->state;

    /* ---- ctor args (declaration order) ---- */
#define PUT_BYTES(arr, n, tag, src) do { \
        if ((rc = set_bytes_arg(&(arr), (tag), (src))) != BNS_OK) goto done; \
        (n)++; \
    } while (0)
#define PUT_INT(arr, n, tag, src) do { \
        if ((rc = set_int_arg(&(arr), (tag), (src))) != BNS_OK) goto done; \
        (n)++; \
    } while (0)

    PUT_BYTES(ctor[0], nctor, SCRYPT_TYPE_PUBKEY, &p->owner);
    PUT_BYTES(ctor[1], nctor, SCRYPT_TYPE_PUBKEY, &p->agent);
    PUT_BYTES(ctor[2], nctor, SCRYPT_TYPE_SHA256, &p->ricardian_hash);
    PUT_INT(ctor[3], nctor, SCRYPT_TYPE_INT, p->per_tx_limit);
    PUT_INT(ctor[4], nctor, SCRYPT_TYPE_INT, p->daily_limit);
    PUT_INT(ctor[5], nctor, SCRYPT_TYPE_INT, p->window_duration);
    PUT_INT(ctor[6], nctor, SCRYPT_TYPE_INT, p->graduation_threshold);
    PUT_INT(ctor[7], nctor, SCRYPT_TYPE_INT, p->validator_threshold);
    PUT_INT(ctor[8], nctor, SCRYPT_TYPE_RABIN_PUBKEY, p->designated_validator_pubkey);
    PUT_INT(ctor[9], nctor, SCRYPT_TYPE_RABIN_PUBKEY, p->validator_rabin_pubkey);

    /* recoveryKeys: FixedArray<RabinPubKey,3> -> a single SCRYPT_TYPE_FIXED_ARRAY
     * arg with 3 RABIN_PUBKEY elements (flattened by flatten_args). */
    {
        scrypt_arg_t *fa = &ctor[10];
        fa->tag = SCRYPT_TYPE_FIXED_ARRAY;
        fa->as.array.count = BONSAI_AGENT_TEA_RECOVERY_KEYS;
        fa->as.array.elems = calloc(BONSAI_AGENT_TEA_RECOVERY_KEYS, sizeof(scrypt_arg_t));
        if (fa->as.array.elems == NULL) { rc = BNS_ENOMEM; goto done; }
        nctor++;
        for (size_t i = 0; i < BONSAI_AGENT_TEA_RECOVERY_KEYS; i++) {
            if ((rc = set_int_arg(&fa->as.array.elems[i], SCRYPT_TYPE_RABIN_PUBKEY,
                                  p->recovery_keys[i])) != BNS_OK) goto done;
        }
    }
    PUT_INT(ctor[11], nctor, SCRYPT_TYPE_INT, p->recovery_threshold);

    /* ---- state values (stateProps order: agent first) ----
     * The @state agent (state[0]) can be overridden by `state_agent` so recover()
     * rotates ONLY this copy; ctor[1] (above) stays the genesis agent frozen in the
     * immutable code part — exactly what the contract's getStateScript reconstructs. */
    PUT_BYTES(state[0], nstate, SCRYPT_TYPE_PUBKEY,
              state_agent != NULL ? state_agent : &p->agent);
    PUT_INT(state[1], nstate, SCRYPT_TYPE_INT, s->tx_count);
    PUT_INT(state[2], nstate, SCRYPT_TYPE_INT, s->spent_in_window);
    PUT_INT(state[3], nstate, SCRYPT_TYPE_INT, s->window_start);
    PUT_INT(state[4], nstate, SCRYPT_TYPE_INT, s->tier);
    PUT_INT(state[5], nstate, SCRYPT_TYPE_INT, s->recovery_count);

#undef PUT_BYTES
#undef PUT_INT

    rc = reconstruct_locking_script(c->artifact, ctor, nctor,
                                    state, nstate, is_genesis, out);

done:
    for (size_t i = 0; i < nctor; i++) scrypt_arg_free(&ctor[i]);
    for (size_t i = 0; i < nstate; i++) scrypt_arg_free(&state[i]);
    return rc;
}

int agent_tea_locking_script(const agent_tea_t *c, bool is_genesis,
                             byte_buf_t *out)
{
    return agent_tea_locking_script_ex(c, is_genesis, NULL, out);
}

/* ---- resumable state DECODER (for agentd) ------------------------------- */

/* Read one minimal-pushdata element from script[*pos..end). On success sets
 * (*data,*dlen) to point INTO `script` and advances *pos past the element.
 * Handles direct pushes (0x01..0x4b) and OP_PUSHDATA1/2/4. Returns BNS_OK or
 * BNS_EPARSE. A push of 0 bytes (opcode 0x00 == OP_0) yields dlen==0. */
static int read_push(const uint8_t *script, size_t end, size_t *pos,
                     const uint8_t **data, size_t *dlen)
{
    size_t p = *pos;
    if (p >= end) return BNS_EPARSE;
    uint8_t op = script[p++];
    size_t n;
    if (op == 0x00) {                    /* OP_0 / empty push */
        n = 0;
    } else if (op <= 0x4b) {             /* direct push of `op` bytes */
        n = op;
    } else if (op == 0x4c) {             /* OP_PUSHDATA1 */
        if (p + 1 > end) return BNS_EPARSE;
        n = script[p++];
    } else if (op == 0x4d) {             /* OP_PUSHDATA2 */
        if (p + 2 > end) return BNS_EPARSE;
        n = (size_t)script[p] | ((size_t)script[p + 1] << 8);
        p += 2;
    } else if (op == 0x4e) {             /* OP_PUSHDATA4 */
        if (p + 4 > end) return BNS_EPARSE;
        n = (size_t)script[p] | ((size_t)script[p + 1] << 8) |
            ((size_t)script[p + 2] << 16) | ((size_t)script[p + 3] << 24);
        p += 4;
    } else {
        return BNS_EPARSE;               /* not a pushdata opcode */
    }
    if (p + n > end) return BNS_EPARSE;
    *data = script + p;
    *dlen = n;
    *pos = p + n;
    return BNS_OK;
}

/* Decode a STATE int push body (minimal sign-magnitude LE, non-negative here:
 * a positive value may carry a trailing 0x00 sign byte which contributes nothing
 * to the unsigned magnitude, and the zero state value encodes as a single 0x00
 * byte) into a fresh bn_t via unsigned LE parse. */
static int decode_state_int(const uint8_t *body, size_t len, bn_t **out)
{
    return bn_parse_le(body, len, out);
}

int agent_tea_from_tx(const uint8_t *locking_script, size_t len,
                      const scrypt_artifact_t *artifact,
                      agent_tea_state_t *out_state, byte_buf_t *out_agent)
{
    int rc;
    size_t pos, body_start, body_end, state_len;
    const uint8_t *agent_data = NULL;
    size_t agent_len = 0;
    agent_tea_state_t st;

    (void)artifact; /* state layout is fixed for AgentTea; artifact borrowed for API symmetry */

    if (locking_script == NULL || out_state == NULL) return BNS_EINVAL;
    memset(&st, 0, sizeof st);

    /* The state suffix trailer is: [4-byte LE stateByteLen][version byte].
     * The state body of `stateByteLen` bytes immediately precedes the trailer. */
    if (len < 5) return BNS_EPARSE;
    /* version byte is the final byte (we do not assert its value). */
    state_len = (size_t)locking_script[len - 5] |
                ((size_t)locking_script[len - 4] << 8) |
                ((size_t)locking_script[len - 3] << 16) |
                ((size_t)locking_script[len - 2] << 24);
    if (state_len < 1 || state_len + 5 > len) return BNS_EPARSE; /* must hold >= isGenesis byte */

    body_start = len - 5 - state_len;
    body_end   = len - 5;

    /* state body: [isGenesis byte][agent push][txCount][spentInWindow]
     *             [windowStart][tier][recoveryCount] */
    pos = body_start;
    pos++; /* skip isGenesis flag byte */

    /* agent PubKey push (33 bytes expected). */
    if ((rc = read_push(locking_script, body_end, &pos, &agent_data, &agent_len)) != BNS_OK)
        return rc;
    if (agent_len != 33) return BNS_EPARSE;

    /* 5 numeric state ints. */
    {
        const uint8_t *d;
        size_t dl;
        bn_t **slots[5] = {
            &st.tx_count, &st.spent_in_window, &st.window_start,
            &st.tier, &st.recovery_count
        };
        for (int i = 0; i < 5; i++) {
            if ((rc = read_push(locking_script, body_end, &pos, &d, &dl)) != BNS_OK)
                goto fail;
            if ((rc = decode_state_int(d, dl, slots[i])) != BNS_OK)
                goto fail;
        }
    }

    /* The body must be fully consumed by the documented layout. */
    if (pos != body_end) { rc = BNS_EPARSE; goto fail; }

    if (out_agent != NULL) {
        if ((rc = byte_buf_append(out_agent, agent_data, agent_len)) != BNS_OK)
            goto fail;
    }

    *out_state = st;
    return BNS_OK;

fail:
    agent_tea_state_free(&st);
    return rc;
}

/* ---- byte-exact preimage builders --------------------------------------- */

int agent_tea_attestation_msg(const uint8_t ricardian_hash[32],
                              const uint8_t agent[33],
                              const bn_t *validator_pubkey,
                              const bn_t *amount,
                              const bn_t *attested_limit,
                              const uint8_t receipt_hash[32],
                              byte_buf_t *out)
{
    int rc;
    if (ricardian_hash == NULL || agent == NULL || validator_pubkey == NULL ||
        amount == NULL || attested_limit == NULL || receipt_hash == NULL || out == NULL)
        return BNS_EINVAL;

    if ((rc = byte_buf_append(out, AGNT_ATTEST_TAG, sizeof AGNT_ATTEST_TAG)) != BNS_OK) return rc;
    if ((rc = byte_buf_append(out, ricardian_hash, 32)) != BNS_OK) return rc;
    if ((rc = byte_buf_append(out, agent, 33)) != BNS_OK) return rc;
    /* validatorPubKey: ONE-ARG minimal LE sign-magnitude. */
    if ((rc = int2bytestring_minimal(validator_pubkey, out)) != BNS_OK) return rc;
    /* amount, attestedLimit: TWO-ARG fixed 8-byte LE. */
    if ((rc = int2bytestring_sized(amount, 8, out)) != BNS_OK) return rc;
    if ((rc = int2bytestring_sized(attested_limit, 8, out)) != BNS_OK) return rc;
    if ((rc = byte_buf_append(out, receipt_hash, 32)) != BNS_OK) return rc;
    return BNS_OK;
}

int agent_tea_recovery_msg(const uint8_t ricardian_hash[32],
                           const uint8_t new_agent[33],
                           const bn_t *recovery_count,
                           byte_buf_t *out)
{
    int rc;
    if (ricardian_hash == NULL || new_agent == NULL || recovery_count == NULL || out == NULL)
        return BNS_EINVAL;

    if ((rc = byte_buf_append(out, AGNT_RECOVER_TAG, sizeof AGNT_RECOVER_TAG)) != BNS_OK) return rc;
    if ((rc = byte_buf_append(out, ricardian_hash, 32)) != BNS_OK) return rc;
    if ((rc = byte_buf_append(out, new_agent, 33)) != BNS_OK) return rc;
    /* recoveryCount: TWO-ARG fixed 8-byte LE (int2ByteString(recoveryCount, 8n)). */
    if ((rc = int2bytestring_sized(recovery_count, 8, out)) != BNS_OK) return rc;
    return BNS_OK;
}

int agent_tea_receipt_preimage(const agent_tea_t *c,
                               const uint8_t counterparty[33],
                               const bn_t *amount,
                               const uint8_t action_hash[32],
                               const uint8_t provenance_hash[32],
                               int64_t now,
                               byte_buf_t *out)
{
    int rc;
    bn_t *now_bn = NULL;
    char dec[32];

    if (c == NULL || counterparty == NULL || amount == NULL ||
        action_hash == NULL || provenance_hash == NULL || out == NULL)
        return BNS_EINVAL;
    if (c->params.ricardian_hash.len != 32 || c->params.agent.len != 33)
        return BNS_EINVAL;
    if (c->state.tx_count == NULL) return BNS_EINVAL;

    /* receipt = ricardianHash(32) || agent(33) || counterparty(33) ||
     *           int2ByteString(amount,8) || actionHash(32) || provenanceHash(32) ||
     *           int2ByteString(txCount,8) [PRE-increment] || int2ByteString(now,4) */
    if ((rc = byte_buf_append(out, c->params.ricardian_hash.data, 32)) != BNS_OK) return rc;
    if ((rc = byte_buf_append(out, c->params.agent.data, 33)) != BNS_OK) return rc;
    if ((rc = byte_buf_append(out, counterparty, 33)) != BNS_OK) return rc;
    if ((rc = int2bytestring_sized(amount, 8, out)) != BNS_OK) return rc;
    if ((rc = byte_buf_append(out, action_hash, 32)) != BNS_OK) return rc;
    if ((rc = byte_buf_append(out, provenance_hash, 32)) != BNS_OK) return rc;
    if ((rc = int2bytestring_sized(c->state.tx_count, 8, out)) != BNS_OK) return rc;

    snprintf(dec, sizeof dec, "%lld", (long long)now);
    if ((rc = bn_parse_dec(dec, &now_bn)) != BNS_OK) return rc;
    rc = int2bytestring_sized(now_bn, 4, out);
    bn_free(now_bn);
    return rc;
}

int agent_tea_receipt_hash(const agent_tea_t *c,
                           const uint8_t counterparty[33],
                           const bn_t *amount,
                           const uint8_t action_hash[32],
                           const uint8_t provenance_hash[32],
                           int64_t now,
                           char **out_hex)
{
    int rc;
    byte_buf_t pre;
    uint8_t digest[BONSAI_SHA256_LEN];

    if (out_hex == NULL) return BNS_EINVAL;
    *out_hex = NULL;

    byte_buf_init(&pre);
    rc = agent_tea_receipt_preimage(c, counterparty, amount, action_hash,
                                    provenance_hash, now, &pre);
    if (rc != BNS_OK) { byte_buf_free(&pre); return rc; }

    sha256(pre.data, pre.len, digest);
    byte_buf_free(&pre);

    *out_hex = hex_encode(digest, sizeof digest);
    return (*out_hex != NULL) ? BNS_OK : BNS_ENOMEM;
}
