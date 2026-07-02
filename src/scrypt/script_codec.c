/*
 * script_codec.c — scrypt locking-script encoders + full locking-script
 * reconstruction. Faithful C port of scryptlib's serializer.ts (the CONSTRUCTOR
 * encoders int2hex/bool2hex/bytes2hex), stateful.ts (the STATE encoders), and
 * the Contract locking-script assembly (template substitution + code/data part).
 *
 * Three integer encoders converge here; see script_codec.h for the rationale.
 *   (A) CONSTRUCTOR int2hex  : OP_0/OP_1..OP_16/OP_1NEGATE small-int optimization,
 *                              else minimal-push of toSM(little) body.
 *   (B) STATE int2hex        : NO small-int optimization. 0 -> push of a single
 *                              0x00 byte ('0100'); else minimal-push of toSM body.
 * The fixed-width encoder (C) lives in bsv/num2bin.h and is only used here for
 * the 4-byte state-length meta (num2bin(stateLen, 4)).
 *
 * Pushdata wrapping mirrors bsv `Script.fromASM(hexbody).toHex()` for a single
 * data chunk: '' -> '00'; 1..75 -> len||data; 76..255 -> 4c||len||data;
 * 256..65535 -> 4d||len_le16||data; else -> 4e||len_le32||data.
 */
#include "scrypt/script_codec.h"
#include "scrypt/artifact_loader.h"
#include "bsv/num2bin.h"
#include "crypto/bignum.h"
#include "common/hex.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ---- pushdata wrapping (bsv Script.fromASM(hex).toHex() for one chunk) ---- */

/* Append a minimal single data push of `len` bytes from `data` to `out`.
 * Empty data -> a single OP_0 (0x00) byte, matching bsv fromASM(''). */
static int push_data(byte_buf_t *out, const uint8_t *data, size_t len)
{
    int rc;
    if (len == 0) {
        return byte_buf_append_byte(out, 0x00);
    }
    if (len <= 75) {
        if ((rc = byte_buf_append_byte(out, (uint8_t)len)) != BNS_OK) return rc;
    } else if (len <= 0xff) {
        if ((rc = byte_buf_append_byte(out, 0x4c)) != BNS_OK) return rc;       /* OP_PUSHDATA1 */
        if ((rc = byte_buf_append_byte(out, (uint8_t)len)) != BNS_OK) return rc;
    } else if (len <= 0xffff) {
        uint8_t l2[2] = { (uint8_t)(len & 0xff), (uint8_t)((len >> 8) & 0xff) };
        if ((rc = byte_buf_append_byte(out, 0x4d)) != BNS_OK) return rc;       /* OP_PUSHDATA2 */
        if ((rc = byte_buf_append(out, l2, 2)) != BNS_OK) return rc;
    } else {
        uint8_t l4[4] = { (uint8_t)(len & 0xff), (uint8_t)((len >> 8) & 0xff),
                          (uint8_t)((len >> 16) & 0xff), (uint8_t)((len >> 24) & 0xff) };
        if ((rc = byte_buf_append_byte(out, 0x4e)) != BNS_OK) return rc;       /* OP_PUSHDATA4 */
        if ((rc = byte_buf_append(out, l4, 4)) != BNS_OK) return rc;
    }
    return byte_buf_append(out, data, len);
}

/* ---- (A) CONSTRUCTOR int encoder (serializer.int2hex) -------------------- */

/* Append the opcode-optimized constructor int push for `bn` to `out`. */
static int ctor_int_push(const bn_t *bn, byte_buf_t *out)
{
    int rc;
    bn_t *one = NULL, *sixteen = NULL, *neg_one = NULL;

    if (bn_is_zero(bn)) {
        return byte_buf_append_byte(out, 0x00);          /* OP_0 */
    }

    /* -1 -> OP_1NEGATE (0x4f) */
    if ((rc = bn_parse_dec("-1", &neg_one)) != BNS_OK) return rc;
    if (bn_cmp(bn, neg_one) == 0) {
        bn_free(neg_one);
        return byte_buf_append_byte(out, 0x4f);
    }
    bn_free(neg_one);

    /* 1..16 -> OP_1..OP_16 (single byte 0x50 + n) */
    if ((rc = bn_parse_dec("1", &one)) != BNS_OK) return rc;
    if ((rc = bn_parse_dec("16", &sixteen)) != BNS_OK) { bn_free(one); return rc; }
    if (bn_cmp(bn, one) >= 0 && bn_cmp(bn, sixteen) <= 0) {
        /* The minimal LE body of 1..16 is a single byte whose value == n. */
        byte_buf_t body;
        byte_buf_init(&body);
        rc = int2bytestring_minimal(bn, &body);
        if (rc == BNS_OK && body.len == 1) {
            rc = byte_buf_append_byte(out, (uint8_t)(0x50 + body.data[0]));
        } else if (rc == BNS_OK) {
            rc = BNS_EINVAL; /* impossible for 1..16 */
        }
        byte_buf_free(&body);
        bn_free(one); bn_free(sixteen);
        return rc;
    }
    bn_free(one); bn_free(sixteen);

    /* else: minimal toSM(little) body wrapped as a pushdata */
    {
        byte_buf_t body;
        byte_buf_init(&body);
        if ((rc = int2bytestring_minimal(bn, &body)) != BNS_OK) { byte_buf_free(&body); return rc; }
        rc = push_data(out, body.data, body.len);
        byte_buf_free(&body);
        return rc;
    }
}

int to_script_hex(const scrypt_arg_t *value, scrypt_type_t type, byte_buf_t *out)
{
    if (value == NULL || out == NULL) return BNS_EINVAL;
    if (value->tag != type) return BNS_EINVAL;

    switch (type) {
    case SCRYPT_TYPE_INT:
        return ctor_int_push(value->as.int_val, out);
    case SCRYPT_TYPE_RABIN_PUBKEY:
        return ctor_int_push(value->as.rabin_val, out);
    case SCRYPT_TYPE_BOOL:
        /* serializer.bool2hex: true -> OP_1 (0x51), false -> OP_0 (0x00) */
        return byte_buf_append_byte(out, value->as.bool_val ? 0x51 : 0x00);
    case SCRYPT_TYPE_BYTES:
    case SCRYPT_TYPE_PUBKEY:
    case SCRYPT_TYPE_SHA256:
    case SCRYPT_TYPE_RIPEMD160: {
        /* serializer.bytes2hex: '' -> '00'; if exactly 1 byte with value 1..16 ->
         * single opcode byte (v + 0x50); else minimal pushdata. */
        const byte_buf_t *b = &value->as.bytes_val;
        if (b->len == 0) {
            return byte_buf_append_byte(out, 0x00);
        }
        if (b->len == 1 && b->data[0] >= 1 && b->data[0] <= 16) {
            return byte_buf_append_byte(out, (uint8_t)(0x50 + b->data[0]));
        }
        return push_data(out, b->data, b->len);
    }
    case SCRYPT_TYPE_FIXED_ARRAY:
    case SCRYPT_TYPE_STRUCT:
    default:
        return BNS_EINVAL; /* compound tags must be flattened first */
    }
}

/* ---- (B) STATE encoders (stateful.ts) ------------------------------------ */

/* Stateful.int2hex: 0 -> fromASM('00').toHex() == push of one 0x00 byte ('0100');
 * else minimal toSM(little) body wrapped as a pushdata. NO small-int opcode. */
static int state_int_push(const bn_t *bn, byte_buf_t *out)
{
    int rc;
    byte_buf_t body;
    byte_buf_init(&body);
    if (bn_is_zero(bn)) {
        /* ASM '00' -> a single data byte 0x00, pushdata-wrapped -> '0100' */
        uint8_t zero = 0x00;
        rc = push_data(out, &zero, 1);
        byte_buf_free(&body);
        return rc;
    }
    if ((rc = int2bytestring_minimal(bn, &body)) != BNS_OK) { byte_buf_free(&body); return rc; }
    rc = push_data(out, body.data, body.len);
    byte_buf_free(&body);
    return rc;
}

/* Append one stateProps value using the STATE encoders (B). */
static int state_value_push(scrypt_type_t type, const scrypt_arg_t *v, byte_buf_t *out)
{
    if (v->tag != type) return BNS_EINVAL;
    switch (type) {
    case SCRYPT_TYPE_INT:
        return state_int_push(v->as.int_val, out);
    case SCRYPT_TYPE_RABIN_PUBKEY:
        return state_int_push(v->as.rabin_val, out);
    case SCRYPT_TYPE_BOOL:
        /* Stateful.bool2hex: true -> '01', false -> '00' (raw, NOT 0x51). */
        return byte_buf_append_byte(out, v->as.bool_val ? 0x01 : 0x00);
    case SCRYPT_TYPE_BYTES:
    case SCRYPT_TYPE_PUBKEY:
    case SCRYPT_TYPE_SHA256:
    case SCRYPT_TYPE_RIPEMD160: {
        /* Stateful.bytes2hex: '' -> '00'; else minimal pushdata (no 1..16 opt). */
        const byte_buf_t *b = &v->as.bytes_val;
        if (b->len == 0) return byte_buf_append_byte(out, 0x00);
        return push_data(out, b->data, b->len);
    }
    default:
        return BNS_EINVAL;
    }
}

int build_state(const scrypt_param_t *state_props,
                const scrypt_arg_t *values, size_t count,
                bool is_genesis, byte_buf_t *out)
{
    int rc;
    byte_buf_t body;
    bn_t *len_bn = NULL;
    size_t state_len;

    if (out == NULL) return BNS_EINVAL;
    if (count > 0 && (state_props == NULL || values == NULL)) return BNS_EINVAL;

    byte_buf_init(&body);

    /* isGenesis hidden built-in state: Stateful.bool2hex(isGenesis) */
    if ((rc = byte_buf_append_byte(&body, is_genesis ? 0x01 : 0x00)) != BNS_OK) goto done;

    for (size_t i = 0; i < count; i++) {
        if ((rc = state_value_push(state_props[i].type, &values[i], &body)) != BNS_OK) goto done;
    }

    /* meta: num2bin(stateByteLen, 4) || version byte (0x00) */
    state_len = body.len;
    {
        char dec[32];
        snprintf(dec, sizeof dec, "%zu", state_len);
        if ((rc = bn_parse_dec(dec, &len_bn)) != BNS_OK) goto done;
    }
    if ((rc = int2bytestring_sized(len_bn, BONSAI_SCRYPT_STATE_LEN_WIDTH, &body)) != BNS_OK) goto done;
    if ((rc = byte_buf_append_byte(&body, BONSAI_SCRYPT_STATE_VERSION)) != BNS_OK) goto done;

    rc = byte_buf_append_buf(out, &body);

done:
    bn_free(len_bn);
    byte_buf_free(&body);
    return rc;
}

/* ---- full locking-script reconstruction ---------------------------------- */

/* Replace every occurrence of needle `<name>` in the NUL-terminated hex string
 * `*tmpl` with `repl`, reallocating. Updates *tmpl. Returns BNS_OK/BNS_ENOMEM. */
static int hex_template_replace(char **tmpl, const char *name, const char *repl)
{
    size_t namelen = strlen(name);
    size_t marklen = namelen + 2; /* '<' + name + '>' */
    size_t replen = strlen(repl);
    char *marker = malloc(marklen + 1);
    if (!marker) return BNS_ENOMEM;
    marker[0] = '<';
    memcpy(marker + 1, name, namelen);
    marker[1 + namelen] = '>';
    marker[marklen] = '\0';

    const char *src = *tmpl;
    /* count occurrences */
    size_t occ = 0;
    for (const char *p = strstr(src, marker); p; p = strstr(p + marklen, marker)) occ++;
    if (occ == 0) { free(marker); return BNS_OK; }

    size_t srclen = strlen(src);
    size_t outlen = srclen + occ * replen - occ * marklen;
    char *dst = malloc(outlen + 1);
    if (!dst) { free(marker); return BNS_ENOMEM; }

    char *w = dst;
    const char *p = src;
    for (;;) {
        const char *hit = strstr(p, marker);
        if (!hit) { size_t rem = strlen(p); memcpy(w, p, rem); w += rem; break; }
        size_t pre = (size_t)(hit - p);
        memcpy(w, p, pre); w += pre;
        memcpy(w, repl, replen); w += replen;
        p = hit + marklen;
    }
    *w = '\0';
    free(marker);
    free(*tmpl);
    *tmpl = dst;
    return BNS_OK;
}

int reconstruct_locking_script(const scrypt_artifact_t *artifact,
                               const scrypt_arg_t *ctor_values,
                               size_t num_ctor_values,
                               const scrypt_arg_t *state_values,
                               size_t num_state_values,
                               bool is_genesis,
                               byte_buf_t *out)
{
    int rc;
    scrypt_leaves_t leaves;
    char *tmpl = NULL;
    byte_buf_t code;

    if (artifact == NULL || out == NULL || artifact->hex_template == NULL) return BNS_EINVAL;

    memset(&leaves, 0, sizeof leaves);
    byte_buf_init(&code);

    /* 1. flatten ctor args into ordered scalar leaves */
    if ((rc = flatten_args(artifact, ctor_values, num_ctor_values, &leaves)) != BNS_OK)
        return rc;

    /* 2. substitute each <leaf.name> placeholder with its CONSTRUCTOR (A) encoding */
    tmpl = strdup(artifact->hex_template);
    if (!tmpl) { rc = BNS_ENOMEM; goto done; }

    for (size_t i = 0; i < leaves.count; i++) {
        const scrypt_leaf_t *lf = &leaves.leaves[i];
        byte_buf_t enc;
        byte_buf_init(&enc);
        rc = to_script_hex(lf->value, lf->value->tag, &enc);
        if (rc != BNS_OK) { byte_buf_free(&enc); goto done; }
        char *enc_hex = hex_encode(enc.data, enc.len);
        byte_buf_free(&enc);
        if (!enc_hex) { rc = BNS_ENOMEM; goto done; }
        rc = hex_template_replace(&tmpl, lf->name, enc_hex);
        free(enc_hex);
        if (rc != BNS_OK) goto done;
    }

    /* 3. decode the substituted code template into bytes */
    if ((rc = hex_decode(tmpl, &code)) != BNS_OK) {
        rc = BNS_EPARSE; /* template no longer valid hex after substitution */
        goto done;
    }
    if ((rc = byte_buf_append_buf(out, &code)) != BNS_OK) goto done;

    /* 4. stateful: append OP_RETURN code/data separator + the state blob (B).
     *    scryptlib: codePart = contractScript.add('6a'); lockingScript = codePart.add(dataPart). */
    if (artifact->stateful) {
        if ((rc = byte_buf_append_byte(out, 0x6a)) != BNS_OK) goto done;
        rc = build_state(artifact->state_props, state_values,
                         num_state_values, is_genesis, out);
        if (rc != BNS_OK) goto done;
    }

    rc = BNS_OK;

done:
    free(tmpl);
    byte_buf_free(&code);
    flat_args_free(&leaves);
    return rc;
}
