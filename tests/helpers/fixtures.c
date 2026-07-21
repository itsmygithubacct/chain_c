/* fixtures.c — see fixtures.h. */
#include "fixtures.h"

#include <stdlib.h>
#include <string.h>

#include "common/hex.h"
#include "bsv/script_utils.h"
#include "bsv/tx_builder.h"

/* ---- golden vectors ----------------------------------------------------- */

/* 'aa'*32 02 'bb'*32 03 'cc'*32 | int2ByteString(1234,8)=d204000000000000 |
 * 'dd'*32 'ee'*32 | int2ByteString(7,8)=0700000000000000 |
 * int2ByteString(1700000000,4)=00f15365  (all little-endian fixed widths). */
const char FIX_AGENTD_GOLDEN_RECEIPT_PREIMAGE_HEX[] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "02"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    "03"
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    "d204000000000000"
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    "0700000000000000"
    "00f15365";

/* Compressed pubkey for secret = 32 bytes of 0x01 (see tx_helper.c
 * fix_test_seckey). This is the well-known secp256k1 point 1*G + ... ; pinned
 * literal so identity/charter tests need no key derivation to reference it. */
const char FIX_PUBKEY_COMPRESSED_HEX[] =
    "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";

/* ---- charter fixtures --------------------------------------------------- */

const char FIX_CHARTER_VALID_BODY[] =
    "perTxLimit          = 100000\n"
    "dailyLimit          = 1000000\n"
    "windowDuration      = 86400\n"
    "graduationThreshold = 10000\n"
    "validatorThreshold  = 50000";

char *fix_charter_block(const char *body)
{
    if (!body) body = "";
    static const char pre[]  = "# charter\n\n<!-- ricardian:params:begin -->\n";
    static const char post[] = "\n<!-- ricardian:params:end -->\n";
    size_t n = sizeof(pre) - 1 + strlen(body) + sizeof(post) - 1 + 1;
    char *out = malloc(n);
    if (!out) return NULL;
    out[0] = '\0';
    strcat(out, pre);
    strcat(out, body);
    strcat(out, post);
    return out;
}

static char *dup_str(const char *s)
{
    size_t n = strlen(s) + 1;
    char *d = malloc(n);
    if (d) memcpy(d, s, n);
    return d;
}

int fix_charter_binding(deployment_binding_t *out)
{
    if (!out) return BNS_EINVAL;
    memset(out, 0, sizeof(*out));
    out->agent_pubkey                  = dup_str("02aa");
    out->designated_validator_pubkey   = dup_str("3");
    out->validator_rabin_pubkey        = dup_str("5");
    out->max_slashing_target           = dup_str("7");
    out->min_slash_confirmations       = dup_str("1");
    out->initial_slash_checkpoint_hash = dup_str(
        "abababababababababababababababababababababababababababababababab");
    if (!out->agent_pubkey || !out->designated_validator_pubkey ||
        !out->validator_rabin_pubkey || !out->max_slashing_target ||
        !out->min_slash_confirmations || !out->initial_slash_checkpoint_hash) {
        deployment_binding_free(out);
        return BNS_ENOMEM;
    }
    return BNS_OK;
}

/* ---- provenance fixture ------------------------------------------------- */

void fix_provenance_record(provenance_record_t *out)
{
    if (!out) return;
    out->dataset_id  = "sha256:dataset-xyz";
    out->model_id    = "agent-fable-5";
    out->version     = "2026-01";
    out->licence_tag = "CC-BY-4.0";
}

/* ---- raw identity-chain tx builders ------------------------------------- */

int fix_raw_tx(const char *out0_script_hex, const char *receipt_hash_hex,
               char **out_hex)
{
    if (!out0_script_hex || !out_hex) return BNS_EINVAL;
    *out_hex = NULL;

    byte_buf_t script0;
    byte_buf_init(&script0);
    int rc = hex_decode(out0_script_hex, &script0);
    if (rc != BNS_OK) { byte_buf_free(&script0); return rc; }

    tx_builder_t b;
    tx_builder_init(&b);

    rc = tx_builder_add_output(&b, script0.data, script0.len, 1);
    byte_buf_free(&script0);
    if (rc != BNS_OK) goto done;

    if (receipt_hash_hex) {
        byte_buf_t r;
        byte_buf_init(&r);
        rc = hex_decode(receipt_hash_hex, &r);
        if (rc != BNS_OK) { byte_buf_free(&r); goto done; }
        byte_buf_t op;
        byte_buf_init(&op);
        rc = build_opreturn_script(r.data, r.len, &op);
        byte_buf_free(&r);
        if (rc != BNS_OK) { byte_buf_free(&op); goto done; }
        rc = tx_builder_add_output(&b, op.data, op.len, 0);
        byte_buf_free(&op);
        if (rc != BNS_OK) goto done;
    }

    rc = tx_builder_build_hex(&b, out_hex);
done:
    tx_builder_free(&b);
    return rc;
}

int fix_raw_tx_recreated(const char *receipt_hash_hex, char **out_hex)
{
    return fix_raw_tx("51", receipt_hash_hex, out_hex);
}

int fix_raw_tx_p2pkh_terminal(char **out_hex)
{
    if (!out_hex) return BNS_EINVAL;
    *out_hex = NULL;
    /* Fixed dummy hash160 (20 bytes of 0xab) -> canonical P2PKH template. */
    uint8_t h160[20];
    memset(h160, 0xab, sizeof(h160));
    byte_buf_t script;
    byte_buf_init(&script);
    int rc = build_p2pkh_script(h160, &script);
    if (rc != BNS_OK) { byte_buf_free(&script); return rc; }
    char *script_hex = hex_encode_buf(&script);
    byte_buf_free(&script);
    if (!script_hex) return BNS_ENOMEM;
    rc = fix_raw_tx(script_hex, NULL, out_hex);
    free(script_hex);
    return rc;
}

int fix_raw_tx_no_outputs(char **out_hex)
{
    if (!out_hex) return BNS_EINVAL;
    *out_hex = NULL;
    tx_builder_t b;
    tx_builder_init(&b);
    int rc = tx_builder_build_hex(&b, out_hex);
    tx_builder_free(&b);
    return rc;
}
