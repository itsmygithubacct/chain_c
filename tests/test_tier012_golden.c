/*
 * test_tier012_golden.c — GOLDEN INTEGRATION TEST for the chain_c tier 0-2 lib.
 *
 * Self-contained C program: loads tests/golden/golden.json via cJSON, drives the
 * real C public API (crypto/bsv/scrypt/zk tier 0-2 surface), and asserts
 * byte-exact equality against the TypeScript-captured golden strings.
 *
 * Build (from chain_c/):
 *   gcc -std=c11 -D_GNU_SOURCE -Iinclude -Ithird_party/cJSON \
 *       -Ithird_party/ripemd160 -Ithird_party/mimc7_consts \
 *       tests/test_tier012_golden.c -Lbuild -lbonsai_chain \
 *       $(pkg-config --libs libsecp256k1 libcrypto libcurl) -lm -lpthread \
 *       -o /tmp/t012_golden
 *
 * Prints one "[PASS]/[FAIL]/[SKIP] <name>" line per check, a final
 * "RESULT: X/Y passed", and exits nonzero if any check FAILED.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include "cJSON.h"

#include "common/error.h"
#include "common/bytes.h"
#include "common/hex.h"
#include "crypto/hash.h"
#include "crypto/bignum.h"
#include "crypto/ecdsa.h"
#include "crypto/rabin.h"
#include "bsv/num2bin.h"
#include "bsv/base58.h"
#include "bsv/address.h"
#include "bsv/tx.h"
#include "bsv/sighash.h"
#include "scrypt/scrypt_contract.h"
#include "scrypt/artifact_loader.h"
#include "scrypt/script_codec.h"
#include "chainSources/bsv_fees.h"
#include "provenance.h"
#include "zk/mimc7.h"

/* ----------------------------------------------------------------------------
 * Tiny test harness
 * ------------------------------------------------------------------------- */
static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;

static void pass(const char *name) { g_pass++; printf("[PASS] %s\n", name); }

static void fail_se(const char *name, const char *expected, const char *got)
{
    g_fail++;
    printf("[FAIL] %s\n", name);
    printf("    expected: %s\n", expected ? expected : "(null)");
    printf("    got:      %s\n", got ? got : "(null)");
}

static void skip(const char *name, const char *reason)
{
    g_skip++;
    printf("[SKIP] %s  (%s)\n", name, reason ? reason : "");
}

/* assert string equality */
static void chk_str(const char *name, const char *expected, const char *got)
{
    if (expected && got && strcmp(expected, got) == 0) pass(name);
    else fail_se(name, expected, got);
}

/* assert boolean predicate */
static void chk_bool(const char *name, bool cond)
{
    if (cond) pass(name);
    else fail_se(name, "true", "false");
}

/* assert int64 equality */
static void chk_i64(const char *name, int64_t expected, int64_t got)
{
    if (expected == got) pass(name);
    else {
        char eb[32], gb[32];
        snprintf(eb, sizeof eb, "%" PRId64, expected);
        snprintf(gb, sizeof gb, "%" PRId64, got);
        fail_se(name, eb, gb);
    }
}

/* ----------------------------------------------------------------------------
 * JSON convenience
 * ------------------------------------------------------------------------- */
static const cJSON *obj(const cJSON *o, const char *k)
{
    return cJSON_GetObjectItemCaseSensitive(o, k);
}
static const char *str(const cJSON *o, const char *k)
{
    const cJSON *i = obj(o, k);
    return (i && cJSON_IsString(i)) ? i->valuestring : NULL;
}

/* read whole file into a malloc'd NUL-terminated buffer; *out_len excludes NUL */
static char *read_file(const char *path, size_t *out_len)
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
    if (out_len) *out_len = rd;
    return buf;
}

/* hex-of-byte_buf helper (caller frees) */
static char *buf_hex(const byte_buf_t *b) { return hex_encode(b->data, b->len); }

/* first differing offset (in BYTES) between two hex strings; -1 if equal in the
 * overlap and same length. Reports the byte offset and the differing nibble. */
static long first_diff_byte(const char *exp, const char *got)
{
    size_t le = strlen(exp), lg = strlen(got);
    size_t n = le < lg ? le : lg;
    for (size_t i = 0; i < n; i++) {
        if (exp[i] != got[i]) return (long)(i / 2); /* byte offset */
    }
    if (le != lg) return (long)(n / 2);
    return -1;
}

/* ----------------------------------------------------------------------------
 * scrypt_arg_t builders (for locking-script reconstruction)
 * ------------------------------------------------------------------------- */
/* build an INT arg from a decimal string */
static int mk_int_dec(const char *dec, scrypt_arg_t *out)
{
    memset(out, 0, sizeof *out);
    out->tag = SCRYPT_TYPE_INT;
    return bn_parse_dec(dec, &out->as.int_val);
}
/* build an INT arg from an int64 */
static int mk_int_i64(int64_t v, scrypt_arg_t *out)
{
    char dec[32];
    snprintf(dec, sizeof dec, "%" PRId64, v);
    return mk_int_dec(dec, out);
}
/* build a bytes-family arg (PubKey/Sha256/bytes) from a hex string */
static int mk_bytes_hex(scrypt_type_t tag, const char *hex, scrypt_arg_t *out)
{
    memset(out, 0, sizeof *out);
    out->tag = tag;
    byte_buf_init(&out->as.bytes_val);
    return hex_decode(hex, &out->as.bytes_val);
}

/* ============================================================================
 *  Areas
 * ========================================================================= */

/* --- provenance ------------------------------------------------------------ */
static void area_provenance(const cJSON *root)
{
    const cJSON *p = obj(root, "provenance");
    if (!p) { skip("provenance", "missing area"); return; }
    const cJSON *in = obj(p, "input");

    provenance_record_t rec = {
        .dataset_id  = str(in, "datasetId"),
        .model_id    = str(in, "modelId"),
        .version     = str(in, "version"),
        .licence_tag = str(in, "licenceTag"),
    };

    /* provenance_preimage hex */
    byte_buf_t pre; byte_buf_init(&pre);
    int rc = provenance_preimage(&rec, &pre);
    if (rc == BNS_OK) {
        char *h = buf_hex(&pre);
        chk_str("provenance.preimage_hex", str(p, "provenancePreimage_hex"), h);
        free(h);
    } else {
        fail_se("provenance.preimage_hex", str(p, "provenancePreimage_hex"), "(error)");
    }
    byte_buf_free(&pre);

    /* compute_provenance_hash */
    char *ph = NULL;
    rc = compute_provenance_hash(&rec, &ph);
    if (rc == BNS_OK) {
        chk_str("provenance.computeProvenanceHash", str(p, "computeProvenanceHash_hex"), ph);
        free(ph);
    } else {
        fail_se("provenance.computeProvenanceHash", str(p, "computeProvenanceHash_hex"), "(error)");
    }

    /* ZERO_PROVENANCE sentinel */
    chk_str("provenance.ZERO_PROVENANCE", str(p, "ZERO_PROVENANCE_hex"), BONSAI_ZERO_PROVENANCE);
}

/* --- intEncoders ----------------------------------------------------------- */
static void area_int_encoders(const cJSON *root)
{
    const cJSON *ie = obj(root, "intEncoders");
    if (!ie) { skip("intEncoders", "missing area"); return; }

    /* int2ByteString minimal */
    const cJSON *mins = obj(ie, "int2ByteString_minimal");
    int n = cJSON_GetArraySize(mins);
    for (int i = 0; i < n; i++) {
        const cJSON *v = cJSON_GetArrayItem(mins, i);
        const char *input = str(v, "input");
        const char *exp = str(v, "int2ByteString_hex");
        char name[96];
        snprintf(name, sizeof name, "int2bytestring_minimal(%s)", input);
        bn_t *bn = NULL;
        if (bn_parse_dec(input, &bn) != BNS_OK) { fail_se(name, exp, "(parse err)"); continue; }
        byte_buf_t out; byte_buf_init(&out);
        int rc = int2bytestring_minimal(bn, &out);
        if (rc == BNS_OK) { char *h = buf_hex(&out); chk_str(name, exp, h); free(h); }
        else fail_se(name, exp, "(error)");
        byte_buf_free(&out); bn_free(bn);
    }

    /* num2bin_vectors: sized fixed-width; entries with "error" expect BNS_ERANGE */
    const cJSON *nb = obj(ie, "num2bin_vectors");
    n = cJSON_GetArraySize(nb);
    for (int i = 0; i < n; i++) {
        const cJSON *v = cJSON_GetArrayItem(nb, i);
        const char *input = str(v, "input");
        const cJSON *wj = obj(v, "width");
        long width = wj ? (long)wj->valuedouble : 0;
        const cJSON *errj = obj(v, "error");
        char name[96];
        snprintf(name, sizeof name, "num2bin(%s,%ld)", input, width);
        bn_t *bn = NULL;
        if (bn_parse_dec(input, &bn) != BNS_OK) { fail_se(name, "(valid)", "(parse err)"); continue; }
        byte_buf_t out; byte_buf_init(&out);
        int rc = int2bytestring_sized(bn, (size_t)width, &out);
        if (errj) {
            /* expect BNS_ERANGE */
            char en[128]; snprintf(en, sizeof en, "%s [overflow -> BNS_ERANGE]", name);
            if (rc == BNS_ERANGE) pass(en);
            else { char gb[64]; snprintf(gb, sizeof gb, "rc=%s", bns_err_name(rc));
                   fail_se(en, "BNS_ERANGE", gb); }
        } else {
            const char *exp = str(v, "num2bin_hex");
            if (rc == BNS_OK) { char *h = buf_hex(&out); chk_str(name, exp, h); free(h); }
            else { char gb[64]; snprintf(gb, sizeof gb, "rc=%s", bns_err_name(rc));
                   fail_se(name, exp, gb); }
        }
        byte_buf_free(&out); bn_free(bn);
    }

    /* int2ByteString_sized: same sized encoder, width is a STRING here */
    const cJSON *sz = obj(ie, "int2ByteString_sized");
    n = cJSON_GetArraySize(sz);
    for (int i = 0; i < n; i++) {
        const cJSON *v = cJSON_GetArrayItem(sz, i);
        const char *input = str(v, "input");
        const char *ws = str(v, "width");
        long width = ws ? strtol(ws, NULL, 10) : 0;
        const cJSON *errj = obj(v, "error");
        char name[96];
        snprintf(name, sizeof name, "int2bytestring_sized(%s,%ld)", input, width);
        bn_t *bn = NULL;
        if (bn_parse_dec(input, &bn) != BNS_OK) { fail_se(name, "(valid)", "(parse err)"); continue; }
        byte_buf_t out; byte_buf_init(&out);
        int rc = int2bytestring_sized(bn, (size_t)width, &out);
        if (errj) {
            char en[128]; snprintf(en, sizeof en, "%s [overflow -> BNS_ERANGE]", name);
            if (rc == BNS_ERANGE) pass(en);
            else { char gb[64]; snprintf(gb, sizeof gb, "rc=%s", bns_err_name(rc));
                   fail_se(en, "BNS_ERANGE", gb); }
        } else {
            const char *exp = str(v, "int2ByteString_hex");
            if (rc == BNS_OK) { char *h = buf_hex(&out); chk_str(name, exp, h); free(h); }
            else { char gb[64]; snprintf(gb, sizeof gb, "rc=%s", bns_err_name(rc));
                   fail_se(name, exp, gb); }
        }
        byte_buf_free(&out); bn_free(bn);
    }

    /* rabinSpike_signByte: int2ByteString minimal of the Rabin modulus n */
    const cJSON *rs = obj(ie, "rabinSpike_signByte");
    if (rs) {
        const char *dec = str(rs, "rabinPubKey_decimal");
        const char *exp = str(rs, "int2ByteString_hex");
        bn_t *bn = NULL;
        if (bn_parse_dec(dec, &bn) == BNS_OK) {
            byte_buf_t out; byte_buf_init(&out);
            int rc = int2bytestring_minimal(bn, &out);
            if (rc == BNS_OK) { char *h = buf_hex(&out);
                chk_str("intEncoders.rabinSpike_signByte", exp, h); free(h); }
            else fail_se("intEncoders.rabinSpike_signByte", exp, "(error)");
            byte_buf_free(&out); bn_free(bn);
        } else fail_se("intEncoders.rabinSpike_signByte", exp, "(parse err)");
    }
}

/* --- mimc7 ----------------------------------------------------------------- */
static void area_mimc7(const cJSON *root)
{
    const cJSON *m = obj(root, "mimc7");
    if (!m) { skip("mimc7", "missing area"); return; }
    const cJSON *in = obj(m, "input");
    const char *limit = str(in, "limit");
    const char *salt  = str(in, "salt");
    const char *exp   = str(m, "mimc7_hash_decimal");

    bn_t *x = NULL, *k = NULL, *h = NULL;
    if (bn_parse_dec(limit, &x) != BNS_OK || bn_parse_dec(salt, &k) != BNS_OK) {
        fail_se("mimc7.hash(1000,42)", exp, "(parse err)");
    } else {
        int rc = mimc7_hash(x, k, &h);
        if (rc == BNS_OK) {
            char *dec = NULL;
            if (bn_to_dec(h, &dec) == BNS_OK) { chk_str("mimc7.hash(1000,42)", exp, dec); free(dec); }
            else fail_se("mimc7.hash(1000,42)", exp, "(to_dec err)");
        } else fail_se("mimc7.hash(1000,42)", exp, "(error)");
    }
    bn_free(x); bn_free(k); bn_free(h);

    /* SNARK scalar field decimal */
    const char *fexp = str(m, "SNARK_SCALAR_FIELD_decimal");
    bn_t *fld = NULL;
    if (mimc7_scalar_field(&fld) == BNS_OK) {
        char *fdec = NULL;
        if (bn_to_dec(fld, &fdec) == BNS_OK) { chk_str("mimc7.SNARK_SCALAR_FIELD", fexp, fdec); free(fdec); }
        else fail_se("mimc7.SNARK_SCALAR_FIELD", fexp, "(to_dec err)");
        bn_free(fld);
    } else fail_se("mimc7.SNARK_SCALAR_FIELD", fexp, "(error)");
}

/* --- bsvFees --------------------------------------------------------------- */
static void area_bsv_fees(const cJSON *root)
{
    const cJSON *f = obj(root, "bsvFees");
    if (!f) { skip("bsvFees", "missing area"); return; }
    int64_t out;

    if (fee_for_size(250, 50, &out) == BNS_OK)
        chk_i64("fee_for_size(250,50)", (int64_t)obj(f, "feeForSize_250_at_50")->valuedouble, out);
    else fail_se("fee_for_size(250,50)", "13", "(error)");

    if (fee_for_size(1000, 50, &out) == BNS_OK)
        chk_i64("fee_for_size(1000,50)", (int64_t)obj(f, "feeForSize_1000_at_50")->valuedouble, out);
    else fail_se("fee_for_size(1000,50)", "50", "(error)");

    const cJSON *w = obj(f, "sendTimeFeeWindow_250_at_50");
    fee_window_t fw;
    if (send_time_fee_window(250, 50, &fw) == BNS_OK) {
        chk_i64("send_time_fee_window(250,50).min", (int64_t)obj(w, "min")->valuedouble, fw.min);
        chk_i64("send_time_fee_window(250,50).max", (int64_t)obj(w, "max")->valuedouble, fw.max);
        chk_i64("send_time_fee_window(250,50).recommended",
                (int64_t)obj(w, "recommended")->valuedouble, fw.recommended);
    } else {
        fail_se("send_time_fee_window(250,50)", "{13,39,17}", "(error)");
    }

    /* bonus: cpfp_child_fee sample (in golden) */
    const cJSON *c = obj(f, "cpfpChildFee_sample");
    if (c) {
        const cJSON *ci = obj(c, "input");
        int64_t cv;
        if (cpfp_child_fee((int64_t)obj(ci,"parentBytes")->valuedouble,
                           (int64_t)obj(ci,"parentFeePaid")->valuedouble,
                           (int64_t)obj(ci,"childBytes")->valuedouble,
                           (int64_t)obj(ci,"targetFeerate")->valuedouble, &cv) == BNS_OK)
            chk_i64("cpfp_child_fee(sample)", (int64_t)obj(c,"output")->valuedouble, cv);
        else fail_se("cpfp_child_fee(sample)", "546", "(error)");
    }
}

/* --- bignum regression (signature_s decimal<->hex roundtrip) --------------- */
static void area_bignum(const cJSON *root)
{
    const cJSON *r = obj(root, "rabin");
    if (!r) { skip("bignum.signature_s_roundtrip", "no rabin area"); return; }
    const char *sdec = str(r, "signature_s_decimal");
    const char *shex = str(r, "signature_s_hex");
    if (!sdec || !shex) { skip("bignum.signature_s_roundtrip", "missing fields"); return; }

    /* decimal -> hex */
    bn_t *bn = NULL;
    if (bn_parse_dec(sdec, &bn) == BNS_OK) {
        char *h = NULL;
        if (bn_to_hex(bn, &h) == BNS_OK) { chk_str("bignum.signature_s dec->hex", shex, h); free(h); }
        else fail_se("bignum.signature_s dec->hex", shex, "(to_hex err)");
        bn_free(bn);
    } else fail_se("bignum.signature_s dec->hex", shex, "(parse err)");

    /* hex -> decimal */
    bn = NULL;
    if (bn_parse_hex(shex, &bn) == BNS_OK) {
        char *d = NULL;
        if (bn_to_dec(bn, &d) == BNS_OK) { chk_str("bignum.signature_s hex->dec", sdec, d); free(d); }
        else fail_se("bignum.signature_s hex->dec", sdec, "(to_dec err)");
        bn_free(bn);
    } else fail_se("bignum.signature_s hex->dec", sdec, "(parse err)");
}

/* --- rabin ----------------------------------------------------------------- */
static void area_rabin(const cJSON *root)
{
    const cJSON *r = obj(root, "rabin");
    if (!r) { skip("rabin", "missing area"); return; }

    const char *msg_hex = str(r, "message_hex");
    const char *n_dec   = str(r, "pubKey_n_decimal");
    const char *s_hex   = str(r, "signature_s_hex");
    const cJSON *pbcj   = obj(r, "paddingByteCount");
    size_t padding = pbcj ? (size_t)pbcj->valuedouble : 0;

    byte_buf_t msg; byte_buf_init(&msg);
    bn_t *n = NULL, *s = NULL;
    int ok_setup = (hex_decode(msg_hex, &msg) == BNS_OK)
                && (bn_parse_dec(n_dec, &n) == BNS_OK)
                && (bn_parse_hex(s_hex, &s) == BNS_OK);

    /* rabin_verify(golden) == true */
    if (ok_setup) {
        rabin_sig_t sig = { .s = s, .padding_byte_count = padding };
        bool v = rabin_verify(msg.data, msg.len, &sig, n);
        chk_bool("rabin_verify(golden) == true", v);
    } else {
        fail_se("rabin_verify(golden) == true", "true", "(setup err)");
    }

    /* rabin_hash intermediate == golden decimal. The golden rabin_hash_decimal is
     * rabinHashBytes(message) over the RAW (un-padded) message — the
     * paddingByteCount is added inside sign/verify, not in this hash vector. */
    const char *rh_exp = str(r, "rabin_hash_decimal");
    if (rh_exp && ok_setup) {
        bn_t *rh = NULL;
        if (rabin_hash(msg.data, msg.len, &rh) == BNS_OK) {
            char *d = NULL;
            if (bn_to_dec(rh, &d) == BNS_OK) {
                chk_str("rabin_hash(message) == golden", rh_exp, d);
                free(d);
            } else fail_se("rabin_hash(message) == golden", rh_exp, "(to_dec err)");
            bn_free(rh);
        } else fail_se("rabin_hash(message) == golden", rh_exp, "(error)");
    } else {
        skip("rabin_hash(message) == golden", "no rabin_hash golden / setup err");
    }

    /* rabin_sign from fixed (p,q): reproduce s + paddingByteCount */
    const char *p_dec = str(r, "privKey_p_decimal");
    const char *q_dec = str(r, "privKey_q_decimal");
    if (p_dec && q_dec && ok_setup) {
        rabin_key_t key = {0};
        bn_t *p = NULL, *q = NULL;
        if (bn_parse_dec(p_dec, &p) == BNS_OK && bn_parse_dec(q_dec, &q) == BNS_OK) {
            key.p = p; key.q = q;
            rabin_sig_t out = {0};
            int rc = rabin_sign(msg.data, msg.len, &key, &out);
            if (rc == BNS_OK) {
                char *got_hex = NULL;
                if (out.s && bn_to_hex(out.s, &got_hex) == BNS_OK) {
                    chk_str("rabin_sign(p,q).s == golden", s_hex, got_hex);
                    free(got_hex);
                } else fail_se("rabin_sign(p,q).s == golden", s_hex, "(to_hex err)");
                chk_i64("rabin_sign(p,q).paddingByteCount", (int64_t)padding,
                        (int64_t)out.padding_byte_count);
                rabin_sig_free(&out);
            } else {
                fail_se("rabin_sign(p,q).s == golden", s_hex, "(sign error)");
                fail_se("rabin_sign(p,q).paddingByteCount", "1", "(sign error)");
            }
        } else {
            fail_se("rabin_sign(p,q).s == golden", s_hex, "(pq parse err)");
        }
        rabin_key_free(&key); /* frees p,q */
    } else {
        skip("rabin_sign(p,q)", "no fixed (p,q) in golden / setup err");
    }

    /* derived pubKey n = p*q matches golden pubKey_n_decimal */
    if (p_dec && q_dec) {
        bn_t *p = NULL, *q = NULL;
        if (bn_parse_dec(p_dec, &p) == BNS_OK && bn_parse_dec(q_dec, &q) == BNS_OK) {
            rabin_key_t key = { .p = p, .q = q };
            bn_t *npk = NULL;
            if (rabin_pubkey(&key, &npk) == BNS_OK) {
                char *d = NULL;
                if (bn_to_dec(npk, &d) == BNS_OK) {
                    chk_str("rabin_pubkey(p,q) == n", n_dec, d);
                    free(d);
                } else fail_se("rabin_pubkey(p,q) == n", n_dec, "(to_dec err)");
                bn_free(npk);
            } else fail_se("rabin_pubkey(p,q) == n", n_dec, "(error)");
            rabin_key_free(&key);
        }
    }

    byte_buf_free(&msg);
    bn_free(n); bn_free(s);
}

/* --- ecdsa + address + base58 ---------------------------------------------- */
static void area_ecdsa_address(const cJSON *root)
{
    const cJSON *t = obj(root, "txSighashAddress");
    if (!t) { skip("ecdsa/address", "missing area"); return; }

    const char *wif_main = str(t, "wif_mainnet");
    const char *wif_test = str(t, "wif_testnet");
    const char *pub_exp  = str(t, "compressed_pubkey_hex");
    const char *addr_main= str(t, "p2pkh_address_mainnet");
    const char *addr_test= str(t, "p2pkh_address_testnet");

    /* WIF mainnet -> compressed pubkey hex */
    ecdsa_key_t *key = NULL;
    bool compressed = false;
    if (ecdsa_key_from_wif(wif_main, &key, &compressed) == BNS_OK) {
        ecdsa_pubkey_t *pub = NULL;
        if (ecdsa_key_derive_pubkey(key, &pub) == BNS_OK) {
            char *ph = NULL;
            if (ecdsa_pubkey_to_hex(pub, &ph) == BNS_OK) {
                chk_str("ecdsa: WIF(main) -> compressed pubkey hex", pub_exp, ph);
                free(ph);
            } else fail_se("ecdsa: WIF(main) -> compressed pubkey hex", pub_exp, "(to_hex err)");

            /* pubkey -> P2PKH mainnet address */
            char *am = NULL;
            if (address_from_pubkey(pub, BSV_MAINNET, &am) == BNS_OK) {
                chk_str("address: pubkey -> P2PKH mainnet", addr_main, am);
                free(am);
            } else fail_se("address: pubkey -> P2PKH mainnet", addr_main, "(error)");

            /* pubkey -> P2PKH testnet address */
            char *at = NULL;
            if (address_from_pubkey(pub, BSV_TESTNET, &at) == BNS_OK) {
                chk_str("address: pubkey -> P2PKH testnet", addr_test, at);
                free(at);
            } else fail_se("address: pubkey -> P2PKH testnet", addr_test, "(error)");

            ecdsa_pubkey_free(pub);
        } else fail_se("ecdsa: WIF(main) -> compressed pubkey hex", pub_exp, "(derive err)");
        ecdsa_key_free(key);
    } else fail_se("ecdsa: WIF(main) -> compressed pubkey hex", pub_exp, "(WIF parse err)");

    /* WIF roundtrip: decode mainnet WIF secret, re-encode -> same WIF (both nets) */
    uint8_t secret[32]; bool comp; bsv_network_t net;
    if (wif_decode(wif_main, secret, &comp, &net) == BNS_OK) {
        char *re = NULL;
        if (wif_encode(secret, comp, BSV_MAINNET, &re) == BNS_OK) {
            chk_str("wif: mainnet decode->encode roundtrip", wif_main, re);
            free(re);
        } else fail_se("wif: mainnet decode->encode roundtrip", wif_main, "(encode err)");
        char *ret = NULL;
        if (wif_encode(secret, comp, BSV_TESTNET, &ret) == BNS_OK) {
            chk_str("wif: testnet re-encode == golden testnet WIF", wif_test, ret);
            free(ret);
        } else fail_se("wif: testnet re-encode == golden testnet WIF", wif_test, "(encode err)");
    } else fail_se("wif: mainnet decode->encode roundtrip", wif_main, "(decode err)");

    /* base58check roundtrip on the mainnet address payload */
    byte_buf_t payload; byte_buf_init(&payload);
    if (base58check_decode(addr_main, &payload) == BNS_OK) {
        char *re = NULL;
        if (base58check_encode(payload.data, payload.len, &re) == BNS_OK) {
            chk_str("base58check: address decode->encode roundtrip", addr_main, re);
            free(re);
        } else fail_se("base58check: address decode->encode roundtrip", addr_main, "(encode err)");
    } else fail_se("base58check: address decode->encode roundtrip", addr_main, "(decode err)");
    byte_buf_free(&payload);

    /* charter signature: ecdsa_verify of golden DER over sha256(canonicalContractBytes) */
    const cJSON *rc = obj(root, "ricardianCharter");
    if (rc) {
        const char *cb_hex   = str(rc, "canonicalContractBytes_hex");
        const char *rhash    = str(rc, "ricardianHash_hex");
        const cJSON *sgn     = obj(rc, "sign");
        const char *der_hex  = sgn ? str(sgn, "signature_der_hex") : NULL;
        const char *issuer   = sgn ? str(sgn, "issuerPubKey_hex")  : NULL;
        if (cb_hex && rhash && der_hex && issuer) {
            /* 1. sha256(canonicalContractBytes) == ricardianHash */
            byte_buf_t cb; byte_buf_init(&cb);
            if (hex_decode(cb_hex, &cb) == BNS_OK) {
                uint8_t dig[BONSAI_SHA256_LEN];
                sha256(cb.data, cb.len, dig);
                char *dh = hex_encode(dig, sizeof dig);
                chk_str("charter: sha256(canonicalContractBytes) == ricardianHash", rhash, dh);

                /* 2. ecdsa_verify(DER, digest, issuerPubKey) (single-hash charter) */
                byte_buf_t der; byte_buf_init(&der);
                ecdsa_pubkey_t *ip = NULL;
                if (hex_decode(der_hex, &der) == BNS_OK
                    && ecdsa_pubkey_from_hex(issuer, &ip) == BNS_OK) {
                    bool v = ecdsa_verify(dig, der.data, der.len, ip);
                    chk_bool("charter: ecdsa_verify(DER, digest, issuerPubKey) == true", v);
                } else {
                    fail_se("charter: ecdsa_verify(DER, digest, issuerPubKey) == true",
                            "true", "(setup err)");
                }
                free(dh);
                byte_buf_free(&der);
                ecdsa_pubkey_free(ip);
            } else {
                fail_se("charter: sha256(canonicalContractBytes) == ricardianHash",
                        rhash, "(hex decode err)");
            }
            byte_buf_free(&cb);
        } else {
            skip("charter: ecdsa_verify", "golden charter signature fields missing");
        }
    }
}

/* --- tx + sighash ---------------------------------------------------------- */
static void area_tx_sighash(const cJSON *root)
{
    const cJSON *t = obj(root, "txSighashAddress");
    if (!t) { skip("tx/sighash", "missing area"); return; }

    const char *raw_hex = str(t, "tx_raw_hex");
    const char *txid_exp= str(t, "txid");

    /* tx_deserialize then tx_serialize roundtrips to the same hex */
    bsv_tx_t tx; tx_init(&tx);
    if (tx_deserialize(raw_hex, &tx) == BNS_OK) {
        byte_buf_t ser; byte_buf_init(&ser);
        if (tx_serialize(&tx, &ser) == BNS_OK) {
            char *h = buf_hex(&ser);
            chk_str("tx: deserialize->serialize roundtrip", raw_hex, h);
            free(h);
        } else fail_se("tx: deserialize->serialize roundtrip", raw_hex, "(serialize err)");
        byte_buf_free(&ser);

        /* tx_id == golden txid */
        char *id = NULL;
        if (tx_id(&tx, &id) == BNS_OK) {
            chk_str("tx: tx_id == golden txid", txid_exp, id);
            free(id);
        } else fail_se("tx: tx_id == golden txid", txid_exp, "(txid err)");

        tx_free(&tx);
    } else {
        fail_se("tx: deserialize->serialize roundtrip", raw_hex, "(deserialize err)");
        fail_se("tx: tx_id == golden txid", txid_exp, "(deserialize err)");
    }

    /* bip143 preimage == golden */
    const char *pre_exp = str(t, "bip143_forkid_sighash_preimage_hex");
    const cJSON *ti = obj(t, "tx_input");
    if (pre_exp && ti) {
        const char *script_hex = str(ti, "prevScript_hex");
        const cJSON *satsj = obj(ti, "prevSats");
        uint64_t sats = satsj ? (uint64_t)satsj->valuedouble : 0;
        const cJSON *shtj = obj(t, "sighash_type");
        uint8_t shtype = shtj ? (uint8_t)shtj->valuedouble : BONSAI_SIGHASH_ALL_FORKID;

        bsv_tx_t tx2; tx_init(&tx2);
        byte_buf_t sc; byte_buf_init(&sc);
        if (tx_deserialize(raw_hex, &tx2) == BNS_OK && hex_decode(script_hex, &sc) == BNS_OK) {
            byte_buf_t pre; byte_buf_init(&pre);
            int rc = bip143_preimage(&tx2, 0, sc.data, sc.len, sats, shtype, &pre);
            if (rc == BNS_OK) {
                char *h = buf_hex(&pre);
                chk_str("sighash: bip143 preimage == golden", pre_exp, h);
                free(h);
            } else fail_se("sighash: bip143 preimage == golden", pre_exp, "(preimage err)");
            byte_buf_free(&pre);
        } else {
            fail_se("sighash: bip143 preimage == golden", pre_exp, "(setup err)");
        }
        byte_buf_free(&sc);
        tx_free(&tx2);
    } else {
        skip("sighash: bip143 preimage", "no preimage/tx_input golden");
    }
}

/* --- LOCKING SCRIPTS (the linchpin) ---------------------------------------- */

/* Compare a reconstructed locking script (byte_buf) against an expected hex,
 * reporting the first differing byte offset on mismatch. */
static void chk_locking(const char *name, const char *exp_hex, const byte_buf_t *got)
{
    char *got_hex = buf_hex(got);
    if (got_hex && strcmp(exp_hex, got_hex) == 0) {
        pass(name);
    } else {
        g_fail++;
        printf("[FAIL] %s\n", name);
        long off = first_diff_byte(exp_hex, got_hex ? got_hex : "");
        size_t le = strlen(exp_hex), lg = got_hex ? strlen(got_hex) : 0;
        printf("    expected length: %zu bytes\n", le / 2);
        printf("    got      length: %zu bytes\n", lg / 2);
        if (off >= 0) {
            printf("    first differing byte offset: %ld\n", off);
            /* print a small window around the diff for diagnosis */
            long start = off * 2 - 8; if (start < 0) start = 0;
            char ewin[33] = {0}, gwin[33] = {0};
            strncpy(ewin, exp_hex + start, 32);
            if (got_hex && (size_t)start < lg) strncpy(gwin, got_hex + start, 32);
            printf("    expected @%ld: ...%s...\n", start / 2, ewin);
            printf("    got      @%ld: ...%s...\n", start / 2, gwin);
        }
    }
    free(got_hex);
}

static void area_locking_scripts(const cJSON *root)
{
    const cJSON *ls = obj(root, "lockingScripts");
    if (!ls) { skip("lockingScripts", "missing area"); return; }

    /* ---- RicardianTea (50286 hex) ---- */
    {
        const cJSON *rt = obj(ls, "ricardianTea");
        const cJSON *in = obj(rt, "inputs");
        const char *exp_hex = str(rt, "lockingScript_hex");

        scrypt_artifact_t art; memset(&art, 0, sizeof art);
        int rc = load_artifact("artifacts/ricardianTea.json", &art);
        if (rc != BNS_OK) {
            fail_se("lockingScripts.RicardianTea", "50286-hex", "(load_artifact err)");
        } else {
            const cJSON *ch = obj(in, "charter");
            /* 13 ctor args in @prop order. NOTE: every int input in the golden is
             * a JSON STRING (e.g. "100000"), so read via str()+mk_int_dec. */
            scrypt_arg_t cv[13]; memset(cv, 0, sizeof cv);
            int ok = 1;
            ok &= mk_bytes_hex(SCRYPT_TYPE_PUBKEY, str(in,"elderPubKey_hex"), &cv[0]) == BNS_OK; /* owner=elder */
            ok &= mk_bytes_hex(SCRYPT_TYPE_PUBKEY, str(in,"agentPubKey_hex"), &cv[1]) == BNS_OK;
            ok &= mk_bytes_hex(SCRYPT_TYPE_SHA256, str(rt,"ricardianHash_hex"), &cv[2]) == BNS_OK;
            ok &= mk_int_dec(str(ch,"perTxLimit"), &cv[3]) == BNS_OK;
            ok &= mk_int_dec(str(ch,"dailyLimit"), &cv[4]) == BNS_OK;
            ok &= mk_int_dec(str(ch,"windowDuration"), &cv[5]) == BNS_OK;
            ok &= mk_int_dec(str(ch,"graduationThreshold"), &cv[6]) == BNS_OK;
            ok &= mk_int_dec(str(ch,"validatorThreshold"), &cv[7]) == BNS_OK;
            ok &= mk_int_dec(str(in,"designatedValidatorPubKey_decimal"), &cv[8]) == BNS_OK;
            ok &= mk_int_dec(str(in,"validatorRabinPubKey_decimal"), &cv[9]) == BNS_OK;
            ok &= mk_int_dec(str(in,"maxSlashingTarget"), &cv[10]) == BNS_OK;
            ok &= mk_int_dec(str(in,"minSlashConfirmations"), &cv[11]) == BNS_OK;
            ok &= mk_bytes_hex(SCRYPT_TYPE_SHA256, str(in,"initialSlashCheckpointHash_hex"), &cv[12]) == BNS_OK;

            /* 5 state values (genesis): txCount=0, spentInWindow=0, windowStart=0,
             * tier=1, slashCheckpointHash=initialSlashCheckpointHash */
            scrypt_arg_t sv[5]; memset(sv, 0, sizeof sv);
            ok &= mk_int_i64(0, &sv[0]) == BNS_OK;
            ok &= mk_int_i64(0, &sv[1]) == BNS_OK;
            ok &= mk_int_i64(0, &sv[2]) == BNS_OK;
            ok &= mk_int_i64(1, &sv[3]) == BNS_OK;
            ok &= mk_bytes_hex(SCRYPT_TYPE_SHA256, str(in,"initialSlashCheckpointHash_hex"), &sv[4]) == BNS_OK;

            if (!ok) {
                fail_se("lockingScripts.RicardianTea", "50286-hex", "(arg build err)");
            } else {
                byte_buf_t out; byte_buf_init(&out);
                rc = reconstruct_locking_script(&art, cv, 13, sv, 5, /*is_genesis=*/false, &out);
                if (rc == BNS_OK) chk_locking("lockingScripts.RicardianTea", exp_hex, &out);
                else { char gb[64]; snprintf(gb, sizeof gb, "rc=%s", bns_err_name(rc));
                       fail_se("lockingScripts.RicardianTea", "50286-hex", gb); }
                byte_buf_free(&out);
            }
            for (int i = 0; i < 13; i++) scrypt_arg_free(&cv[i]);
            for (int i = 0; i < 5; i++)  scrypt_arg_free(&sv[i]);
            scrypt_artifact_free(&art);
        }
    }

    /* ---- AgentTea (54528 hex) ---- */
    {
        const cJSON *at = obj(ls, "agentTea");
        const cJSON *in = obj(at, "inputs");
        const char *exp_hex = str(at, "lockingScript_hex");

        scrypt_artifact_t art; memset(&art, 0, sizeof art);
        int rc = load_artifact("artifacts/src/contracts-next/agentTea.json", &art);
        if (rc != BNS_OK) {
            fail_se("lockingScripts.AgentTea", "54528-hex", "(load_artifact err)");
        } else {
            /* 12 ctor args; recoveryKeys is int[3] (FixedArray). NOTE: every int
             * input in the golden is a JSON STRING -> read via str()+mk_int_dec. */
            scrypt_arg_t cv[12]; memset(cv, 0, sizeof cv);
            int ok = 1;
            ok &= mk_bytes_hex(SCRYPT_TYPE_PUBKEY, str(in,"owner_hex"), &cv[0]) == BNS_OK;
            ok &= mk_bytes_hex(SCRYPT_TYPE_PUBKEY, str(in,"agent_hex"), &cv[1]) == BNS_OK;
            ok &= mk_bytes_hex(SCRYPT_TYPE_SHA256, str(in,"ricardianHash_hex"), &cv[2]) == BNS_OK;
            ok &= mk_int_dec(str(in,"perTxLimit"), &cv[3]) == BNS_OK;
            ok &= mk_int_dec(str(in,"dailyLimit"), &cv[4]) == BNS_OK;
            ok &= mk_int_dec(str(in,"windowDuration"), &cv[5]) == BNS_OK;
            ok &= mk_int_dec(str(in,"graduationThreshold"), &cv[6]) == BNS_OK;
            ok &= mk_int_dec(str(in,"validatorThreshold"), &cv[7]) == BNS_OK;
            ok &= mk_int_dec(str(in,"designatedValidatorPubKey_decimal"), &cv[8]) == BNS_OK;
            ok &= mk_int_dec(str(in,"validatorRabinPubKey_decimal"), &cv[9]) == BNS_OK;
            /* recoveryKeys int[3] */
            const cJSON *rk = obj(in, "recoveryKeys_decimal");
            cv[10].tag = SCRYPT_TYPE_FIXED_ARRAY;
            cv[10].as.array.count = 3;
            cv[10].as.array.elems = calloc(3, sizeof(scrypt_arg_t));
            if (cv[10].as.array.elems) {
                for (int i = 0; i < 3; i++)
                    ok &= mk_int_dec(cJSON_GetArrayItem(rk, i)->valuestring,
                                     &cv[10].as.array.elems[i]) == BNS_OK;
            } else ok = 0;
            ok &= mk_int_dec(str(in,"recoveryThreshold"), &cv[11]) == BNS_OK;

            /* 6 state values (genesis): agent(PubKey), txCount=0, spentInWindow=0,
             * windowStart=0, tier=1, recoveryCount=0 (state ints are JSON strings) */
            const cJSON *is = obj(in, "initial_state");
            scrypt_arg_t sv[6]; memset(sv, 0, sizeof sv);
            ok &= mk_bytes_hex(SCRYPT_TYPE_PUBKEY, str(in,"agent_hex"), &sv[0]) == BNS_OK;
            ok &= mk_int_dec(is ? str(is,"txCount")       : "0", &sv[1]) == BNS_OK;
            ok &= mk_int_dec(is ? str(is,"spentInWindow") : "0", &sv[2]) == BNS_OK;
            ok &= mk_int_dec(is ? str(is,"windowStart")   : "0", &sv[3]) == BNS_OK;
            ok &= mk_int_dec(is ? str(is,"tier")          : "1", &sv[4]) == BNS_OK;
            ok &= mk_int_dec(is ? str(is,"recoveryCount") : "0", &sv[5]) == BNS_OK;

            if (!ok) {
                fail_se("lockingScripts.AgentTea", "54528-hex", "(arg build err)");
            } else {
                byte_buf_t out; byte_buf_init(&out);
                rc = reconstruct_locking_script(&art, cv, 12, sv, 6, /*is_genesis=*/false, &out);
                if (rc == BNS_OK) chk_locking("lockingScripts.AgentTea", exp_hex, &out);
                else { char gb[64]; snprintf(gb, sizeof gb, "rc=%s", bns_err_name(rc));
                       fail_se("lockingScripts.AgentTea", "54528-hex", gb); }
                byte_buf_free(&out);
            }
            for (int i = 0; i < 12; i++) scrypt_arg_free(&cv[i]);
            for (int i = 0; i < 6; i++)  scrypt_arg_free(&sv[i]);
            scrypt_artifact_free(&art);
        }
    }
}

/* --- reputationIndexer (tier 3+; no tier 0-2 symbol exposed) --------------- */
static void area_reputation(const cJSON *root)
{
    const cJSON *ri = obj(root, "reputationIndexer");
    if (!ri) { skip("reputationIndexer", "missing area"); return; }
    skip("reputationIndexer.reputationScore",
         "reputation_score is tier-3+ (not in the tier 0-2 lib surface)");
}

/* ============================================================================
 *  main
 * ========================================================================= */
int main(int argc, char **argv)
{
    const char *golden_path = (argc > 1) ? argv[1] : "tests/golden/golden.json";

    size_t len = 0;
    char *txt = read_file(golden_path, &len);
    if (!txt) {
        fprintf(stderr, "FATAL: cannot read golden vectors at %s\n", golden_path);
        return 2;
    }
    cJSON *root = cJSON_Parse(txt);
    free(txt);
    if (!root) {
        fprintf(stderr, "FATAL: cannot parse golden JSON\n");
        return 2;
    }

    printf("== chain_c tier 0-2 GOLDEN INTEGRATION TEST ==\n");
    printf("golden: %s\n\n", golden_path);

    printf("-- provenance --\n");        area_provenance(root);
    printf("\n-- intEncoders --\n");      area_int_encoders(root);
    printf("\n-- mimc7 --\n");            area_mimc7(root);
    printf("\n-- bsvFees --\n");          area_bsv_fees(root);
    printf("\n-- bignum regression --\n");area_bignum(root);
    printf("\n-- rabin --\n");            area_rabin(root);
    printf("\n-- ecdsa/address/base58 --\n"); area_ecdsa_address(root);
    printf("\n-- tx/sighash --\n");       area_tx_sighash(root);
    printf("\n-- lockingScripts --\n");   area_locking_scripts(root);
    printf("\n-- reputationIndexer --\n");area_reputation(root);

    cJSON_Delete(root);

    int total = g_pass + g_fail;
    printf("\n============================================================\n");
    printf("RESULT: %d/%d passed   (%d failed, %d skipped)\n",
           g_pass, total, g_fail, g_skip);
    printf("============================================================\n");

    return g_fail == 0 ? 0 : 1;
}
