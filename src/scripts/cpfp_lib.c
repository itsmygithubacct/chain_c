/*
 * cpfp_lib.c — logic for the cpfp CLI. Faithful C port of scripts/cpfp.ts.
 *
 * Accelerate a stuck/slow parent tx by spending one of its P2PKH outputs with a
 * high-fee child back to the funded key. Dry-run unless
 * CONFIRM_MAINNET_BROADCAST=yes. See include/scripts/cpfp.h.
 */
#include "scripts/cpfp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <errno.h>

#include "scripts/script_support.h"
#include "common/bytes.h"
#include "crypto/ecdsa.h"
#include "crypto/hash.h"
#include "bsv/address.h"
#include "bsv/tx.h"
#include "bsv/tx_builder.h"
#include "bsv/sighash.h"
#include "bsv/script_utils.h"
#include "chainSources/http_transport.h"
#include "chainSources/woc_client.h"

/* TS throw path: console.error('CPFP FAILED:', message); process.exit(1). */
static int fail(const char *msg, int *out_exit_code)
{
    fprintf(stderr, "CPFP FAILED: %s\n", msg);
    *out_exit_code = 1;
    return BNS_OK; /* the run "completed"; the exit code carries the failure */
}

/* TS: const vout = Number(process.env.VOUT). Number('') === 0 and Number(' 12 ')
 * trims, but Number('1.5')/'abc' -> NaN. We mirror the practical contract: a
 * non-negative integer index; anything else is treated as NaN -> the
 * 'set PARENT=<txid> and VOUT=<n>' throw (the TS Number.isNaN(vout) guard). */
static bool parse_vout(const char *s, long *out)
{
    if (!s) return false;
    /* Number() trims surrounding ASCII whitespace. */
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r' ||
           *s == '\f' || *s == '\v')
        s++;
    if (*s == '\0') { /* Number('') === 0, NOT NaN */
        *out = 0;
        return true;
    }
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s) return false;
    while (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r' ||
           *end == '\f' || *end == '\v')
        end++;
    if (*end != '\0') return false; /* trailing junk / float -> NaN */
    if (v < 0) return false;
    *out = v;
    return true;
}

/* Number(process.env.FEE ?? 3000): default 3000 when unset; otherwise Number(). */
static bool parse_fee(const char *s, long *out)
{
    if (!s) { *out = 3000; return true; }
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r' ||
           *s == '\f' || *s == '\v')
        s++;
    if (*s == '\0') { *out = 0; return true; } /* Number('') === 0 */
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s) return false;
    while (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r' ||
           *end == '\f' || *end == '\v')
        end++;
    if (*end != '\0') return false;
    *out = v;
    return true;
}

int cpfp_run(int argc, char **argv, int *out_exit_code)
{
    (void)argc;
    (void)argv;

    int rc = BNS_OK;
    int dummy_exit = 0;
    if (!out_exit_code) out_exit_code = &dummy_exit;
    *out_exit_code = 0;

    /* --- KEY_FILE default: $BONSAI_NOTARY_HOME/chain/test_bsv.json --------- */
    const char *key_file_env = env_get("KEY_FILE");
    char key_file_buf[2048];
    const char *key_file;
    if (key_file_env && key_file_env[0]) {
        key_file = key_file_env;
    } else {
        snprintf(key_file_buf, sizeof key_file_buf, "%s/chain/test_bsv.json",
                 bonsai_home());
        key_file = key_file_buf;
    }

    /* --- PARENT / VOUT / FEE ---------------------------------------------- */
    const char *parent = env_get("PARENT");
    long vout_l = 0, fee_l = 3000;
    bool vout_ok = parse_vout(env_get("VOUT"), &vout_l);
    bool fee_ok = parse_fee(env_get("FEE"), &fee_l);

    /* TS: if (!parent || Number.isNaN(vout)) throw 'set PARENT=<txid> and VOUT=<n>'.
     * FEE parse failure also yields NaN downstream; we surface the same throw
     * shape ('CPFP FAILED:' + message) but the spec'd line is the PARENT/VOUT
     * one, so honor that first. */
    if (!parent || !parent[0] || !vout_ok) {
        return fail("set PARENT=<txid> and VOUT=<n>", out_exit_code);
    }
    if (!fee_ok) {
        /* Number(FEE) === NaN: every downstream comparison is false, so childOut
         * (NaN) < 1000 is false and the tx math is garbage. Refuse cleanly. */
        return fail("set PARENT=<txid> and VOUT=<n>", out_exit_code);
    }
    uint32_t vout = (uint32_t)vout_l;
    long child_fee = fee_l;

    /* --- load + verify key (mainnet) -------------------------------------- */
    bonsai_err_ctx err;
    key_file_t kf;
    rc = key_file_load(key_file, &kf, &err);
    if (rc != BNS_OK) {
        return fail(err.msg[0] ? err.msg : "key file load failed", out_exit_code);
    }
    rc = key_file_verify(&kf, BSV_MAINNET, &err);
    if (rc != BNS_OK) {
        /* TS message: 'WIF/address mismatch — aborting'. script_support emits
         * 'WIF/address mismatch'; pass through its verbatim text. */
        key_file_free(&kf);
        return fail(err.msg[0] ? err.msg : "WIF/address mismatch", out_exit_code);
    }

    /* Derive the funded key's compressed pubkey + hash160 (the P2PKH target). */
    ecdsa_key_t *key = NULL;
    rc = ecdsa_key_from_wif(kf.wif, &key, NULL);
    if (rc != BNS_OK) {
        key_file_free(&kf);
        return fail("invalid WIF", out_exit_code);
    }
    ecdsa_pubkey_t *pub = NULL;
    rc = ecdsa_key_derive_pubkey(key, &pub);
    if (rc != BNS_OK) {
        ecdsa_key_free(key);
        key_file_free(&kf);
        return fail("pubkey derivation failed", out_exit_code);
    }
    uint8_t pub_comp[BONSAI_ECDSA_PUBKEY_COMPRESSED_LEN];
    rc = ecdsa_pubkey_serialize_compressed(pub, pub_comp);
    if (rc != BNS_OK) {
        ecdsa_pubkey_free(pub);
        ecdsa_key_free(key);
        key_file_free(&kf);
        return fail("pubkey serialization failed", out_exit_code);
    }
    uint8_t h160[BONSAI_HASH160_LEN];
    hash160(pub_comp, sizeof pub_comp, h160);

    /* --- WocClient (libcurl) ---------------------------------------------- */
    http_transport_t transport;
    rc = http_transport_curl(&transport);
    if (rc != BNS_OK) {
        ecdsa_pubkey_free(pub);
        ecdsa_key_free(key);
        key_file_free(&kf);
        return fail("HTTP transport init failed", out_exit_code);
    }
    woc_client_t *woc = NULL;
    woc_client_opts_t wopts = { .transport = &transport, .sleep = NULL,
                                .sleep_user = NULL };
    rc = woc_client_new(&wopts, &woc);
    if (rc != BNS_OK) {
        transport.free(transport.ctx);
        ecdsa_pubkey_free(pub);
        ecdsa_key_free(key);
        key_file_free(&kf);
        return fail("WocClient init failed", out_exit_code);
    }

    /* --- fetch parent raw tx, read outputs[vout].satoshis ----------------- */
    char *hex = NULL;
    rc = woc_client_raw_tx(woc, parent, &hex);
    if (rc != BNS_OK || hex == NULL) {
        char m[512];
        snprintf(m, sizeof m, "parent %s not found on-chain", parent);
        free(hex);
        woc_client_free(woc);
        transport.free(transport.ctx);
        ecdsa_pubkey_free(pub);
        ecdsa_key_free(key);
        key_file_free(&kf);
        return fail(m, out_exit_code);
    }

    bsv_tx_t ptx;
    tx_init(&ptx);
    rc = tx_deserialize(hex, &ptx);
    free(hex);
    if (rc != BNS_OK) {
        char m[512];
        snprintf(m, sizeof m, "parent %s not found on-chain", parent);
        tx_free(&ptx);
        woc_client_free(woc);
        transport.free(transport.ctx);
        ecdsa_pubkey_free(pub);
        ecdsa_key_free(key);
        key_file_free(&kf);
        return fail(m, out_exit_code);
    }

    if ((size_t)vout >= ptx.num_outputs) {
        char m[512];
        snprintf(m, sizeof m, "no output %s:%u", parent, vout);
        tx_free(&ptx);
        woc_client_free(woc);
        transport.free(transport.ctx);
        ecdsa_pubkey_free(pub);
        ecdsa_key_free(key);
        key_file_free(&kf);
        return fail(m, out_exit_code);
    }
    uint64_t value = ptx.outputs[vout].satoshis;
    tx_free(&ptx);

    /* --- fee math + hard safety guard ------------------------------------- */
    long child_out = (long)value - child_fee;
    if (child_out < 1000 || child_fee > 50000) {
        char m[256];
        snprintf(m, sizeof m, "refusing unsafe CPFP: out=%ld fee=%ld",
                 child_out, child_fee);
        woc_client_free(woc);
        transport.free(transport.ctx);
        ecdsa_pubkey_free(pub);
        ecdsa_key_free(key);
        key_file_free(&kf);
        return fail(m, out_exit_code);
    }

    /* --- build + sign the single-input single-output P2PKH child ----------- */
    tx_builder_t b;
    tx_builder_init(&b);

    /* input: spend PARENT:vout, initial empty scriptSig (filled after signing). */
    rc = tx_builder_add_input(&b, parent, vout, NULL, 0, 0xffffffff);
    if (rc != BNS_OK) {
        tx_builder_free(&b);
        woc_client_free(woc);
        transport.free(transport.ctx);
        ecdsa_pubkey_free(pub);
        ecdsa_key_free(key);
        key_file_free(&kf);
        return fail("add input failed", out_exit_code);
    }

    /* output: P2PKH to the funded key for childOut. */
    byte_buf_t out_script;
    byte_buf_init(&out_script);
    rc = build_p2pkh_script(h160, &out_script);
    if (rc == BNS_OK) {
        rc = tx_builder_add_output(&b, out_script.data, out_script.len,
                                   (uint64_t)child_out);
    }
    if (rc != BNS_OK) {
        byte_buf_free(&out_script);
        tx_builder_free(&b);
        woc_client_free(woc);
        transport.free(transport.ctx);
        ecdsa_pubkey_free(pub);
        ecdsa_key_free(key);
        key_file_free(&kf);
        return fail("add output failed", out_exit_code);
    }

    /* scriptCode for the prevout being spent = its P2PKH locking script (same
     * funded key) — identical to out_script. */
    uint8_t digest[BONSAI_SHA256_LEN];
    rc = bip143_sighash(&b.tx, 0, out_script.data, out_script.len, value,
                        BONSAI_SIGHASH_ALL_FORKID, digest);
    byte_buf_free(&out_script);
    if (rc != BNS_OK) {
        tx_builder_free(&b);
        woc_client_free(woc);
        transport.free(transport.ctx);
        ecdsa_pubkey_free(pub);
        ecdsa_key_free(key);
        key_file_free(&kf);
        return fail("sighash failed", out_exit_code);
    }

    byte_buf_t der;
    byte_buf_init(&der);
    rc = ecdsa_sign_low_s(digest, key, &der);
    if (rc != BNS_OK) {
        byte_buf_free(&der);
        tx_builder_free(&b);
        woc_client_free(woc);
        transport.free(transport.ctx);
        ecdsa_pubkey_free(pub);
        ecdsa_key_free(key);
        key_file_free(&kf);
        return fail("signing failed", out_exit_code);
    }

    /* scriptSig = <push (DER||0x41)> <push compressedPubkey>. Both pushes are
     * direct (length < OP_PUSHDATA1 == 0x4c). */
    byte_buf_t script_sig;
    byte_buf_init(&script_sig);
    size_t sig_push_len = der.len + 1; /* +1 for the sighash type byte */
    rc = byte_buf_append_byte(&script_sig, (uint8_t)sig_push_len);
    if (rc == BNS_OK) rc = byte_buf_append(&script_sig, der.data, der.len);
    if (rc == BNS_OK) rc = byte_buf_append_byte(&script_sig,
                                                BONSAI_SIGHASH_ALL_FORKID);
    if (rc == BNS_OK) rc = byte_buf_append_byte(&script_sig, (uint8_t)sizeof pub_comp);
    if (rc == BNS_OK) rc = byte_buf_append(&script_sig, pub_comp, sizeof pub_comp);
    byte_buf_free(&der);
    if (rc != BNS_OK) {
        byte_buf_free(&script_sig);
        tx_builder_free(&b);
        woc_client_free(woc);
        transport.free(transport.ctx);
        ecdsa_pubkey_free(pub);
        ecdsa_key_free(key);
        key_file_free(&kf);
        return fail("scriptSig build failed", out_exit_code);
    }

    /* Install the unlocking script on input 0 (the builder exposes its tx). */
    byte_buf_free(&b.tx.inputs[0].script_sig);
    rc = byte_buf_from(&b.tx.inputs[0].script_sig, script_sig.data, script_sig.len);
    byte_buf_free(&script_sig);
    if (rc != BNS_OK) {
        tx_builder_free(&b);
        woc_client_free(woc);
        transport.free(transport.ctx);
        ecdsa_pubkey_free(pub);
        ecdsa_key_free(key);
        key_file_free(&kf);
        return fail("scriptSig install failed", out_exit_code);
    }

    /* Serialize + txid. */
    char *raw = NULL;
    rc = tx_builder_build_hex(&b, &raw);
    if (rc != BNS_OK) {
        tx_builder_free(&b);
        woc_client_free(woc);
        transport.free(transport.ctx);
        ecdsa_pubkey_free(pub);
        ecdsa_key_free(key);
        key_file_free(&kf);
        return fail("serialize failed", out_exit_code);
    }
    char *txid = NULL;
    rc = tx_id(&b.tx, &txid);
    if (rc != BNS_OK) {
        free(raw);
        tx_builder_free(&b);
        woc_client_free(woc);
        transport.free(transport.ctx);
        ecdsa_pubkey_free(pub);
        ecdsa_key_free(key);
        key_file_free(&kf);
        return fail("txid failed", out_exit_code);
    }

    /* size = raw.length / 2 (bytes); feerate = round((fee/size)*1000) sats/KB. */
    size_t size_bytes = strlen(raw) / 2;
    long feerate = 0;
    if (size_bytes > 0) {
        feerate = (long)llround(((double)child_fee / (double)size_bytes) * 1000.0);
    }

    printf("CPFP child            : %s\n", txid);
    printf("spends                : %s:%u (%llu sats)\n", parent, vout,
           (unsigned long long)value);
    printf("child fee / feerate   : %ld sats / %ld sats/KB\n", child_fee, feerate);

    /* --- dry-run gate ----------------------------------------------------- */
    if (!confirm_mainnet_broadcast()) {
        printf("\nDRY RUN — set CONFIRM_MAINNET_BROADCAST=yes to send.\n");
        free(txid);
        free(raw);
        tx_builder_free(&b);
        woc_client_free(woc);
        transport.free(transport.ctx);
        ecdsa_pubkey_free(pub);
        ecdsa_key_free(key);
        key_file_free(&kf);
        *out_exit_code = 0;
        return BNS_OK;
    }

    char *bcast_txid = NULL;
    rc = woc_client_broadcast(woc, raw, &bcast_txid);
    if (rc != BNS_OK) {
        char m[512];
        snprintf(m, sizeof m, "broadcast failed: %s", bns_err_name((bonsai_err_t)rc));
        free(bcast_txid);
        free(txid);
        free(raw);
        tx_builder_free(&b);
        woc_client_free(woc);
        transport.free(transport.ctx);
        ecdsa_pubkey_free(pub);
        ecdsa_key_free(key);
        key_file_free(&kf);
        return fail(m, out_exit_code);
    }
    printf("\nBROADCAST OK: %s\n", bcast_txid);

    free(bcast_txid);
    free(txid);
    free(raw);
    tx_builder_free(&b);
    woc_client_free(woc);
    transport.free(transport.ctx);
    ecdsa_pubkey_free(pub);
    ecdsa_key_free(key);
    key_file_free(&kf);
    *out_exit_code = 0;
    return BNS_OK;
}
