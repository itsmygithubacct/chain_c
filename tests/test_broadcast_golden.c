/*
 * test_broadcast_golden.c — BYTE-EXACT golden test for the chain_c "sign +
 * finalize" layer (scrypt/contract_call.c + txbuilders/contract_sign.c).
 *
 * Self-contained C program (own main(), no Unity). Loads tests/golden/broadcast.json
 * via the in-lib cJSON, and for EACH of the 6 deterministic, tx.verify()-passing
 * transactions:
 *   ricardianTea_deploy, agentTea_deploy, agentTea_executeAction,
 *   agentTea_revoke, ricardianTea_executeTea, ricardianTea_revoke
 * it RECONSTRUCTS the tx from the recorded inputs/outputs/keys/args/funding
 * (so the change + fee + input set are pinned to the golden), drives the real C
 * sign+finalize API, and asserts the produced rawTxHex == golden rawTxHex
 * byte-for-byte.
 *
 * On FAIL it prints the first differing byte offset + ~40 bytes of context
 * (got vs expected) and which tx section (input scriptSig / output) diverges.
 *
 * Build (from chain_c/):
 *   gcc -std=c11 -D_GNU_SOURCE -Iinclude -Ithird_party/cJSON \
 *       -Ithird_party/ripemd160 -Ithird_party/mimc7_consts \
 *       tests/test_broadcast_golden.c src/scrypt/contract_call.c \
 *       src/txbuilders/contract_sign.c -Lbuild -lbonsai_chain \
 *       $(pkg-config --libs libsecp256k1 libcrypto libcurl) -lm -lpthread -o /tmp/tb
 *   /tmp/tb
 * (the lib already contains contract_call.c + contract_sign.c after a rebuild;
 *  they are listed on the command line too so the standalone build works either way.)
 *
 * The _golden suffix makes CMake treat this as a standalone harness, run with
 * WORKING_DIRECTORY == chain_c root.
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
#include "bsv/tx.h"
#include "bsv/tx_builder.h"
#include "bsv/sighash.h"
#include "scrypt/contract_call.h"
#include "txbuilders/contract_sign.h"

/* ----------------------------------------------------------------------------
 * harness
 * ------------------------------------------------------------------------- */
static int g_pass = 0;
static int g_fail = 0;

/* ----------------------------------------------------------------------------
 * JSON convenience
 * ------------------------------------------------------------------------- */
static const cJSON *obj(const cJSON *o, const char *k)
{
    return cJSON_GetObjectItemCaseSensitive(o, k);
}
static const char *jstr(const cJSON *o, const char *k)
{
    const cJSON *i = obj(o, k);
    return (i && cJSON_IsString(i)) ? i->valuestring : NULL;
}
static uint64_t ju64(const cJSON *o, const char *k)
{
    const cJSON *i = obj(o, k);
    return (i && cJSON_IsNumber(i)) ? (uint64_t)i->valuedouble : 0;
}

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

/* first differing offset (in BYTES) between two hex strings; -1 if equal. */
static long first_diff_byte(const char *exp, const char *got)
{
    size_t le = strlen(exp), lg = strlen(got);
    size_t n = le < lg ? le : lg;
    for (size_t i = 0; i < n; i++) {
        if (exp[i] != got[i]) return (long)(i / 2);
    }
    if (le != lg) return (long)(n / 2);
    return -1;
}

/* ----------------------------------------------------------------------------
 * key lookup (fixtures.keys.<role>.wif)
 * ------------------------------------------------------------------------- */
static const cJSON *g_keys; /* fixtures.keys */

static ecdsa_key_t *key_for_pubkey(const char *pubkey_hex)
{
    if (!g_keys || !pubkey_hex) return NULL;
    for (const cJSON *k = g_keys->child; k; k = k->next) {
        const char *pk = jstr(k, "pubKey_hex");
        const char *wif = jstr(k, "wif");
        if (pk && wif && strcmp(pk, pubkey_hex) == 0) {
            ecdsa_key_t *key = NULL;
            if (ecdsa_key_from_wif(wif, &key, NULL) == BNS_OK) return key;
            return NULL;
        }
    }
    return NULL;
}

/* the funder key signs every P2PKH funding input across the goldens */
static ecdsa_key_t *funder_key(void)
{
    const cJSON *f = obj(g_keys, "funder");
    const char *wif = jstr(f, "wif");
    ecdsa_key_t *k = NULL;
    if (wif && ecdsa_key_from_wif(wif, &k, NULL) == BNS_OK) return k;
    return NULL;
}

/* ----------------------------------------------------------------------------
 * structuralBreakdown lookup
 * ------------------------------------------------------------------------- */
static const cJSON *breakdown_role(const cJSON *tx, const char *role)
{
    const cJSON *us = obj(tx, "unlockingScript");
    const cJSON *bd = us ? obj(us, "structuralBreakdown") : NULL;
    if (!bd) return NULL;
    for (const cJSON *e = bd->child; e; e = e->next) {
        const char *r = jstr(e, "role");
        if (r && strcmp(r, role) == 0) return e;
    }
    return NULL;
}

/* decode the changeAddress (20-byte Ripemd160) from the breakdown into out20 */
static bool change_addr20(const cJSON *tx, uint8_t out20[20])
{
    const cJSON *e = breakdown_role(tx, "__scrypt_ts_changeAddress");
    const char *h = e ? jstr(e, "dataHex") : NULL;
    if (!h) return false;
    return hex_decode_fixed(h, out20, 20) == BNS_OK;
}

/* ----------------------------------------------------------------------------
 * build the tx skeleton from the recorded inputs[] / outputs[]
 *   - inputs added with NULL scriptSig (to be filled by the finalize layer)
 *   - sequence + locktime + version pinned to the golden
 *   - outputs added verbatim (satoshis + scriptHex)
 * Also fills the contract input's prevScriptHex/identity value via out-params.
 * ------------------------------------------------------------------------- */
static int build_skeleton(const cJSON *tx, tx_builder_t *b,
                          long *out_contract_idx,
                          byte_buf_t *out_contract_script_code,
                          uint64_t *out_identity_value)
{
    tx_builder_init(b);
    tx_builder_set_locktime(b, (uint32_t)ju64(tx, "lockTime"));
    b->tx.version = (uint32_t)ju64(tx, "version");

    *out_contract_idx = -1;
    byte_buf_init(out_contract_script_code);
    *out_identity_value = 0;

    const cJSON *inputs = obj(tx, "inputs");
    for (const cJSON *in = inputs->child; in; in = in->next) {
        const char *prev = jstr(in, "prevTxid");
        uint32_t vout = (uint32_t)ju64(in, "vout");
        uint32_t seq = (uint32_t)ju64(in, "sequence");
        if (tx_builder_add_input(b, prev, vout, NULL, 0, seq) != BNS_OK) return -1;

        const cJSON *isc = obj(in, "isContractInput");
        if (isc && cJSON_IsTrue(isc)) {
            *out_contract_idx = (long)ju64(in, "inputIndex");
            const char *psh = jstr(in, "prevScriptHex");
            if (!psh || hex_decode(psh, out_contract_script_code) != BNS_OK) return -1;
            *out_identity_value = ju64(in, "satoshis");
        }
    }

    const cJSON *outputs = obj(tx, "outputs");
    for (const cJSON *o = outputs->child; o; o = o->next) {
        const char *sh = jstr(o, "scriptHex");
        uint64_t sats = ju64(o, "satoshis");
        byte_buf_t sc;
        byte_buf_init(&sc);
        if (!sh || hex_decode(sh, &sc) != BNS_OK) { byte_buf_free(&sc); return -1; }
        int rc = tx_builder_add_output(b, sc.data, sc.len, sats);
        byte_buf_free(&sc);
        if (rc != BNS_OK) return -1;
    }
    return 0;
}

/* gather the non-contract (funding) inputs into a contract_funding_input_t array.
 * Each funding input is a P2PKH spent with the funder key; scriptCode is its
 * recorded prevScriptHex. The decoded scripts are kept alive in `scratch`. */
static size_t gather_funding(const cJSON *tx, contract_funding_input_t *fund,
                             byte_buf_t *scratch, size_t max,
                             const ecdsa_key_t *funder)
{
    size_t n = 0;
    const cJSON *inputs = obj(tx, "inputs");
    for (const cJSON *in = inputs->child; in && n < max; in = in->next) {
        const cJSON *isc = obj(in, "isContractInput");
        if (isc && cJSON_IsTrue(isc)) continue; /* skip contract input */
        const char *psh = jstr(in, "prevScriptHex");
        byte_buf_init(&scratch[n]);
        if (!psh || hex_decode(psh, &scratch[n]) != BNS_OK) continue;
        fund[n].input_index = (size_t)ju64(in, "inputIndex");
        fund[n].script_code = scratch[n].data;
        fund[n].script_code_len = scratch[n].len;
        fund[n].value = ju64(in, "satoshis");
        fund[n].key = funder;
        n++;
    }
    return n;
}

/* ----------------------------------------------------------------------------
 * per-vector report
 * ------------------------------------------------------------------------- */

/* Decode hex -> bytes; return offset (in this tx's byte stream) of the start of
 * input[i].scriptSig and output[j].script, to name the diverging section. */
static void name_section(const cJSON *tx, long byte_off, char *out, size_t out_sz)
{
    /* Walk the wire layout to locate which field contains byte_off. */
    /* 4 version + varint(nIn) */
    const cJSON *inputs = obj(tx, "inputs");
    const cJSON *outputs = obj(tx, "outputs");
    size_t nin = (size_t)cJSON_GetArraySize(inputs);
    size_t nout = (size_t)cJSON_GetArraySize(outputs);
    long off = 4;
    off += (nin < 0xfd) ? 1 : 3;
    size_t idx = 0;
    for (const cJSON *in = inputs->child; in; in = in->next, idx++) {
        off += 36; /* outpoint */
        size_t ssl = (size_t)ju64(in, "scriptSigLength");
        long var = (ssl < 0xfd) ? 1 : (ssl <= 0xffff ? 3 : 5);
        if (byte_off >= off && byte_off < off + var) {
            snprintf(out, out_sz, "input[%zu] scriptSig length varint", idx); return;
        }
        off += var;
        if (byte_off >= off && byte_off < off + (long)ssl) {
            snprintf(out, out_sz, "input[%zu] scriptSig (%s)", idx,
                     (obj(in,"isContractInput") && cJSON_IsTrue(obj(in,"isContractInput")))
                       ? "CONTRACT" : "funding P2PKH");
            return;
        }
        off += (long)ssl;
        off += 4; /* sequence */
        if (byte_off < off) { snprintf(out, out_sz, "input[%zu] sequence", idx); return; }
    }
    off += (nout < 0xfd) ? 1 : 3;
    idx = 0;
    for (const cJSON *o = outputs->child; o; o = o->next, idx++) {
        off += 8; /* satoshis */
        if (byte_off < off) { snprintf(out, out_sz, "output[%zu] satoshis", idx); return; }
        const char *sh = jstr(o, "scriptHex");
        size_t sl = sh ? strlen(sh) / 2 : 0;
        long var = (sl < 0xfd) ? 1 : 3;
        off += var;
        if (byte_off < off) { snprintf(out, out_sz, "output[%zu] script length", idx); return; }
        off += (long)sl;
        if (byte_off < off) { snprintf(out, out_sz, "output[%zu] script", idx); return; }
    }
    snprintf(out, out_sz, "locktime / trailer");
}

static void report(const char *name, const cJSON *tx, const char *got_hex)
{
    const char *exp = jstr(tx, "rawTxHex");
    if (!got_hex) { g_fail++; printf("[FAIL] %s  (no output produced)\n", name); return; }
    long d = first_diff_byte(exp, got_hex);
    if (d < 0 && strlen(exp) == strlen(got_hex)) {
        g_pass++;
        printf("[PASS] %s  (%zu bytes byte-exact)\n", name, strlen(exp) / 2);
        return;
    }
    g_fail++;
    char section[96];
    name_section(tx, d, section, sizeof section);
    printf("[FAIL] %s\n", name);
    printf("    first diff at byte offset %ld  (section: %s)\n", d, section);
    printf("    got  len=%zuB  expected len=%zuB\n", strlen(got_hex)/2, strlen(exp)/2);
    /* ~40 bytes (80 hex chars) of context around the diff */
    long start = (d - 8) * 2; if (start < 0) start = 0;
    char ctx_g[96] = {0}, ctx_e[96] = {0};
    size_t lg = strlen(got_hex), le = strlen(exp);
    size_t span = 80;
    if ((size_t)start < lg) { size_t n = (lg - (size_t)start < span) ? lg - (size_t)start : span; memcpy(ctx_g, got_hex + start, n); }
    if ((size_t)start < le) { size_t n = (le - (size_t)start < span) ? le - (size_t)start : span; memcpy(ctx_e, exp + start, n); }
    printf("    got  @%ld: ...%s...\n", start/2, ctx_g);
    printf("    want @%ld: ...%s...\n", start/2, ctx_e);
}

/* ----------------------------------------------------------------------------
 * DEPLOY: just funding inputs -> recorded outputs.
 * ------------------------------------------------------------------------- */
static void do_deploy(const char *name, const cJSON *tx)
{
    tx_builder_t b;
    long cidx; byte_buf_t cs; uint64_t ival;
    if (build_skeleton(tx, &b, &cidx, &cs, &ival) != 0) {
        g_fail++; printf("[FAIL] %s  (skeleton build failed)\n", name);
        byte_buf_free(&cs); return;
    }
    byte_buf_free(&cs);

    ecdsa_key_t *funder = funder_key();
    contract_funding_input_t fund[8];
    byte_buf_t scratch[8];
    size_t nf = gather_funding(tx, fund, scratch, 8, funder);

    char *hex = NULL;
    int rc = build_contract_deploy(&b, fund, nf, &hex);
    if (rc != BNS_OK) { g_fail++; printf("[FAIL] %s  (build_contract_deploy rc=%d)\n", name, rc); }
    else report(name, tx, hex);

    free(hex);
    for (size_t i = 0; i < nf; i++) byte_buf_free(&scratch[i]);
    ecdsa_key_free(funder);
    tx_builder_free(&b);
}

/* ----------------------------------------------------------------------------
 * REVOKE: ownerSig + preimage + changeAmount + changeAddress + selector.
 * ------------------------------------------------------------------------- */
static void do_revoke(const char *name, const cJSON *tx, int64_t selector)
{
    tx_builder_t b;
    long cidx; byte_buf_t cs; uint64_t ival;
    if (build_skeleton(tx, &b, &cidx, &cs, &ival) != 0 || cidx < 0) {
        g_fail++; printf("[FAIL] %s  (skeleton/contract-input build failed)\n", name);
        byte_buf_free(&cs); tx_builder_free(&b); return;
    }

    /* owner key from methodArgValues.owner_hex */
    const cJSON *mav = obj(tx, "methodArgValues");
    ecdsa_key_t *owner = key_for_pubkey(jstr(mav, "owner_hex"));

    /* change amount = the change output satoshis (last output); changeAddress from breakdown */
    const cJSON *outputs = obj(tx, "outputs");
    int nout = cJSON_GetArraySize(outputs);
    uint64_t change_sats = ju64(cJSON_GetArrayItem(outputs, nout - 1), "satoshis");
    uint8_t change20[20];
    bool have_addr = change_addr20(tx, change20);

    ecdsa_key_t *funder = funder_key();
    contract_funding_input_t fund[8];
    byte_buf_t scratch[8];
    size_t nf = gather_funding(tx, fund, scratch, 8, funder);

    char *hex = NULL;
    int rc = BNS_EINVAL;
    if (owner && have_addr) {
        rc = contract_revoke_sign(&b, (size_t)cidx, cs.data, cs.len, ival, owner,
                                  (int64_t)change_sats, change20, selector,
                                  fund, nf, &hex);
    }
    if (rc != BNS_OK) { g_fail++; printf("[FAIL] %s  (contract_revoke_sign rc=%d owner=%p addr=%d)\n",
                                         name, rc, (void*)owner, have_addr); }
    else report(name, tx, hex);

    free(hex);
    for (size_t i = 0; i < nf; i++) byte_buf_free(&scratch[i]);
    ecdsa_key_free(owner); ecdsa_key_free(funder);
    byte_buf_free(&cs); tx_builder_free(&b);
}

/* ----------------------------------------------------------------------------
 * EXECUTE: full executeAction / executeTea spend.
 * ------------------------------------------------------------------------- */
static bn_t *bn_dec(const char *dec)
{
    bn_t *bn = NULL;
    if (dec && bn_parse_dec(dec, &bn) == BNS_OK) return bn;
    /* default to 0 when absent */
    bn_parse_dec("0", &bn);
    return bn;
}

static void do_execute(const char *name, const cJSON *tx, const char *hash_field,
                       int64_t selector)
{
    tx_builder_t b;
    long cidx; byte_buf_t cs; uint64_t ival;
    if (build_skeleton(tx, &b, &cidx, &cs, &ival) != 0 || cidx < 0) {
        g_fail++; printf("[FAIL] %s  (skeleton/contract-input build failed)\n", name);
        byte_buf_free(&cs); tx_builder_free(&b); return;
    }

    const cJSON *mav = obj(tx, "methodArgValues");

    /* keys: agentSig (agent), counterpartySig (counterparty), funding (funder) */
    ecdsa_key_t *agent = key_for_pubkey(jstr(obj(g_keys, "agent"), "pubKey_hex"));
    ecdsa_key_t *cp    = key_for_pubkey(jstr(mav, "counterparty_hex"));
    ecdsa_key_t *funder = funder_key();

    /* counterparty pubkey (33B), hashes (32B), amount/attestedLimit (int) */
    uint8_t cp_pub[33], hash32[32], prov32[32];
    bool ok = (hex_decode_fixed(jstr(mav, "counterparty_hex"), cp_pub, 33) == BNS_OK)
           && (hex_decode_fixed(jstr(mav, hash_field), hash32, 32) == BNS_OK)
           && (hex_decode_fixed(jstr(mav, "provenanceHash_hex"), prov32, 32) == BNS_OK);

    bn_t *amount = bn_dec(jstr(mav, "amount"));
    bn_t *attlim = bn_dec(jstr(mav, "attestedLimit"));

    /* RabinSig dummy: s (int), padding (bytes). Default {s:0, padding:""}. */
    const cJSON *vsig = obj(mav, "validatorSig");
    bn_t *rabin_s = bn_dec(vsig ? jstr(vsig, "s") : "0");
    byte_buf_t rpad; byte_buf_init(&rpad);
    const char *pad_hex = vsig ? jstr(vsig, "padding_hex") : NULL;
    if (pad_hex && *pad_hex) hex_decode(pad_hex, &rpad);

    /* change amount = change output (last) satoshis; changeAddress from breakdown */
    const cJSON *outputs = obj(tx, "outputs");
    int nout = cJSON_GetArraySize(outputs);
    uint64_t change_sats = ju64(cJSON_GetArrayItem(outputs, nout - 1), "satoshis");
    uint8_t change20[20];
    bool have_addr = change_addr20(tx, change20);

    contract_funding_input_t fund[8];
    byte_buf_t scratch[8];
    size_t nf = gather_funding(tx, fund, scratch, 8, funder);

    contract_execute_args_t args;
    memset(&args, 0, sizeof args);
    args.agent_key = agent;
    args.counterparty_key = cp;
    args.counterparty_pub33 = cp_pub;
    args.amount = amount;
    args.hash32 = hash32;
    args.provenance_hash32 = prov32;
    args.attested_limit = attlim;
    args.rabin_s = rabin_s;
    args.rabin_padding = rpad.data;
    args.rabin_padding_len = rpad.len;

    char *hex = NULL;
    int rc = BNS_EINVAL;
    if (agent && cp && ok && have_addr) {
        rc = contract_execute_sign(&b, (size_t)cidx, cs.data, cs.len, ival, &args,
                                   (int64_t)change_sats, change20, selector,
                                   fund, nf, &hex);
    }
    if (rc != BNS_OK) { g_fail++; printf("[FAIL] %s  (contract_execute_sign rc=%d agent=%p cp=%p ok=%d addr=%d)\n",
                                         name, rc, (void*)agent, (void*)cp, ok, have_addr); }
    else report(name, tx, hex);

    free(hex);
    for (size_t i = 0; i < nf; i++) byte_buf_free(&scratch[i]);
    bn_free(amount); bn_free(attlim); bn_free(rabin_s);
    byte_buf_free(&rpad);
    ecdsa_key_free(agent); ecdsa_key_free(cp); ecdsa_key_free(funder);
    byte_buf_free(&cs); tx_builder_free(&b);
}

/* ----------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */
int main(void)
{
    size_t len = 0;
    char *txt = read_file("tests/golden/broadcast.json", &len);
    if (!txt) { fprintf(stderr, "cannot read tests/golden/broadcast.json\n"); return 2; }
    cJSON *root = cJSON_Parse(txt);
    free(txt);
    if (!root) { fprintf(stderr, "broadcast.json parse error\n"); return 2; }

    const cJSON *fixtures = obj(root, "fixtures");
    g_keys = obj(fixtures, "keys");
    const cJSON *txs = obj(root, "transactions");
    if (!g_keys || !txs) { fprintf(stderr, "missing fixtures.keys / transactions\n"); cJSON_Delete(root); return 2; }

    printf("=== broadcast.json byte-exact sign+finalize golden ===\n\n");

    /* DEPLOY (easiest) */
    do_deploy("ricardianTea_deploy", obj(txs, "ricardianTea_deploy"));
    do_deploy("agentTea_deploy",     obj(txs, "agentTea_deploy"));

    /* REVOKE (1 sig, no prevouts).  AgentTea.revoke=4, RicardianTea.revoke=3 */
    do_revoke("agentTea_revoke",     obj(txs, "agentTea_revoke"),     4);
    do_revoke("ricardianTea_revoke", obj(txs, "ricardianTea_revoke"), 3);

    /* EXECUTE (full).  executeAction#0 / executeTea#0 */
    do_execute("agentTea_executeAction", obj(txs, "agentTea_executeAction"), "actionHash_hex", 0);
    do_execute("ricardianTea_executeTea", obj(txs, "ricardianTea_executeTea"), "invoiceHash_hex", 0);

    printf("\nRESULT: %d/%d passed\n", g_pass, g_pass + g_fail);
    cJSON_Delete(root);
    return g_fail == 0 ? 0 : 1;
}
