/*
 * agentd_lib.c — the agentd CLI library: a RESUMABLE Pillar-B agent lifecycle
 * (deploy a stateful AgentTea identity UTXO once, then run many metered actions,
 * revoke, or report status across separate process invocations). Faithful port
 * of scripts/agentd.ts (agentDeploy / agentAction / agentRevoke + the CLI
 * dispatch).
 *
 *   deploy  — create the AgentTea identity UTXO, persist the tip (raw tx + outpoint)
 *   action  — run ONE metered action (binds actionHash=receiptHash,
 *             provenanceHash=modelHash into the Third Entry), advance state, persist
 *   revoke  — Elder kill-switch
 *   status  — print the persisted tip + state
 *
 * The state-carry trick is AgentTea.fromTx(rawTx, vout): each step reconstructs
 * the contract's on-chain @prop(true) state from the previous step's raw tx, so
 * nothing but the raw tx (in the JSON STATE_FILE) survives between runs.
 *
 * DRY-RUN unless CONFIRM_MAINNET_BROADCAST=yes (the two-key interlock). The
 * dry-run plans, env handling and error strings mirror the TS exactly.
 */
#include "scripts/agentd.h"
#include "scripts/agentd_persistence.h"
#include "scripts/agent_state.h"
#include "scripts/script_support.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include "common/bytes.h"
#include "common/hex.h"
#include "crypto/hash.h"
#include "crypto/ecdsa.h"
#include "crypto/bignum.h"
#include "crypto/rabin.h"
#include "bsv/address.h"
#include "bsv/base58.h"
#include "bsv/tx.h"
#include "bsv/tx_builder.h"
#include "bsv/script_utils.h"
#include "scrypt/artifact_loader.h"
#include "scrypt/scrypt_contract.h"
#include "contracts_next/agent_tea.h"
#include "txbuilders/agent_tea_tx_builder.h"
#include "txbuilders/contract_sign.h"
#include "chainSources/utxo_select.h"
#include "chainSources/bsv_fees.h"
#include "scripts/chain_broadcast.h"

#include <stdint.h>

/* ABI method selectors (scrypt-ts @method declaration order). TS:
 * AgentTea.executeAction#0, AgentTea.recover#3, AgentTea.revoke#4. */
#define AGENT_TEA_EXECUTE_ACTION_SELECTOR 0
#define AGENT_TEA_RECOVER_SELECTOR        3
#define AGENT_TEA_REVOKE_SELECTOR         4

/* The CLI pins bsv.Transaction.FEE_PER_KB = 100 (agentd.ts FEE_PER_KB). */
#define AGENTD_FEE_PER_KB 100

/* Value locked in the AgentTea identity UTXO (1 sat). TS: agentDeploy identitySats
 * default (DeployConfig.identitySats ?? 1). */
#define AGENTD_IDENTITY_SATS 1

/* HELP text — mirrors scripts/agentd.ts::HELP verbatim. */
static const char *HELP =
"agentd — resumable Pillar B agent lifecycle (DRY-RUN unless CONFIRM_MAINNET_BROADCAST=yes)\n"
"\n"
"  ts-node scripts/agentd.ts deploy   # create the identity, write STATE_FILE\n"
"  ts-node scripts/agentd.ts action   # one metered action under the identity (ACTION_HASH/PROVENANCE_HASH)\n"
"  ts-node scripts/agentd.ts recover  # M-of-3 social recovery: rotate the agent key to NEW_AGENT_KEY_FILE\n"
"  ts-node scripts/agentd.ts revoke   # Elder kill-switch\n"
"  ts-node scripts/agentd.ts status   # print the persisted tip + state\n"
"\n"
"Env: STATE_FILE (required), ELDER_KEY_FILE, AGENT_KEY_FILE, COUNTERPARTY_KEY_FILE, FUND_DEPLOY_KEY_FILE,\n"
"     FUND_ACTION_KEY_FILE, FUND_REVOKE_KEY_FILE (defaults to FUND_ACTION_KEY_FILE), CHANGE_ADDRESS,\n"
"     RICARDIAN_HASH, ACTION_HASH, PROVENANCE_HASH, AMOUNT, NETWORK (main|test), CONFIRM_MAINNET_BROADCAST.\n"
"     recover: NEW_AGENT_KEY_FILE (required; the rotated-to agent keyfile), FUND_RECOVER_KEY_FILE\n"
"     (defaults to FUND_ACTION_KEY_FILE). Guardian sigs come from RECOVER_SIGS_FILE (3 lines\n"
"     '<used 0|1> <s_hex|-> <paddingByteCount>'), or are self-signed from <STATE_FILE>.recovery_keys\n"
"     when deploy was run with AGENTD_PERSIST_RECOVERY_KEYS=yes (operator-custodial recovery).\n"
"     Key files are bonsai-notary {wif,address} JSON.";

/* The agentd top-level catch: "agentd FAILED: <msg>" on stderr, exit 1. */
static int agentd_failed(const char *msg, int *out_exit_code)
{
    fprintf(stderr, "agentd FAILED: %s\n", msg ? msg : "");
    if (out_exit_code) *out_exit_code = 1;
    return BNS_OK;
}

/* assertHash32: /^[0-9a-fA-F]{64}$/ then toLowerCase(); else throw the exact TS
 * message. On success writes a freshly malloc'd lowercase 64-hex to *out. */
static int assert_hash32(const char *name, const char *value, char **out, char *errmsg, size_t errsz)
{
    *out = NULL;
    size_t n = value ? strlen(value) : 0;
    bool ok = (n == 64);
    for (size_t i = 0; ok && i < n; i++) {
        char c = value[i];
        if (!isxdigit((unsigned char)c)) ok = false;
    }
    if (!ok) {
        snprintf(errmsg, errsz, "%s must be a 32-byte hex string (64 hex chars), got '%s'", name, value ? value : "");
        return BNS_EINVAL;
    }
    char *lower = malloc(65);
    if (lower == NULL) return BNS_ENOMEM;
    for (size_t i = 0; i < 64; i++) lower[i] = (char)tolower((unsigned char)value[i]);
    lower[64] = '\0';
    *out = lower;
    return BNS_OK;
}

/* Read an entire file into a freshly malloc'd NUL-terminated string. */
static int read_file(const char *path, char **out)
{
    *out = NULL;
    FILE *f = fopen(path, "rb");
    if (f == NULL) return BNS_EPERSIST;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return BNS_EPERSIST; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return BNS_EPERSIST; }
    rewind(f);
    char *buf = malloc((size_t)sz + 1);
    if (buf == NULL) { fclose(f); return BNS_ENOMEM; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';
    *out = buf;
    return BNS_OK;
}

/* Report a journal failure immediately after an accepted broadcast, then keep
 * going: the durable atomic state write is an independent recovery record. */
static void persist_broadcast_journal(const char *state_file, const char *tag,
                                      const char *txid)
{
    if (agentd_journal_broadcast(state_file, tag, txid) != BNS_OK)
        fprintf(stderr, "agentd WARNING: broadcast %s accepted as %s, but the durable txid journal "
                        "could not be written; attempting the state file\n", tag, txid);
}

/* loadKey: parse {wif,address} JSON, fromWIF, assert it derives the address on
 * `net`. Mirrors agentd.ts::loadKey (error: "WIF in <file> does not derive <addr>").
 * On success *out_key (caller ecdsa_key_free) + *out_addr (caller free). */
static int load_key(const char *file, bsv_network_t net,
                    ecdsa_key_t **out_key, char **out_addr,
                    char *errmsg, size_t errsz)
{
    *out_key = NULL;
    if (out_addr) *out_addr = NULL;

    key_file_t kf;
    memset(&kf, 0, sizeof kf);
    bonsai_err_ctx ctx;
    memset(&ctx, 0, sizeof ctx);

    int rc = key_file_load(file, &kf, &ctx);
    if (rc != BNS_OK) {
        snprintf(errmsg, errsz, "%s", ctx.msg[0] ? ctx.msg : "cannot read key file");
        return rc;
    }

    ecdsa_key_t *key = NULL;
    rc = ecdsa_key_from_wif(kf.wif, &key, NULL);
    if (rc != BNS_OK) {
        snprintf(errmsg, errsz, "invalid WIF in %s", file);
        key_file_free(&kf);
        return rc;
    }

    /* Derive the address on `net` and compare to the recorded one. */
    ecdsa_pubkey_t *pub = NULL;
    rc = ecdsa_key_derive_pubkey(key, &pub);
    if (rc != BNS_OK) { ecdsa_key_free(key); key_file_free(&kf); return rc; }

    char *addr = NULL;
    rc = address_from_pubkey(pub, net, &addr);
    ecdsa_pubkey_free(pub);
    if (rc != BNS_OK) { ecdsa_key_free(key); key_file_free(&kf); return rc; }

    if (kf.address == NULL || strcmp(addr, kf.address) != 0) {
        snprintf(errmsg, errsz, "WIF in %s does not derive %s", file, kf.address ? kf.address : "");
        free(addr);
        ecdsa_key_free(key);
        key_file_free(&kf);
        return BNS_EBINDING;
    }

    key_file_free(&kf);
    *out_key = key;
    if (out_addr) *out_addr = addr; else free(addr);
    return BNS_OK;
}

/* ------------------------------------------------------------------------- *
 * status — print the fixed JSON subset (console.log(JSON.stringify(..., 2))).
 * ------------------------------------------------------------------------- */
static int cmd_status(const char *state_file, int *out_exit_code)
{
    char *json = NULL;
    int rc = read_file(state_file, &json);
    if (rc != BNS_OK) return agentd_failed("cannot read STATE_FILE", out_exit_code);

    agent_state_t st;
    rc = agent_state_from_json(json, &st);
    free(json);
    if (rc != BNS_OK) return agentd_failed("cannot parse STATE_FILE", out_exit_code);

    const char *status =
        st.status == AGENT_STATUS_REVOKED  ? "revoked"  :
        st.status == AGENT_STATUS_ACTIONED ? "actioned" : "deployed";

    /* JSON.stringify({ status, genesisTxid, tip, txCount, tier, ricardianHash }, null, 2). */
    printf("{\n");
    printf("  \"status\": \"%s\",\n", status);
    printf("  \"genesisTxid\": \"%s\",\n", st.genesis_txid ? st.genesis_txid : "");
    printf("  \"tip\": \"%s\",\n", st.tip.txid ? st.tip.txid : "");
    printf("  \"txCount\": \"%" PRId64 "\",\n", st.state.tx_count);
    printf("  \"tier\": \"%" PRId64 "\",\n", st.state.tier);
    printf("  \"ricardianHash\": \"%s\"\n", st.ricardian_hash ? st.ricardian_hash : "");
    printf("}\n");

    agent_state_free(&st);
    if (out_exit_code) *out_exit_code = 0;
    return BNS_OK;
}

/* ------------------------------------------------------------------------- *
 * Shared CLI setup: STATE_FILE, NETWORK, the Elder/Agent/Counterparty keys.
 * Mirrors the post-status block in cliMain.
 * ------------------------------------------------------------------------- */
typedef struct {
    bsv_network_t net;
    const char   *net_name;        /* "livenet"/"testnet" display (network.name) */
    ecdsa_key_t  *elder, *agent, *counterparty;
    char         *elder_addr;
} cli_ctx_t;

static void cli_ctx_free(cli_ctx_t *c)
{
    if (c == NULL) return;
    ecdsa_key_free(c->elder);
    ecdsa_key_free(c->agent);
    ecdsa_key_free(c->counterparty);
    free(c->elder_addr);
    memset(c, 0, sizeof *c);
}

static int cli_setup_keys(cli_ctx_t *c, int *out_exit_code)
{
    char errmsg[256];

    /* network = (NETWORK ?? 'main').startsWith('test') ? testnet : mainnet. */
    const char *netenv = env_or("NETWORK", "main");
    c->net = (strncmp(netenv, "test", 4) == 0) ? BSV_TESTNET : BSV_MAINNET;
    c->net_name = (c->net == BSV_TESTNET) ? "testnet" : "livenet";

    /* elder = loadKey(ELDER_KEY_FILE ?? `${BONSAI_HOME}/chain/test_bsv.json`). */
    const char *elder_file = env_get("ELDER_KEY_FILE");
    char default_elder[1024];
    if (elder_file == NULL || elder_file[0] == '\0') {
        snprintf(default_elder, sizeof default_elder, "%s/chain/test_bsv.json", bonsai_home());
        elder_file = default_elder;
    }
    int rc = load_key(elder_file, c->net, &c->elder, &c->elder_addr, errmsg, sizeof errmsg);
    if (rc != BNS_OK) { agentd_failed(errmsg, out_exit_code); return rc; }

    /* agent = AGENT_KEY_FILE ? loadKey(...) : elder. */
    const char *agent_file = env_get("AGENT_KEY_FILE");
    if (agent_file && agent_file[0]) {
        rc = load_key(agent_file, c->net, &c->agent, NULL, errmsg, sizeof errmsg);
        if (rc != BNS_OK) { agentd_failed(errmsg, out_exit_code); return rc; }
    }

    /* counterparty = COUNTERPARTY_KEY_FILE ? loadKey(...) : elder. */
    const char *cp_file = env_get("COUNTERPARTY_KEY_FILE");
    if (cp_file && cp_file[0]) {
        rc = load_key(cp_file, c->net, &c->counterparty, NULL, errmsg, sizeof errmsg);
        if (rc != BNS_OK) { agentd_failed(errmsg, out_exit_code); return rc; }
    }
    return BNS_OK;
}

/* ------------------------------------------------------------------------- *
 * LIVE broadcast helpers (CONFIRM_MAINNET_BROADCAST=yes path).
 *
 * The live contract lifecycle is a real fund -> build -> sign -> broadcast path:
 *   - chain_broadcast_woc_new()      : mainnet WoC client
 *   - chain_broadcast_select_funding : pick the funder's UTXOs for need_sats
 *   - build_agent_tea_*              : lay out the UNSIGNED tx (identity input +
 *                                      funding + outputs incl. change)
 *   - build_contract_deploy /        : finalize + sign -> byte-exact raw hex
 *     contract_execute_sign /
 *     contract_revoke_sign
 *   - chain_broadcast_send           : POST /tx/raw, print "BROADCAST OK: <txid>"
 * ------------------------------------------------------------------------- */

/* Resolve the AgentTea compiled-artifact path: $AGENT_TEA_ARTIFACT, else the
 * known repo-relative locations (mirrors live_agent_smoke_lib). Static buffer. */
static const char *agentd_artifact_path(void)
{
    static char buf[1024];
    const char *override = env_get("AGENT_TEA_ARTIFACT");
    if (override && override[0]) {
        snprintf(buf, sizeof buf, "%s", override);
        if (access(buf, R_OK) == 0) return buf;
        return NULL;
    }
    static const char *candidates[] = {
        "artifacts/src/contracts-next/agentTea.json",
        "../artifacts/src/contracts-next/agentTea.json",
        "chain_c/artifacts/src/contracts-next/agentTea.json",
    };
    for (size_t i = 0; i < sizeof candidates / sizeof candidates[0]; i++) {
        snprintf(buf, sizeof buf, "%s", candidates[i]);
        if (access(buf, R_OK) == 0) return buf;
    }
    return NULL;
}

/* int64 -> a fresh bn_t (decimal). */
static int i64_to_bn(int64_t v, bn_t **out)
{
    char dec[32];
    snprintf(dec, sizeof dec, "%" PRId64, v);
    return bn_parse_dec(dec, out);
}

/* Resolve the 20-byte change hash160: CHANGE_ADDRESS (base58check P2PKH) if set,
 * else hash160 of the Elder address (== elder.toAddress(network)). The Elder
 * pubkey bytes are supplied so we can fall back without re-deriving. */
static int resolve_change_hash160(const uint8_t elder_pub33[33], bsv_network_t net,
                                  uint8_t out20[20], char *errmsg, size_t errsz)
{
    const char *addr = env_get("CHANGE_ADDRESS");
    if (addr && addr[0]) {
        byte_buf_t payload;
        byte_buf_init(&payload);
        int rc = base58check_decode(addr, &payload);
        if (rc != BNS_OK || payload.len != 21) {
            byte_buf_free(&payload);
            snprintf(errmsg, errsz, "CHANGE_ADDRESS is not a valid P2PKH address");
            return BNS_EINVAL;
        }
        /* Enforce the version byte matches the active network's P2PKH prefix
         * (mainnet 0x00, testnet 0x6f). Without this a wrong-network address is
         * silently accepted; funds stay key-spendable but this catches the
         * cross-network footgun loudly rather than after broadcast. */
        uint8_t ver = payload.data[0];
        uint8_t want_ver = (net == BSV_TESTNET) ? 0x6f : 0x00;
        if (ver != want_ver) {
            byte_buf_free(&payload);
            snprintf(errmsg, errsz,
                     "CHANGE_ADDRESS version byte 0x%02x does not match active network "
                     "(%s expects 0x%02x)",
                     ver, net == BSV_TESTNET ? "testnet" : "mainnet", want_ver);
            return BNS_EINVAL;
        }
        memcpy(out20, payload.data + 1, 20); /* strip 1-byte version */
        byte_buf_free(&payload);
        return BNS_OK;
    }
    hash160(elder_pub33, 33, out20);
    return BNS_OK;
}

/* Load a WIF key file (FUND_* env), select funding UTXOs covering need_sats from
 * its address via WoC. *out_funder_key is the signing key (caller frees);
 * *out_funding is the selected set (caller funding_utxos_free's). When the env
 * var is unset/empty, *out_funder_key=NULL and *out_funding is empty (TS: no
 * funding => undefined). */
static int pick_funding_from_keyfile(woc_client_t *woc, const char *key_file_env,
                                     bsv_network_t net, int64_t need_sats,
                                     ecdsa_key_t **out_funder_key,
                                     funding_utxos_t *out_funding,
                                     char *errmsg, size_t errsz)
{
    *out_funder_key = NULL;
    memset(out_funding, 0, sizeof *out_funding);

    const char *file = env_get(key_file_env);
    if (file == NULL || file[0] == '\0') return BNS_OK; /* no funding */

    ecdsa_key_t *key = NULL;
    char *addr = NULL;
    int rc = load_key(file, net, &key, &addr, errmsg, errsz);
    if (rc != BNS_OK) return rc;

    bonsai_err_ctx err; memset(&err, 0, sizeof err);
    rc = chain_broadcast_select_funding(woc, addr, need_sats, out_funding, &err);
    free(addr);
    if (rc != BNS_OK) {
        ecdsa_key_free(key);
        snprintf(errmsg, errsz, "%s", err.msg[0] ? err.msg : "funding selection failed");
        return rc;
    }
    *out_funder_key = key;
    return BNS_OK;
}

/* Build the contract_funding_input_t array for the funding UTXOs added by a
 * builder at input indices [first_index .. first_index+count). All funding UTXOs
 * are P2PKH outputs to `funder_key`'s address, so they share one scriptCode (the
 * funder's P2PKH locking script, kept alive in *out_script). *out_fund is a fresh
 * array (caller frees). When count==0, no array is allocated. */
static int build_funding_inputs(const funding_utxos_t *funding,
                                size_t first_index,
                                const ecdsa_key_t *funder_key,
                                contract_funding_input_t **out_fund,
                                byte_buf_t *out_script,
                                char *errmsg, size_t errsz)
{
    *out_fund = NULL;
    byte_buf_init(out_script);
    if (funding == NULL || funding->count == 0 || funder_key == NULL)
        return BNS_OK;

    /* funder P2PKH scriptCode = OP_DUP OP_HASH160 <hash160(funderPub)> ... */
    ecdsa_pubkey_t *pub = NULL;
    uint8_t pub33[33];
    int rc = ecdsa_key_derive_pubkey(funder_key, &pub);
    if (rc == BNS_OK) rc = ecdsa_pubkey_serialize_compressed(pub, pub33);
    ecdsa_pubkey_free(pub);
    if (rc != BNS_OK) { snprintf(errmsg, errsz, "cannot derive funder pubkey"); return rc; }

    uint8_t h160[20];
    hash160(pub33, 33, h160);
    rc = build_p2pkh_script(h160, out_script);
    if (rc != BNS_OK) { byte_buf_free(out_script); snprintf(errmsg, errsz, "cannot build funder script"); return rc; }

    contract_funding_input_t *fund = calloc(funding->count, sizeof *fund);
    if (fund == NULL) { byte_buf_free(out_script); snprintf(errmsg, errsz, "out of memory"); return BNS_ENOMEM; }
    for (size_t i = 0; i < funding->count; i++) {
        fund[i].input_index     = first_index + i;
        fund[i].script_code     = out_script->data;
        fund[i].script_code_len = out_script->len;
        fund[i].value           = (uint64_t)funding->items[i].satoshis;
        fund[i].key             = funder_key;
    }
    *out_fund = fund;
    return BNS_OK;
}

/* Reconstruct the live AgentTea instance from the persisted AgentState + the tip
 * raw tx: params (owner/agent/ricardianHash/limits/rabin) come from the JSON; the
 * mutable state (txCount/.../recoveryCount) and the rotated agent key are decoded
 * from the tip output's on-chain locking script (TS: AgentTea.fromTx). Also yields
 * the contract scriptCode (the tip output's locking script) + identity value for
 * the BIP143 preimage. On success *inst is owned (agent_tea_free) and *script_code
 * holds the scriptCode (caller byte_buf_free). */
static int instance_at_tip(const agent_state_t *st,
                           const scrypt_artifact_t *artifact,
                           agent_tea_t *inst,
                           byte_buf_t *out_script_code,
                           uint64_t *out_identity_value,
                           char *errmsg, size_t errsz)
{
    memset(inst, 0, sizeof *inst);
    byte_buf_init(out_script_code);
    *out_identity_value = 0;

    if (st->tip.raw_tx_hex == NULL || st->ricardian_hash == NULL) {
        snprintf(errmsg, errsz, "STATE_FILE tip is missing the raw tx");
        return BNS_EINVAL;
    }

    /* Parse the tip tx and extract output[tip.vout] = the identity locking script. */
    bsv_tx_t tip; tx_init(&tip);
    int rc = tx_deserialize(st->tip.raw_tx_hex, &tip);
    if (rc != BNS_OK) { snprintf(errmsg, errsz, "cannot parse tip raw tx"); return rc; }
    if (st->tip.vout >= tip.num_outputs) {
        tx_free(&tip);
        snprintf(errmsg, errsz, "tip vout out of range");
        return BNS_EINVAL;
    }
    const bsv_txout_t *idout = &tip.outputs[st->tip.vout];
    rc = byte_buf_from(out_script_code, idout->script.data, idout->script.len);
    if (rc != BNS_OK) { tx_free(&tip); snprintf(errmsg, errsz, "out of memory"); return rc; }
    *out_identity_value = idout->satoshis;

    /* Decode the mutable state + rotated agent key from the locking script. */
    agent_tea_state_t state; memset(&state, 0, sizeof state);
    byte_buf_t decoded_agent; byte_buf_init(&decoded_agent);
    rc = agent_tea_from_tx(out_script_code->data, out_script_code->len, artifact,
                           &state, &decoded_agent);
    tx_free(&tip);
    if (rc != BNS_OK) {
        byte_buf_free(&decoded_agent);
        byte_buf_free(out_script_code);
        snprintf(errmsg, errsz, "cannot decode on-chain state from tip");
        return rc;
    }

    /* Build params from the persisted JSON. owner/agent/ricardianHash are hex. */
    agent_tea_params_t *p = &inst->params;
    byte_buf_init(&p->owner);
    byte_buf_init(&p->agent);
    byte_buf_init(&p->ricardian_hash);

#define FAIL_INST(msg) do { snprintf(errmsg, errsz, "%s", (msg)); \
        agent_tea_state_free(&state); byte_buf_free(&decoded_agent); \
        agent_tea_free(inst); byte_buf_free(out_script_code); return BNS_EINVAL; } while (0)

    if (st->owner == NULL || hex_decode(st->owner, &p->owner) != BNS_OK || p->owner.len != 33)
        FAIL_INST("STATE_FILE owner pubkey is invalid");
    /* agent: prefer the rotated key decoded on-chain (recover() lineage). */
    if (decoded_agent.len == 33)
        rc = byte_buf_from(&p->agent, decoded_agent.data, decoded_agent.len);
    else if (st->agent_pub_key)
        rc = hex_decode(st->agent_pub_key, &p->agent);
    else rc = BNS_EINVAL;
    if (rc != BNS_OK || p->agent.len != 33) FAIL_INST("STATE_FILE agent pubkey is invalid");
    if (hex_decode(st->ricardian_hash, &p->ricardian_hash) != BNS_OK || p->ricardian_hash.len != 32)
        FAIL_INST("STATE_FILE ricardianHash is invalid");

    if (i64_to_bn(st->params.per_tx_limit, &p->per_tx_limit) != BNS_OK ||
        i64_to_bn(st->params.daily_limit, &p->daily_limit) != BNS_OK ||
        i64_to_bn(st->params.window_duration, &p->window_duration) != BNS_OK ||
        i64_to_bn(st->params.graduation_threshold, &p->graduation_threshold) != BNS_OK ||
        i64_to_bn(st->params.validator_threshold, &p->validator_threshold) != BNS_OK ||
        i64_to_bn(st->params.recovery_threshold, &p->recovery_threshold) != BNS_OK)
        FAIL_INST("STATE_FILE params are invalid");

    /* Rabin pubkeys: decimal strings in rabinPub. */
    if (st->rabin_pub.guardian == NULL ||
        bn_parse_dec(st->rabin_pub.guardian, &p->designated_validator_pubkey) != BNS_OK)
        FAIL_INST("STATE_FILE rabinPub.guardian is invalid");
    if (st->rabin_pub.own_validator == NULL ||
        bn_parse_dec(st->rabin_pub.own_validator, &p->validator_rabin_pubkey) != BNS_OK)
        FAIL_INST("STATE_FILE rabinPub.ownValidator is invalid");
    for (size_t i = 0; i < BONSAI_AGENT_TEA_RECOVERY_KEYS; i++) {
        const char *r = (i < st->rabin_pub.num_recovery) ? st->rabin_pub.recovery[i] : NULL;
        if (r == NULL || bn_parse_dec(r, &p->recovery_keys[i]) != BNS_OK)
            FAIL_INST("STATE_FILE rabinPub.recovery is invalid");
    }
#undef FAIL_INST

    inst->state = state;          /* take ownership of the decoded numeric state */
    inst->artifact = artifact;
    byte_buf_free(&decoded_agent);
    return BNS_OK;
}

/* ------------------------------------------------------------------------- *
 * deploy
 * ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- *
 * recovery-key store — operator-custodial M-of-3 social recovery (opt-in)
 *
 * deploy generates the 3 guardian Rabin keypairs and normally DISCARDS the
 * private factors — true social recovery means the guardians each hold their own
 * key and sign offline (the RECOVER_SIGS_FILE path). With
 * AGENTD_PERSIST_RECOVERY_KEYS=yes, deploy instead persists the 3 (p,q) factors
 * to "<STATE_FILE>.recovery_keys" (0600) so `recover` can self-sign the
 * AgentTea.recoveryMsg without external guardians (self-contained / testable).
 * Format: one "p_dec:q_dec" line per guardian. This is SECRET key material.
 * ------------------------------------------------------------------------- */
#define AGENTD_RECOVERY_KEYS BONSAI_AGENT_TEA_RECOVERY_KEYS  /* 3 */

static void recovery_store_path(const char *state_file, char *out, size_t outsz)
{
    snprintf(out, outsz, "%s.recovery_keys", state_file);
}

/* Persist the 3 guardian (p,q) factors to <state_file>.recovery_keys at 0600. */
static int save_recovery_keys(const char *state_file,
                              const rabin_key_t keys[AGENTD_RECOVERY_KEYS])
{
    byte_buf_t txt; byte_buf_init(&txt);
    int rc = BNS_OK;
    for (int i = 0; i < AGENTD_RECOVERY_KEYS && rc == BNS_OK; i++) {
        char *pd = NULL, *qd = NULL;
        if (keys[i].p == NULL || keys[i].q == NULL ||
            bn_to_dec(keys[i].p, &pd) != BNS_OK || bn_to_dec(keys[i].q, &qd) != BNS_OK) {
            free(pd); free(qd); rc = BNS_EINVAL; break;
        }
        rc = byte_buf_append(&txt, pd, strlen(pd));
        if (rc == BNS_OK) rc = byte_buf_append_byte(&txt, ':');
        if (rc == BNS_OK) rc = byte_buf_append(&txt, qd, strlen(qd));
        if (rc == BNS_OK) rc = byte_buf_append_byte(&txt, '\n');
        free(pd); free(qd);
    }
    if (rc == BNS_OK) rc = byte_buf_append_byte(&txt, '\0');  /* C-string for write_file_mode */
    if (rc == BNS_OK) {
        char path[1200];
        recovery_store_path(state_file, path, sizeof path);
        rc = agentd_write_file_atomic(path, (const char *)txt.data);  /* mode 0600 */
    }
    byte_buf_free(&txt);
    return rc;
}

/* Load the 3 guardian (p,q) factors. BNS_OK -> caller rabin_key_free's each;
 * non-OK means the store is absent (not custodial) or malformed. */
static int load_recovery_keys(const char *state_file,
                              rabin_key_t out[AGENTD_RECOVERY_KEYS])
{
    char path[1200];
    recovery_store_path(state_file, path, sizeof path);
    char *txt = NULL;
    int rc = read_file(path, &txt);
    if (rc != BNS_OK) return rc;            /* absent -> caller falls back to external sigs */
    memset(out, 0, AGENTD_RECOVERY_KEYS * sizeof *out);
    int n = 0;
    char *save = NULL;
    for (char *line = strtok_r(txt, "\n", &save);
         line != NULL && n < AGENTD_RECOVERY_KEYS;
         line = strtok_r(NULL, "\n", &save)) {
        char *colon = strchr(line, ':');
        if (colon == NULL) { rc = BNS_EPARSE; break; }
        *colon = '\0';
        if (bn_parse_dec(line, &out[n].p) != BNS_OK ||
            bn_parse_dec(colon + 1, &out[n].q) != BNS_OK) { rc = BNS_EPARSE; break; }
        n++;
    }
    free(txt);
    if (rc == BNS_OK && n != AGENTD_RECOVERY_KEYS) rc = BNS_EPARSE;
    if (rc != BNS_OK)
        for (int i = 0; i < AGENTD_RECOVERY_KEYS; i++) rabin_key_free(&out[i]);
    return rc;
}

static int cmd_deploy(const char *state_file, bool confirm, int *out_exit_code)
{
    char errmsg[256];
    cli_ctx_t c;
    memset(&c, 0, sizeof c);
    int rc = cli_setup_keys(&c, out_exit_code);
    if (rc != BNS_OK) { cli_ctx_free(&c); return BNS_OK; }

    /* ricardianHash: RICARDIAN_HASH ? assertHash32 : sha256(`bonsai agent ${stateFile}`). */
    char *ricardian_hex = NULL;
    const char *rh_env = env_get("RICARDIAN_HASH");
    if (rh_env != NULL) {
        rc = assert_hash32("RICARDIAN_HASH", rh_env, &ricardian_hex, errmsg, sizeof errmsg);
        if (rc != BNS_OK) { cli_ctx_free(&c); return agentd_failed(errmsg, out_exit_code); }
    } else {
        char tmpl[1100];
        snprintf(tmpl, sizeof tmpl, "bonsai agent %s", state_file);
        uint8_t dg[BONSAI_SHA256_LEN];
        sha256((const uint8_t *)tmpl, strlen(tmpl), dg);
        ricardian_hex = hex_encode(dg, sizeof dg);
        if (ricardian_hex == NULL) { cli_ctx_free(&c); return agentd_failed("out of memory", out_exit_code); }
    }

    /* console.log('deploy plan: network', name, 'elder', addr, 'ricardianHash', hash). */
    printf("deploy plan: network %s elder %s ricardianHash %s\n",
           c.net_name, c.elder_addr ? c.elder_addr : "", ricardian_hex);

    if (!confirm) {
        printf("\nDRY RUN — set CONFIRM_MAINNET_BROADCAST=yes to deploy. No STATE_FILE written.\n");
        free(ricardian_hex);
        cli_ctx_free(&c);
        if (out_exit_code) *out_exit_code = 0;
        return BNS_OK;
    }

    /* ---- LIVE deploy: build a genesis AgentTea identity UTXO + broadcast ---- */
    int exit_code = 1;
    woc_client_t *woc = NULL;
    ecdsa_key_t *funder_key = NULL;
    funding_utxos_t funding; memset(&funding, 0, sizeof funding);
    contract_funding_input_t *fund = NULL;
    byte_buf_t fund_script; byte_buf_init(&fund_script);
    scrypt_artifact_t artifact; memset(&artifact, 0, sizeof artifact);
    bool artifact_ok = false;
    agent_tea_t inst; memset(&inst, 0, sizeof inst);
    bool inst_ok = false;
    byte_buf_t genesis_script; byte_buf_init(&genesis_script);
    tx_builder_t b; tx_builder_init(&b);
    char *raw_hex = NULL, *txid = NULL, *state_json = NULL;
    agent_state_t out_state; memset(&out_state, 0, sizeof out_state);
    bonsai_err_ctx err; memset(&err, 0, sizeof err);

    /* Opt-in custodial recovery: capture the guardian private factors so `recover`
     * can self-sign. Default OFF — the keys are otherwise discarded. */
    rabin_key_t recovery_priv[AGENTD_RECOVERY_KEYS];
    memset(recovery_priv, 0, sizeof recovery_priv);
    const char *prk = env_get("AGENTD_PERSIST_RECOVERY_KEYS");
    bool persist_recovery = prk && strcmp(prk, "yes") == 0;

    /* Elder/agent/counterparty pubkey bytes (agent/counterparty default to elder). */
    uint8_t elder_pub[33], agent_pub[33], cp_pub[33];
    {
        ecdsa_pubkey_t *pub = NULL;
        if (ecdsa_key_derive_pubkey(c.elder, &pub) != BNS_OK ||
            ecdsa_pubkey_serialize_compressed(pub, elder_pub) != BNS_OK) {
            ecdsa_pubkey_free(pub); snprintf(errmsg, sizeof errmsg, "cannot derive elder pubkey"); goto deploy_fail;
        }
        ecdsa_pubkey_free(pub);
    }
    {
        const ecdsa_key_t *ak = c.agent ? c.agent : c.elder;
        const ecdsa_key_t *ck = c.counterparty ? c.counterparty : c.elder;
        ecdsa_pubkey_t *pub = NULL;
        if (ecdsa_key_derive_pubkey(ak, &pub) != BNS_OK ||
            ecdsa_pubkey_serialize_compressed(pub, agent_pub) != BNS_OK) {
            ecdsa_pubkey_free(pub); snprintf(errmsg, sizeof errmsg, "cannot derive agent pubkey"); goto deploy_fail;
        }
        ecdsa_pubkey_free(pub); pub = NULL;
        if (ecdsa_key_derive_pubkey(ck, &pub) != BNS_OK ||
            ecdsa_pubkey_serialize_compressed(pub, cp_pub) != BNS_OK) {
            ecdsa_pubkey_free(pub); snprintf(errmsg, sizeof errmsg, "cannot derive counterparty pubkey"); goto deploy_fail;
        }
        ecdsa_pubkey_free(pub);
    }

    /* Load the AgentTea artifact and build the genesis instance. */
    {
        const char *apath = agentd_artifact_path();
        if (apath == NULL) { snprintf(errmsg, sizeof errmsg, "AgentTea artifact not found (set AGENT_TEA_ARTIFACT)"); goto deploy_fail; }
        if (load_artifact(apath, &artifact) != BNS_OK) { snprintf(errmsg, sizeof errmsg, "cannot load AgentTea artifact"); goto deploy_fail; }
        artifact_ok = true;
    }
    {
        agent_tea_params_t *p = &inst.params;
        byte_buf_init(&p->owner); byte_buf_init(&p->agent); byte_buf_init(&p->ricardian_hash);
        if (byte_buf_from(&p->owner, elder_pub, 33) != BNS_OK ||
            byte_buf_from(&p->agent, agent_pub, 33) != BNS_OK ||
            hex_decode(ricardian_hex, &p->ricardian_hash) != BNS_OK || p->ricardian_hash.len != 32) {
            snprintf(errmsg, sizeof errmsg, "cannot build genesis params"); goto deploy_fail;
        }
        int prc = BNS_OK;
        prc |= i64_to_bn(100000, &p->per_tx_limit);
        prc |= i64_to_bn(1000000, &p->daily_limit);
        prc |= i64_to_bn(86400, &p->window_duration);
        prc |= i64_to_bn(10000, &p->graduation_threshold);
        prc |= i64_to_bn(50000, &p->validator_threshold);
        prc |= i64_to_bn(2, &p->recovery_threshold);
        if (prc != BNS_OK) { snprintf(errmsg, sizeof errmsg, "cannot build genesis params"); goto deploy_fail; }
        /* genRabin(): fresh Rabin moduli for guardian/ownValidator/recovery[3]. */
        bn_t **rabins[5] = { &p->designated_validator_pubkey, &p->validator_rabin_pubkey,
                             &p->recovery_keys[0], &p->recovery_keys[1], &p->recovery_keys[2] };
        for (int i = 0; i < 5; i++) {
            rabin_key_t rk = {0};
            if (rabin_keygen(&rk) != BNS_OK || rabin_pubkey(&rk, rabins[i]) != BNS_OK) {
                rabin_key_free(&rk); snprintf(errmsg, sizeof errmsg, "rabin keygen failed"); goto deploy_fail;
            }
            /* recovery guardians are indices 2..4; capture their private factors for
             * the opt-in custodial store (persisted only after a successful broadcast). */
            if (persist_recovery && i >= 2) {
                if (bn_dup(rk.p, &recovery_priv[i - 2].p) != BNS_OK ||
                    bn_dup(rk.q, &recovery_priv[i - 2].q) != BNS_OK) {
                    rabin_key_free(&rk); snprintf(errmsg, sizeof errmsg, "out of memory"); goto deploy_fail;
                }
            }
            rabin_key_free(&rk);
        }
        if (agent_tea_genesis_state(&inst.state) != BNS_OK) { snprintf(errmsg, sizeof errmsg, "genesis state failed"); goto deploy_fail; }
        inst.artifact = &artifact;
        inst_ok = true;
    }

    /* Genesis locking script (output[0]). */
    if (agent_tea_locking_script(&inst, /*is_genesis=*/true, &genesis_script) != BNS_OK) {
        snprintf(errmsg, sizeof errmsg, "genesis locking script reconstruction failed"); goto deploy_fail;
    }

    /* WoC client + funding: need identitySats + the deploy fee. */
    woc = chain_broadcast_woc_new(c.net, &err);
    if (woc == NULL) { snprintf(errmsg, sizeof errmsg, "%s", err.msg[0] ? err.msg : "cannot create WoC client"); goto deploy_fail; }
    {
        fee_window_t fw;
        int64_t est_size = (int64_t)genesis_script.len + 400; /* identity output + funding/change overhead */
        if (chain_broadcast_fee_window(est_size, AGENTD_FEE_PER_KB, &fw, &err) != BNS_OK) {
            snprintf(errmsg, sizeof errmsg, "fee window failed"); goto deploy_fail;
        }
        int64_t need = AGENTD_IDENTITY_SATS + fw.recommended;
        if (pick_funding_from_keyfile(woc, "FUND_DEPLOY_KEY_FILE", c.net, need,
                                      &funder_key, &funding, errmsg, sizeof errmsg) != BNS_OK)
            goto deploy_fail;
        if (funder_key == NULL || funding.count == 0) {
            snprintf(errmsg, sizeof errmsg, "FUND_DEPLOY_KEY_FILE is required to fund the deploy"); goto deploy_fail;
        }
    }

    /* Lay out the deploy tx: funding inputs -> output[0]=contract(1 sat) + change. */
    {
        uint64_t total_in = 0;
        for (size_t i = 0; i < funding.count; i++) {
            if (tx_builder_add_input(&b, funding.items[i].tx_id, funding.items[i].output_index,
                                     NULL, 0, 0xffffffffu) != BNS_OK) { snprintf(errmsg, sizeof errmsg, "cannot add funding input"); goto deploy_fail; }
        }
        /* Overflow-safe funding total (fail-closed > MAX_MONEY / wrap) instead of an ad-hoc
         * `total += satoshis` loop that could wrap on a malicious WoC response. */
        if (funding_utxos_total(funding.items, funding.count, &total_in) != BNS_OK) {
            snprintf(errmsg, sizeof errmsg, "funding total out of range (overflow / exceeds MAX_MONEY)");
            goto deploy_fail;
        }
        if (tx_builder_add_output(&b, genesis_script.data, genesis_script.len, AGENTD_IDENTITY_SATS) != BNS_OK) {
            snprintf(errmsg, sizeof errmsg, "cannot add identity output"); goto deploy_fail;
        }
        /* change to the Elder change address. */
        uint8_t change20[20];
        if (resolve_change_hash160(elder_pub, c.net, change20, errmsg, sizeof errmsg) != BNS_OK) goto deploy_fail;
        byte_buf_t chg; byte_buf_init(&chg);
        if (build_p2pkh_script(change20, &chg) != BNS_OK) { byte_buf_free(&chg); snprintf(errmsg, sizeof errmsg, "cannot build change script"); goto deploy_fail; }
        /* change = total_in - identitySats - fee. */
        fee_window_t fw;
        if (chain_broadcast_fee_window((int64_t)genesis_script.len + 400, AGENTD_FEE_PER_KB, &fw, &err) != BNS_OK) {
            byte_buf_free(&chg); snprintf(errmsg, sizeof errmsg, "fee window failed"); goto deploy_fail;
        }
        if (total_in < (uint64_t)(AGENTD_IDENTITY_SATS + fw.recommended)) {
            byte_buf_free(&chg); snprintf(errmsg, sizeof errmsg, "insufficient funding for deploy"); goto deploy_fail;
        }
        uint64_t change_sats = total_in - AGENTD_IDENTITY_SATS - (uint64_t)fw.recommended;
        if (change_sats >= 1) {
            if (tx_builder_add_output(&b, chg.data, chg.len, change_sats) != BNS_OK) {
                byte_buf_free(&chg); snprintf(errmsg, sizeof errmsg, "cannot add change output"); goto deploy_fail;
            }
        }
        byte_buf_free(&chg);
    }

    /* Sign the funding inputs (deploy has no contract unlocking script). */
    if (build_funding_inputs(&funding, 0, funder_key, &fund, &fund_script, errmsg, sizeof errmsg) != BNS_OK)
        goto deploy_fail;
    if (build_contract_deploy(&b, fund, funding.count, &raw_hex) != BNS_OK) {
        snprintf(errmsg, sizeof errmsg, "deploy signing failed"); goto deploy_fail;
    }

    printf("signed raw tx: %s\n", raw_hex);

    /* Broadcast. */
    if (chain_broadcast_send(woc, raw_hex, &txid, &err) != BNS_OK) {
        snprintf(errmsg, sizeof errmsg, "%s", err.msg[0] ? err.msg : "broadcast failed"); goto deploy_fail;
    }
    printf("BROADCAST OK: %s\n", txid);
    printf("DEPLOY broadcast: %s \xe2\x86\x92 STATE_FILE %s\n", txid, state_file);
    persist_broadcast_journal(state_file, "deploy", txid);  /* durable record before JSON write */

    /* Persist the STATE_FILE (genesis tip = txid:0, txCount=0, deployed). */
    out_state.schema   = strdup(BONSAI_AGENT_STATE_SCHEMA);
    out_state.network  = strdup(c.net == BSV_TESTNET ? "testnet" : "mainnet");
    out_state.genesis_txid = strdup(txid);
    out_state.ricardian_hash = strdup(ricardian_hex);
    out_state.owner = hex_encode(elder_pub, 33);
    out_state.agent_pub_key = hex_encode(agent_pub, 33);
    out_state.counterparty_pub_key = hex_encode(cp_pub, 33);
    {
        char ch[1200];
        snprintf(ch, sizeof ch, "bonsai agent %s", ricardian_hex);
        out_state.charter = strdup(ch);
    }
    agent_params_defaults(&out_state.params);
    out_state.rabin_pub.guardian      = NULL;
    out_state.rabin_pub.own_validator = NULL;
    if (bn_to_dec(inst.params.designated_validator_pubkey, &out_state.rabin_pub.guardian) != BNS_OK ||
        bn_to_dec(inst.params.validator_rabin_pubkey, &out_state.rabin_pub.own_validator) != BNS_OK) {
        snprintf(errmsg, sizeof errmsg, "cannot serialize rabin pubkeys"); goto deploy_fail;
    }
    out_state.rabin_pub.recovery = calloc(BONSAI_AGENT_TEA_RECOVERY_KEYS, sizeof(char *));
    if (out_state.rabin_pub.recovery == NULL) { snprintf(errmsg, sizeof errmsg, "out of memory"); goto deploy_fail; }
    out_state.rabin_pub.num_recovery = BONSAI_AGENT_TEA_RECOVERY_KEYS;
    for (size_t i = 0; i < BONSAI_AGENT_TEA_RECOVERY_KEYS; i++) {
        if (bn_to_dec(inst.params.recovery_keys[i], &out_state.rabin_pub.recovery[i]) != BNS_OK) {
            snprintf(errmsg, sizeof errmsg, "cannot serialize recovery pubkeys"); goto deploy_fail;
        }
    }
    out_state.identity_sats = AGENTD_IDENTITY_SATS;
    out_state.tip.txid = strdup(txid);
    out_state.tip.vout = 0;
    out_state.tip.raw_tx_hex = strdup(raw_hex);
    out_state.state.tx_count = 0;
    out_state.state.spent_in_window = 0;
    out_state.state.window_start = 0;
    out_state.state.tier = 1;
    out_state.state.recovery_count = 0;
    out_state.status = AGENT_STATUS_DEPLOYED;
    out_state.history = calloc(1, sizeof(agent_history_entry_t));
    if (out_state.history) {
        out_state.num_history = 1;
        out_state.history[0].op = strdup("deploy");
        out_state.history[0].txid = strdup(txid);
    }
    if (agent_state_to_json(&out_state, &state_json) != BNS_OK ||
        agentd_write_file_atomic(state_file, state_json) != BNS_OK) {
        snprintf(errmsg, sizeof errmsg, "cannot write STATE_FILE %s", state_file); goto deploy_fail;
    }
    if (persist_recovery) {
        if (save_recovery_keys(state_file, recovery_priv) != BNS_OK) {
            snprintf(errmsg, sizeof errmsg, "cannot persist recovery keys to %s.recovery_keys", state_file);
            goto deploy_fail;
        }
        printf("recovery keys persisted (custodial): %s.recovery_keys\n", state_file);
    }
    exit_code = 0;

deploy_fail:
    if (exit_code != 0) agentd_failed(errmsg, out_exit_code);
    else if (out_exit_code) *out_exit_code = 0;
    for (int i = 0; i < AGENTD_RECOVERY_KEYS; i++) rabin_key_free(&recovery_priv[i]);
    free(state_json);
    agent_state_free(&out_state);
    free(txid);
    free(raw_hex);
    tx_builder_free(&b);
    free(fund);
    byte_buf_free(&fund_script);
    byte_buf_free(&genesis_script);
    if (inst_ok) agent_tea_free(&inst);
    if (artifact_ok) scrypt_artifact_free(&artifact);
    funding_utxos_free(&funding);
    ecdsa_key_free(funder_key);
    chain_broadcast_woc_free(woc);
    free(ricardian_hex);
    cli_ctx_free(&c);
    return BNS_OK;
}

/* ------------------------------------------------------------------------- *
 * action
 * ------------------------------------------------------------------------- */
static int cmd_action(const char *state_file, bool confirm, int *out_exit_code)
{
    char errmsg[256];

    /* const state = readState(stateFile). */
    char *json = NULL;
    int rc = read_file(state_file, &json);
    if (rc != BNS_OK) return agentd_failed("cannot read STATE_FILE", out_exit_code);
    agent_state_t st;
    rc = agent_state_from_json(json, &st);
    free(json);
    if (rc != BNS_OK) return agentd_failed("cannot parse STATE_FILE", out_exit_code);

    /* ACTION_HASH is required. */
    const char *ah_env = env_get("ACTION_HASH");
    if (ah_env == NULL || ah_env[0] == '\0') {
        agent_state_free(&st);
        return agentd_failed("ACTION_HASH (the Bonsai receiptHash) is required for action", out_exit_code);
    }
    char *action_hash = NULL;
    rc = assert_hash32("ACTION_HASH", ah_env, &action_hash, errmsg, sizeof errmsg);
    if (rc != BNS_OK) { agent_state_free(&st); return agentd_failed(errmsg, out_exit_code); }

    /* provenanceHash = assertHash32(PROVENANCE_HASH ?? '00'*32). */
    const char *ph_env = env_get("PROVENANCE_HASH");
    char zeros[65];
    if (ph_env == NULL) { memset(zeros, '0', 64); zeros[64] = '\0'; ph_env = zeros; }
    char *provenance_hash = NULL;
    rc = assert_hash32("PROVENANCE_HASH", ph_env, &provenance_hash, errmsg, sizeof errmsg);
    if (rc != BNS_OK) { free(action_hash); agent_state_free(&st); return agentd_failed(errmsg, out_exit_code); }

    /* amount = BigInt(AMOUNT ?? '1000'). TS BigInt() throws on garbage; strtoll
     * silently returns 0 for non-numeric and accepts negatives — either would land a
     * wrong metered amount in the on-chain Third-Entry receipt. Parse here; the strict
     * validation + goto are below, after the cleanup vars are declared (so the early
     * bailout cannot skip their initializers). */
    const char *amt_env = env_or("AMOUNT", "1000");
    errno = 0;
    char *amt_end = NULL;
    long long amount = strtoll(amt_env, &amt_end, 10);
    bool amount_valid = !(errno != 0 || amt_end == amt_env || (amt_end && *amt_end != '\0') || amount < 0);

    /* console.log('action plan: txCount', txCount, 'amount', amount, 'actionHash', actionHash). */
    printf("action plan: txCount %" PRId64 " amount %lld actionHash %s\n",
           st.state.tx_count, amount, action_hash);

    if (!confirm) {
        printf("\nDRY RUN — set CONFIRM_MAINNET_BROADCAST=yes to broadcast. STATE_FILE unchanged.\n");
        free(action_hash);
        free(provenance_hash);
        agent_state_free(&st);
        if (out_exit_code) *out_exit_code = 0;
        return BNS_OK;
    }

    /* ---- LIVE action: executeAction spend under the identity + broadcast ---- */
    int exit_code = 1;
    cli_ctx_t c; memset(&c, 0, sizeof c);
    bool cli_ok = false;
    woc_client_t *woc = NULL;
    ecdsa_key_t *funder_key = NULL;
    funding_utxos_t funding; memset(&funding, 0, sizeof funding);
    contract_funding_input_t *fund = NULL;
    byte_buf_t fund_script; byte_buf_init(&fund_script);
    scrypt_artifact_t artifact; memset(&artifact, 0, sizeof artifact);
    bool artifact_ok = false;
    agent_tea_t inst; memset(&inst, 0, sizeof inst);
    bool inst_ok = false;
    byte_buf_t script_code; byte_buf_init(&script_code);
    tx_builder_t b; tx_builder_init(&b);
    bn_t *amount_bn = NULL;
    char *raw_hex = NULL, *txid = NULL, *state_json = NULL;
    bonsai_err_ctx err; memset(&err, 0, sizeof err);
    uint8_t action_bytes[32], prov_bytes[32], cp_pub[33];

    if (hex_decode_fixed(action_hash, action_bytes, 32) != BNS_OK ||
        hex_decode_fixed(provenance_hash, prov_bytes, 32) != BNS_OK) {
        snprintf(errmsg, sizeof errmsg, "invalid action/provenance hash"); goto action_fail;
    }

    if (cli_setup_keys(&c, out_exit_code) != BNS_OK) { /* prints its own error */
        free(action_hash); free(provenance_hash); agent_state_free(&st); cli_ctx_free(&c);
        return BNS_OK;
    }
    cli_ok = true;

    /* counterparty pubkey bytes (defaults to elder). */
    {
        const ecdsa_key_t *ck = c.counterparty ? c.counterparty : c.elder;
        ecdsa_pubkey_t *pub = NULL;
        if (ecdsa_key_derive_pubkey(ck, &pub) != BNS_OK ||
            ecdsa_pubkey_serialize_compressed(pub, cp_pub) != BNS_OK) {
            ecdsa_pubkey_free(pub); snprintf(errmsg, sizeof errmsg, "cannot derive counterparty pubkey"); goto action_fail;
        }
        ecdsa_pubkey_free(pub);
    }

    if (!amount_valid) {
        snprintf(errmsg, sizeof errmsg, "invalid AMOUNT %s (expected a non-negative integer)", amt_env);
        goto action_fail;
    }
    if (i64_to_bn((int64_t)amount, &amount_bn) != BNS_OK) { snprintf(errmsg, sizeof errmsg, "bad AMOUNT"); goto action_fail; }

    /* WoC client + tip-liveness pre-flight (assertTipLive). */
    woc = chain_broadcast_woc_new(c.net, &err);
    if (woc == NULL) { snprintf(errmsg, sizeof errmsg, "%s", err.msg[0] ? err.msg : "cannot create WoC client"); goto action_fail; }
    if (st.tip.txid) {
        bool spent = false;
        int chk = woc_client_is_output_spent(woc, st.tip.txid, st.tip.vout, &spent);
        if (chk != BNS_OK) {
            /* A non-OK liveness check (network/rate-limit/5xx) is NOT "tip live": broadcasting
             * against an unverified tip risks a double-spend of the identity input exactly when
             * the provider is unreachable. Fail closed and tell the operator to retry. */
            snprintf(errmsg, sizeof errmsg,
                     "action: cannot verify tip %s:%u liveness (WoC error) — refusing to broadcast against an unverified tip; retry when the provider is reachable",
                     st.tip.txid, st.tip.vout);
            goto action_fail;
        }
        if (spent) {
            snprintf(errmsg, sizeof errmsg,
                     "action: persisted tip %s:%u is already spent on-chain — STATE_FILE is stale; re-sync before action",
                     st.tip.txid, st.tip.vout);
            goto action_fail;
        }
    }

    /* Load artifact + reconstruct the instance at the tip. */
    {
        const char *apath = agentd_artifact_path();
        if (apath == NULL) { snprintf(errmsg, sizeof errmsg, "AgentTea artifact not found (set AGENT_TEA_ARTIFACT)"); goto action_fail; }
        if (load_artifact(apath, &artifact) != BNS_OK) { snprintf(errmsg, sizeof errmsg, "cannot load AgentTea artifact"); goto action_fail; }
        artifact_ok = true;
    }
    uint64_t identity_value = 0;
    if (instance_at_tip(&st, &artifact, &inst, &script_code, &identity_value, errmsg, sizeof errmsg) != BNS_OK)
        goto action_fail;
    inst_ok = true;

    /* feeSats = sendTimeFeeWindow(2*scriptBytes + 3000, FEE_PER_KB).recommended. */
    fee_window_t fw;
    if (chain_broadcast_fee_window(2 * (int64_t)script_code.len + 3000, AGENTD_FEE_PER_KB, &fw, &err) != BNS_OK) {
        snprintf(errmsg, sizeof errmsg, "fee window failed"); goto action_fail;
    }
    int64_t fee_sats = fw.recommended;

    /* Funding from FUND_ACTION_KEY_FILE covering the fee (identity is recreated 1:1). */
    if (pick_funding_from_keyfile(woc, "FUND_ACTION_KEY_FILE", c.net, fee_sats,
                                  &funder_key, &funding, errmsg, sizeof errmsg) != BNS_OK)
        goto action_fail;
    if (funder_key == NULL || funding.count == 0) {
        snprintf(errmsg, sizeof errmsg, "FUND_ACTION_KEY_FILE is required to fund the action fee"); goto action_fail;
    }

    /* nLockTime for the action. executeAction pins sequence < 0xffffffff (non-final), so the tx is
     * only mineable once median-time-past (MTP, ~1h behind wall-clock) exceeds nLockTime. A 600s
     * back-date leaves it non-final for ~45min (and blocks the next action from chaining). Back-date
     * past the MTP window so the action is immediately final + mineable; the contract only uses `now`
     * for 24h windowing, so a couple hours of slack is harmless. Override with AGENTD_LOCKTIME_BACKDATE. */
    int64_t backdate = 7200;
    {
        const char *bd = getenv("AGENTD_LOCKTIME_BACKDATE");
        if (bd && bd[0]) {
            /* Clamp/validate to [0, 24h] so `now` can't be pushed to an absurd
             * timestamp. A back-date of 0 is allowed but leaves the action
             * non-final for ~1h (MTP runs ~1h behind wall-clock). Default 7200
             * is unchanged. */
            long v = strtol(bd, NULL, 10);
            if (v >= 0 && v <= 24 * 3600) {
                backdate = (int64_t)v;
            } else {
                snprintf(errmsg, sizeof errmsg,
                         "AGENTD_LOCKTIME_BACKDATE must be in [0, 86400] seconds");
                goto action_fail;
            }
        }
    }
    int64_t now = (int64_t)time(NULL) - backdate;
    /* Sanity-gate the resulting locktime as a real unix timestamp. */
    if (now <= 500000000) {
        snprintf(errmsg, sizeof errmsg, "computed locktime is not a sane unix timestamp");
        goto action_fail;
    }

    /* Build the unsigned executeAction tx. */
    uint8_t change20[20];
    {
        uint8_t elder_pub[33];
        ecdsa_pubkey_t *pub = NULL;
        if (ecdsa_key_derive_pubkey(c.elder, &pub) != BNS_OK ||
            ecdsa_pubkey_serialize_compressed(pub, elder_pub) != BNS_OK) {
            ecdsa_pubkey_free(pub); snprintf(errmsg, sizeof errmsg, "cannot derive elder pubkey"); goto action_fail;
        }
        ecdsa_pubkey_free(pub);
        if (resolve_change_hash160(elder_pub, c.net, change20, errmsg, sizeof errmsg) != BNS_OK) goto action_fail;
    }

    agent_tea_utxo_t identity;
    memset(&identity, 0, sizeof identity);
    snprintf(identity.txid_display, sizeof identity.txid_display, "%s", st.tip.txid ? st.tip.txid : "");
    identity.vout = st.tip.vout;
    identity.value = identity_value;

    agent_tea_builder_opts_t opts;
    memset(&opts, 0, sizeof opts);
    opts.funding = &funding;
    opts.change_hash160 = change20;
    opts.has_change = true;
    opts.fee_sats = (uint64_t)fee_sats;
    opts.has_fee_sats = true;

    if (build_agent_tea_action(&inst, &identity, cp_pub, amount_bn, action_bytes, prov_bytes,
                               now, &opts, &b) != BNS_OK) {
        snprintf(errmsg, sizeof errmsg, "executeAction build failed"); goto action_fail;
    }

    /* change_amount = the change output (last output) satoshis, if present.
     * build_agent_tea_action lays out [identity-state, OP_RETURN, change?]. */
    int64_t change_amount = 0;
    if (b.tx.num_outputs >= 3)
        change_amount = (int64_t)b.tx.outputs[b.tx.num_outputs - 1].satoshis;

    /* Sign: contract input[0] + funding inputs at index 1.. */
    if (build_funding_inputs(&funding, 1, funder_key, &fund, &fund_script, errmsg, sizeof errmsg) != BNS_OK)
        goto action_fail;

    contract_execute_args_t eargs;
    memset(&eargs, 0, sizeof eargs);
    bn_t *attested_limit = NULL, *rabin_s = NULL;
    if (bn_dup(amount_bn, &attested_limit) != BNS_OK || i64_to_bn(0, &rabin_s) != BNS_OK) {
        bn_free(attested_limit); bn_free(rabin_s);
        snprintf(errmsg, sizeof errmsg, "out of memory"); goto action_fail;
    }
    eargs.agent_key = c.agent ? c.agent : c.elder;
    eargs.counterparty_key = c.counterparty ? c.counterparty : c.elder;
    eargs.counterparty_pub33 = cp_pub;
    eargs.amount = amount_bn;
    eargs.hash32 = action_bytes;
    eargs.provenance_hash32 = prov_bytes;
    eargs.attested_limit = attested_limit;     /* attestedLimit == amount (inert) */
    eargs.rabin_s = rabin_s;                    /* DUMMY_SIG.s = 0 */
    eargs.rabin_padding = NULL;
    eargs.rabin_padding_len = 0;

    int src = contract_execute_sign(&b, 0, script_code.data, script_code.len, identity_value,
                                    &eargs, change_amount, change20,
                                    AGENT_TEA_EXECUTE_ACTION_SELECTOR, fund, funding.count, &raw_hex);
    bn_free(attested_limit);
    bn_free(rabin_s);
    if (src != BNS_OK) { snprintf(errmsg, sizeof errmsg, "executeAction signing failed"); goto action_fail; }

    printf("signed raw tx: %s\n", raw_hex);

    if (chain_broadcast_send(woc, raw_hex, &txid, &err) != BNS_OK) {
        snprintf(errmsg, sizeof errmsg, "%s", err.msg[0] ? err.msg : "broadcast failed"); goto action_fail;
    }
    printf("BROADCAST OK: %s\n", txid);
    printf("EXECUTE broadcast: %s\n", txid);
    persist_broadcast_journal(state_file, "action", txid);  /* durable record before JSON write */

    /* Persist the advanced state (TS agentAction state-advance + new tip). */
    {
        /* Roll the window if elapsed, then meter (identical to executeAction). */
        int64_t window_dur = st.params.window_duration;
        bool elapsed = (now - st.state.window_start) >= window_dur;
        st.state.window_start = elapsed ? now : st.state.window_start;
        st.state.spent_in_window = (elapsed ? 0 : st.state.spent_in_window) + (int64_t)amount;
        st.state.tx_count = st.state.tx_count + 1;
        if (st.state.tx_count >= st.params.graduation_threshold && st.state.tier < 2)
            st.state.tier = 2;
        st.status = AGENT_STATUS_ACTIONED;

        free(st.tip.txid);     st.tip.txid = strdup(txid);
        st.tip.vout = 0;
        free(st.tip.raw_tx_hex); st.tip.raw_tx_hex = strdup(raw_hex);

        /* history += {op:"action", txid}. */
        size_t nh = st.num_history;
        agent_history_entry_t *h2 = realloc(st.history, (nh + 1) * sizeof *h2);
        if (h2) {
            st.history = h2;
            st.history[nh].op = strdup("action");
            st.history[nh].txid = strdup(txid);
            st.num_history = nh + 1;
        }

        if (agent_state_to_json(&st, &state_json) != BNS_OK ||
            agentd_write_file_atomic(state_file, state_json) != BNS_OK) {
            snprintf(errmsg, sizeof errmsg, "cannot write STATE_FILE %s", state_file); goto action_fail;
        }
    }
    exit_code = 0;

action_fail:
    if (exit_code != 0) agentd_failed(errmsg, out_exit_code);
    else if (out_exit_code) *out_exit_code = 0;
    free(state_json);
    free(txid);
    free(raw_hex);
    bn_free(amount_bn);
    tx_builder_free(&b);
    free(fund);
    byte_buf_free(&fund_script);
    byte_buf_free(&script_code);
    if (inst_ok) agent_tea_free(&inst);
    if (artifact_ok) scrypt_artifact_free(&artifact);
    funding_utxos_free(&funding);
    ecdsa_key_free(funder_key);
    chain_broadcast_woc_free(woc);
    if (cli_ok) cli_ctx_free(&c);
    free(action_hash);
    free(provenance_hash);
    agent_state_free(&st);
    return BNS_OK;
}

/* ------------------------------------------------------------------------- *
 * revoke
 * ------------------------------------------------------------------------- */
static int cmd_revoke(const char *state_file, bool confirm, int *out_exit_code)
{
    char *json = NULL;
    int rc = read_file(state_file, &json);
    if (rc != BNS_OK) return agentd_failed("cannot read STATE_FILE", out_exit_code);
    agent_state_t st;
    rc = agent_state_from_json(json, &st);
    free(json);
    if (rc != BNS_OK) return agentd_failed("cannot parse STATE_FILE", out_exit_code);

    /* console.log('revoke plan: tip', state.tip.txid). */
    printf("revoke plan: tip %s\n", st.tip.txid ? st.tip.txid : "");

    if (!confirm) {
        printf("\nDRY RUN — set CONFIRM_MAINNET_BROADCAST=yes to revoke. STATE_FILE unchanged.\n");
        agent_state_free(&st);
        if (out_exit_code) *out_exit_code = 0;
        return BNS_OK;
    }

    /* ---- LIVE revoke: Elder kill-switch spend + broadcast ---- */
    int exit_code = 1;
    char errmsg[256];
    cli_ctx_t c; memset(&c, 0, sizeof c);
    bool cli_ok = false;
    woc_client_t *woc = NULL;
    ecdsa_key_t *funder_key = NULL;
    funding_utxos_t funding; memset(&funding, 0, sizeof funding);
    contract_funding_input_t *fund = NULL;
    byte_buf_t fund_script; byte_buf_init(&fund_script);
    scrypt_artifact_t artifact; memset(&artifact, 0, sizeof artifact);
    bool artifact_ok = false;
    agent_tea_t inst; memset(&inst, 0, sizeof inst);
    bool inst_ok = false;
    byte_buf_t script_code; byte_buf_init(&script_code);
    tx_builder_t b; tx_builder_init(&b);
    char *raw_hex = NULL, *txid = NULL, *state_json = NULL;
    bonsai_err_ctx err; memset(&err, 0, sizeof err);

    if (cli_setup_keys(&c, out_exit_code) != BNS_OK) { agent_state_free(&st); cli_ctx_free(&c); return BNS_OK; }
    cli_ok = true;

    /* WoC client + tip-liveness pre-flight (assertTipLive). */
    woc = chain_broadcast_woc_new(c.net, &err);
    if (woc == NULL) { snprintf(errmsg, sizeof errmsg, "%s", err.msg[0] ? err.msg : "cannot create WoC client"); goto revoke_fail; }
    if (st.tip.txid) {
        bool spent = false;
        int chk = woc_client_is_output_spent(woc, st.tip.txid, st.tip.vout, &spent);
        if (chk != BNS_OK) {
            snprintf(errmsg, sizeof errmsg,
                     "revoke: cannot verify tip %s:%u liveness (WoC error) — refusing to broadcast against an unverified tip; retry when the provider is reachable",
                     st.tip.txid, st.tip.vout);
            goto revoke_fail;
        }
        if (spent) {
            snprintf(errmsg, sizeof errmsg,
                     "revoke: persisted tip %s:%u is already spent on-chain — STATE_FILE is stale; re-sync before revoke",
                     st.tip.txid, st.tip.vout);
            goto revoke_fail;
        }
    }

    /* Load artifact + reconstruct the instance at the tip. */
    {
        const char *apath = agentd_artifact_path();
        if (apath == NULL) { snprintf(errmsg, sizeof errmsg, "AgentTea artifact not found (set AGENT_TEA_ARTIFACT)"); goto revoke_fail; }
        if (load_artifact(apath, &artifact) != BNS_OK) { snprintf(errmsg, sizeof errmsg, "cannot load AgentTea artifact"); goto revoke_fail; }
        artifact_ok = true;
    }
    uint64_t identity_value = 0;
    if (instance_at_tip(&st, &artifact, &inst, &script_code, &identity_value, errmsg, sizeof errmsg) != BNS_OK)
        goto revoke_fail;
    inst_ok = true;

    /* revokeFeeSats = sendTimeFeeWindow(scriptBytes + 2000, FEE_PER_KB).recommended. */
    fee_window_t fw;
    if (chain_broadcast_fee_window((int64_t)script_code.len + 2000, AGENTD_FEE_PER_KB, &fw, &err) != BNS_OK) {
        snprintf(errmsg, sizeof errmsg, "fee window failed"); goto revoke_fail;
    }
    int64_t fee_sats = fw.recommended;

    /* Funding from FUND_REVOKE_KEY_FILE ?? FUND_ACTION_KEY_FILE. */
    const char *revoke_fund_env = (env_get("FUND_REVOKE_KEY_FILE") && env_get("FUND_REVOKE_KEY_FILE")[0])
                                ? "FUND_REVOKE_KEY_FILE" : "FUND_ACTION_KEY_FILE";
    if (pick_funding_from_keyfile(woc, revoke_fund_env, c.net, fee_sats,
                                  &funder_key, &funding, errmsg, sizeof errmsg) != BNS_OK)
        goto revoke_fail;
    if (funder_key == NULL || funding.count == 0) {
        snprintf(errmsg, sizeof errmsg, "FUND_REVOKE_KEY_FILE/FUND_ACTION_KEY_FILE is required to fund the revoke fee"); goto revoke_fail;
    }

    /* change to the Elder change address. */
    uint8_t change20[20];
    {
        uint8_t elder_pub[33];
        ecdsa_pubkey_t *pub = NULL;
        if (ecdsa_key_derive_pubkey(c.elder, &pub) != BNS_OK ||
            ecdsa_pubkey_serialize_compressed(pub, elder_pub) != BNS_OK) {
            ecdsa_pubkey_free(pub); snprintf(errmsg, sizeof errmsg, "cannot derive elder pubkey"); goto revoke_fail;
        }
        ecdsa_pubkey_free(pub);
        if (resolve_change_hash160(elder_pub, c.net, change20, errmsg, sizeof errmsg) != BNS_OK) goto revoke_fail;
    }

    agent_tea_utxo_t identity;
    memset(&identity, 0, sizeof identity);
    snprintf(identity.txid_display, sizeof identity.txid_display, "%s", st.tip.txid ? st.tip.txid : "");
    identity.vout = st.tip.vout;
    identity.value = identity_value;

    agent_tea_builder_opts_t opts;
    memset(&opts, 0, sizeof opts);
    opts.funding = &funding;
    opts.change_hash160 = change20;
    opts.has_change = true;
    opts.fee_sats = (uint64_t)fee_sats;
    opts.has_fee_sats = true;

    if (build_agent_tea_revoke(&inst, &identity, &opts, &b) != BNS_OK) {
        snprintf(errmsg, sizeof errmsg, "revoke build failed"); goto revoke_fail;
    }

    /* change_amount = last output sats if a change output was appended. revoke lays
     * out [P2PKH payout, change?]. */
    int64_t change_amount = 0;
    if (b.tx.num_outputs >= 2)
        change_amount = (int64_t)b.tx.outputs[b.tx.num_outputs - 1].satoshis;

    /* Sign: contract input[0] + funding inputs at index 1.. (owner = Elder). */
    if (build_funding_inputs(&funding, 1, funder_key, &fund, &fund_script, errmsg, sizeof errmsg) != BNS_OK)
        goto revoke_fail;

    if (contract_revoke_sign(&b, 0, script_code.data, script_code.len, identity_value, c.elder,
                             change_amount, change20, AGENT_TEA_REVOKE_SELECTOR,
                             fund, funding.count, &raw_hex) != BNS_OK) {
        snprintf(errmsg, sizeof errmsg, "revoke signing failed"); goto revoke_fail;
    }

    printf("signed raw tx: %s\n", raw_hex);

    if (chain_broadcast_send(woc, raw_hex, &txid, &err) != BNS_OK) {
        snprintf(errmsg, sizeof errmsg, "%s", err.msg[0] ? err.msg : "broadcast failed"); goto revoke_fail;
    }
    printf("BROADCAST OK: %s\n", txid);
    printf("REVOKE broadcast: %s\n", txid);
    persist_broadcast_journal(state_file, "revoke", txid);  /* durable record before JSON write */

    /* Persist: status=revoked, history += {op:"revoke", txid}. */
    {
        st.status = AGENT_STATUS_REVOKED;
        size_t nh = st.num_history;
        agent_history_entry_t *h2 = realloc(st.history, (nh + 1) * sizeof *h2);
        if (h2) {
            st.history = h2;
            st.history[nh].op = strdup("revoke");
            st.history[nh].txid = strdup(txid);
            st.num_history = nh + 1;
        }
        if (agent_state_to_json(&st, &state_json) != BNS_OK ||
            agentd_write_file_atomic(state_file, state_json) != BNS_OK) {
            snprintf(errmsg, sizeof errmsg, "cannot write STATE_FILE %s", state_file); goto revoke_fail;
        }
    }
    exit_code = 0;

revoke_fail:
    if (exit_code != 0) agentd_failed(errmsg, out_exit_code);
    else if (out_exit_code) *out_exit_code = 0;
    free(state_json);
    free(txid);
    free(raw_hex);
    tx_builder_free(&b);
    free(fund);
    byte_buf_free(&fund_script);
    byte_buf_free(&script_code);
    if (inst_ok) agent_tea_free(&inst);
    if (artifact_ok) scrypt_artifact_free(&artifact);
    funding_utxos_free(&funding);
    ecdsa_key_free(funder_key);
    chain_broadcast_woc_free(woc);
    if (cli_ok) cli_ctx_free(&c);
    agent_state_free(&st);
    return BNS_OK;
}

/* ------------------------------------------------------------------------- *
 * recover — M-of-3 social recovery: rotate the agent key (AgentTea.recover #3)
 * ------------------------------------------------------------------------- */

/* Parse RECOVER_SIGS_FILE: 3 lines "<used 0|1> <s_hex|-> <paddingByteCount>".
 * On BNS_OK, `sigs[i].s` points into `s_store[i]` (caller bn_free's each set slot). */
static int load_external_recover_sigs(const char *path,
                                      contract_recover_sig_t sigs[AGENTD_RECOVERY_KEYS],
                                      bn_t *s_store[AGENTD_RECOVERY_KEYS],
                                      char *errmsg, size_t errsz)
{
    char *txt = NULL;
    int rc = read_file(path, &txt);
    if (rc != BNS_OK) { snprintf(errmsg, errsz, "cannot read RECOVER_SIGS_FILE %s", path); return rc; }
    memset(sigs, 0, AGENTD_RECOVERY_KEYS * sizeof *sigs);
    for (int i = 0; i < AGENTD_RECOVERY_KEYS; i++) s_store[i] = NULL;
    int n = 0;
    char *save = NULL;
    for (char *line = strtok_r(txt, "\n", &save);
         line != NULL && n < AGENTD_RECOVERY_KEYS;
         line = strtok_r(NULL, "\n", &save)) {
        int used = 0; long pad = 0; char shex[1100];
        if (sscanf(line, "%d %1099s %ld", &used, shex, &pad) != 3 || pad < 0) { rc = BNS_EPARSE; break; }
        sigs[n].used = (used != 0);
        sigs[n].padding_len = (size_t)pad;
        if (sigs[n].used) {
            if (strcmp(shex, "-") == 0 || bn_parse_hex(shex, &s_store[n]) != BNS_OK) { rc = BNS_EPARSE; break; }
            sigs[n].s = s_store[n];
        }
        n++;
    }
    free(txt);
    if (rc == BNS_OK && n != AGENTD_RECOVERY_KEYS) rc = BNS_EPARSE;
    if (rc != BNS_OK) {
        snprintf(errmsg, errsz,
                 "malformed RECOVER_SIGS_FILE (need %d lines '<used 0|1> <s_hex|-> <paddingByteCount>')",
                 AGENTD_RECOVERY_KEYS);
        for (int i = 0; i < AGENTD_RECOVERY_KEYS; i++) { bn_free(s_store[i]); s_store[i] = NULL; }
    }
    return rc;
}

static int cmd_recover(const char *state_file, bool confirm, int *out_exit_code)
{
    char errmsg[256];

    char *json = NULL;
    int rc = read_file(state_file, &json);
    if (rc != BNS_OK) return agentd_failed("cannot read STATE_FILE", out_exit_code);
    agent_state_t st;
    rc = agent_state_from_json(json, &st);
    free(json);
    if (rc != BNS_OK) return agentd_failed("cannot parse STATE_FILE", out_exit_code);

    /* NEW_AGENT_KEY_FILE is required (the rotated-to agent keyfile). */
    const char *na_env = env_get("NEW_AGENT_KEY_FILE");
    if (na_env == NULL || na_env[0] == '\0') {
        agent_state_free(&st);
        return agentd_failed("NEW_AGENT_KEY_FILE (the rotated-to agent keyfile) is required for recover", out_exit_code);
    }

    printf("recover plan: recoveryCount %" PRId64 " threshold %" PRId64 " of %zu guardians\n",
           st.state.recovery_count, st.params.recovery_threshold, st.rabin_pub.num_recovery);

    if (!confirm) {
        printf("\nDRY RUN — set CONFIRM_MAINNET_BROADCAST=yes to broadcast. STATE_FILE unchanged.\n");
        agent_state_free(&st);
        if (out_exit_code) *out_exit_code = 0;
        return BNS_OK;
    }

    /* ---- LIVE recover: AgentTea.recover spend under the identity + broadcast ---- */
    int exit_code = 1;
    cli_ctx_t c; memset(&c, 0, sizeof c);
    bool cli_ok = false;
    ecdsa_key_t *new_agent_key = NULL;
    woc_client_t *woc = NULL;
    ecdsa_key_t *funder_key = NULL;
    funding_utxos_t funding; memset(&funding, 0, sizeof funding);
    contract_funding_input_t *fund = NULL;
    byte_buf_t fund_script; byte_buf_init(&fund_script);
    scrypt_artifact_t artifact; memset(&artifact, 0, sizeof artifact);
    bool artifact_ok = false;
    agent_tea_t inst; memset(&inst, 0, sizeof inst);
    bool inst_ok = false;
    byte_buf_t script_code; byte_buf_init(&script_code);
    tx_builder_t b; tx_builder_init(&b);
    byte_buf_t recovery_msg; byte_buf_init(&recovery_msg);
    rabin_key_t rkeys[AGENTD_RECOVERY_KEYS];        memset(rkeys, 0, sizeof rkeys);
    rabin_sig_t rsigs[AGENTD_RECOVERY_KEYS];        memset(rsigs, 0, sizeof rsigs);
    bn_t *ext_s[AGENTD_RECOVERY_KEYS];              memset(ext_s, 0, sizeof ext_s);
    contract_recover_sig_t recover_sigs[AGENTD_RECOVERY_KEYS]; memset(recover_sigs, 0, sizeof recover_sigs);
    bool custodial = false;
    char *raw_hex = NULL, *txid = NULL, *state_json = NULL, *new_agent_hex = NULL;
    bonsai_err_ctx err; memset(&err, 0, sizeof err);
    uint8_t new_agent33[33];

    if (cli_setup_keys(&c, out_exit_code) != BNS_OK) {  /* prints its own error */
        agent_state_free(&st);
        return BNS_OK;
    }
    cli_ok = true;

    /* New agent pubkey from NEW_AGENT_KEY_FILE. */
    if (load_key(na_env, c.net, &new_agent_key, NULL, errmsg, sizeof errmsg) != BNS_OK)
        goto recover_fail;
    {
        ecdsa_pubkey_t *pub = NULL;
        if (ecdsa_key_derive_pubkey(new_agent_key, &pub) != BNS_OK ||
            ecdsa_pubkey_serialize_compressed(pub, new_agent33) != BNS_OK) {
            ecdsa_pubkey_free(pub); snprintf(errmsg, sizeof errmsg, "cannot derive new agent pubkey"); goto recover_fail;
        }
        ecdsa_pubkey_free(pub);
    }

    /* WoC client + tip-liveness pre-flight. */
    woc = chain_broadcast_woc_new(c.net, &err);
    if (woc == NULL) { snprintf(errmsg, sizeof errmsg, "%s", err.msg[0] ? err.msg : "cannot create WoC client"); goto recover_fail; }
    if (st.tip.txid) {
        bool spent = false;
        int chk = woc_client_is_output_spent(woc, st.tip.txid, st.tip.vout, &spent);
        if (chk != BNS_OK) {
            snprintf(errmsg, sizeof errmsg,
                     "recover: cannot verify tip %s:%u liveness (WoC error) — refusing to broadcast against an unverified tip; retry when the provider is reachable",
                     st.tip.txid, st.tip.vout);
            goto recover_fail;
        }
        if (spent) {
            snprintf(errmsg, sizeof errmsg,
                     "recover: persisted tip %s:%u is already spent on-chain — STATE_FILE is stale; re-sync first",
                     st.tip.txid, st.tip.vout);
            goto recover_fail;
        }
    }

    /* Load artifact + reconstruct the instance at the tip. */
    {
        const char *apath = agentd_artifact_path();
        if (apath == NULL) { snprintf(errmsg, sizeof errmsg, "AgentTea artifact not found (set AGENT_TEA_ARTIFACT)"); goto recover_fail; }
        if (load_artifact(apath, &artifact) != BNS_OK) { snprintf(errmsg, sizeof errmsg, "cannot load AgentTea artifact"); goto recover_fail; }
        artifact_ok = true;
    }
    uint64_t identity_value = 0;
    if (instance_at_tip(&st, &artifact, &inst, &script_code, &identity_value, errmsg, sizeof errmsg) != BNS_OK)
        goto recover_fail;
    inst_ok = true;

    /* recoveryMsg the guardians sign = AGNT_RECOVER_V1 || ricardianHash || newAgent
     * || num2bin(recoveryCount,8), at the CURRENT (pre-increment) on-chain count. */
    if (inst.params.ricardian_hash.len != 32) { snprintf(errmsg, sizeof errmsg, "instance ricardianHash is not 32 bytes"); goto recover_fail; }
    if (agent_tea_recovery_msg(inst.params.ricardian_hash.data, new_agent33,
                               inst.state.recovery_count, &recovery_msg) != BNS_OK) {
        snprintf(errmsg, sizeof errmsg, "cannot build recovery message"); goto recover_fail;
    }

    /* Obtain the M-of-3 guardian Rabin sigs: custodial self-sign if deploy persisted
     * the keys, else from RECOVER_SIGS_FILE (operator-supplied / true social recovery). */
    if (load_recovery_keys(state_file, rkeys) == BNS_OK) {
        custodial = true;
        for (int i = 0; i < AGENTD_RECOVERY_KEYS; i++) {
            /* sanity: the stored key must match the on-chain guardian pubkey. */
            bn_t *n = NULL; char *ndec = NULL;
            if (rabin_pubkey(&rkeys[i], &n) != BNS_OK || bn_to_dec(n, &ndec) != BNS_OK) {
                bn_free(n); free(ndec); snprintf(errmsg, sizeof errmsg, "recovery key %d: cannot derive pubkey", i); goto recover_fail;
            }
            bn_free(n);
            if (i >= (int)st.rabin_pub.num_recovery || st.rabin_pub.recovery[i] == NULL ||
                strcmp(ndec, st.rabin_pub.recovery[i]) != 0) {
                free(ndec);
                snprintf(errmsg, sizeof errmsg, "recovery key store does not match on-chain guardian %d (stale store?)", i);
                goto recover_fail;
            }
            free(ndec);
            if (rabin_sign(recovery_msg.data, recovery_msg.len, &rkeys[i], &rsigs[i]) != BNS_OK) {
                snprintf(errmsg, sizeof errmsg, "recovery key %d: rabin_sign failed", i); goto recover_fail;
            }
            recover_sigs[i].used = true;
            recover_sigs[i].s = rsigs[i].s;
            recover_sigs[i].padding_len = rsigs[i].padding_byte_count;
        }
    } else {
        const char *sigs_file = env_get("RECOVER_SIGS_FILE");
        if (sigs_file == NULL || sigs_file[0] == '\0') {
            snprintf(errmsg, sizeof errmsg,
                     "no guardian signatures: set RECOVER_SIGS_FILE, or deploy with AGENTD_PERSIST_RECOVERY_KEYS=yes");
            goto recover_fail;
        }
        if (load_external_recover_sigs(sigs_file, recover_sigs, ext_s, errmsg, sizeof errmsg) != BNS_OK)
            goto recover_fail;
    }

    /* Require at least recoveryThreshold used sigs (the contract enforces this too). */
    {
        int used = 0;
        for (int i = 0; i < AGENTD_RECOVERY_KEYS; i++) if (recover_sigs[i].used) used++;
        if (used < (int)st.params.recovery_threshold) {
            snprintf(errmsg, sizeof errmsg, "only %d guardian sig(s); need recoveryThreshold=%" PRId64,
                     used, st.params.recovery_threshold);
            goto recover_fail;
        }
        printf("recover: %s %d-of-%zu guardian signatures\n",
               custodial ? "custodial self-signed" : "external", used, st.rabin_pub.num_recovery);
    }

    /* feeSats = sendTimeFeeWindow(2*scriptBytes + 3000).recommended (identity recreated 1:1). */
    fee_window_t fw;
    if (chain_broadcast_fee_window(2 * (int64_t)script_code.len + 3000, AGENTD_FEE_PER_KB, &fw, &err) != BNS_OK) {
        snprintf(errmsg, sizeof errmsg, "fee window failed"); goto recover_fail;
    }
    int64_t fee_sats = fw.recommended;

    /* Funding for the fee: FUND_RECOVER_KEY_FILE, defaulting to FUND_ACTION_KEY_FILE. */
    {
        const char *frk = env_get("FUND_RECOVER_KEY_FILE");
        const char *fund_env = (frk && frk[0]) ? "FUND_RECOVER_KEY_FILE" : "FUND_ACTION_KEY_FILE";
        if (pick_funding_from_keyfile(woc, fund_env, c.net, fee_sats,
                                      &funder_key, &funding, errmsg, sizeof errmsg) != BNS_OK)
            goto recover_fail;
        if (funder_key == NULL || funding.count == 0) {
            snprintf(errmsg, sizeof errmsg, "FUND_RECOVER_KEY_FILE/FUND_ACTION_KEY_FILE is required to fund the recover fee"); goto recover_fail;
        }
    }

    /* Change to the Elder address (recover has no non-final/locktime constraint). */
    uint8_t change20[20];
    {
        uint8_t elder_pub[33];
        ecdsa_pubkey_t *pub = NULL;
        if (ecdsa_key_derive_pubkey(c.elder, &pub) != BNS_OK ||
            ecdsa_pubkey_serialize_compressed(pub, elder_pub) != BNS_OK) {
            ecdsa_pubkey_free(pub); snprintf(errmsg, sizeof errmsg, "cannot derive elder pubkey"); goto recover_fail;
        }
        ecdsa_pubkey_free(pub);
        if (resolve_change_hash160(elder_pub, c.net, change20, errmsg, sizeof errmsg) != BNS_OK) goto recover_fail;
    }

    agent_tea_utxo_t identity;
    memset(&identity, 0, sizeof identity);
    snprintf(identity.txid_display, sizeof identity.txid_display, "%s", st.tip.txid ? st.tip.txid : "");
    identity.vout = st.tip.vout;
    identity.value = identity_value;

    agent_tea_builder_opts_t opts;
    memset(&opts, 0, sizeof opts);
    opts.funding = &funding;
    opts.change_hash160 = change20;
    opts.has_change = true;
    opts.fee_sats = (uint64_t)fee_sats;
    opts.has_fee_sats = true;

    if (build_agent_tea_recover(&inst, &identity, new_agent33, &opts, &b) != BNS_OK) {
        snprintf(errmsg, sizeof errmsg, "recover build failed"); goto recover_fail;
    }

    /* recover lays out [identity-state, OP_RETURN, change?]; change is the last output. */
    int64_t change_amount = 0;
    if (b.tx.num_outputs >= 3)
        change_amount = (int64_t)b.tx.outputs[b.tx.num_outputs - 1].satoshis;

    if (build_funding_inputs(&funding, 1, funder_key, &fund, &fund_script, errmsg, sizeof errmsg) != BNS_OK)
        goto recover_fail;

    if (contract_recover_sign(&b, 0, script_code.data, script_code.len, identity_value,
                              new_agent33, recover_sigs, change_amount, change20,
                              AGENT_TEA_RECOVER_SELECTOR, fund, funding.count, &raw_hex) != BNS_OK) {
        snprintf(errmsg, sizeof errmsg, "recover signing failed"); goto recover_fail;
    }

    printf("signed raw tx: %s\n", raw_hex);

    if (chain_broadcast_send(woc, raw_hex, &txid, &err) != BNS_OK) {
        snprintf(errmsg, sizeof errmsg, "%s", err.msg[0] ? err.msg : "broadcast failed"); goto recover_fail;
    }
    printf("BROADCAST OK: %s\n", txid);
    printf("RECOVER broadcast: %s\n", txid);
    persist_broadcast_journal(state_file, "recover", txid);  /* durable record before JSON write */

    /* Persist: rotate agent_pub_key, recoveryCount += 1, new tip, history += recover. */
    {
        new_agent_hex = hex_encode(new_agent33, 33);
        if (new_agent_hex) { free(st.agent_pub_key); st.agent_pub_key = new_agent_hex; new_agent_hex = NULL; }
        st.state.recovery_count = st.state.recovery_count + 1;

        free(st.tip.txid);       st.tip.txid = strdup(txid);
        st.tip.vout = 0;
        free(st.tip.raw_tx_hex);  st.tip.raw_tx_hex = strdup(raw_hex);

        size_t nh = st.num_history;
        agent_history_entry_t *h2 = realloc(st.history, (nh + 1) * sizeof *h2);
        if (h2) {
            st.history = h2;
            st.history[nh].op = strdup("recover");
            st.history[nh].txid = strdup(txid);
            st.num_history = nh + 1;
        }

        if (agent_state_to_json(&st, &state_json) != BNS_OK ||
            agentd_write_file_atomic(state_file, state_json) != BNS_OK) {
            snprintf(errmsg, sizeof errmsg, "cannot write STATE_FILE %s", state_file); goto recover_fail;
        }
    }
    exit_code = 0;

recover_fail:
    if (exit_code != 0) agentd_failed(errmsg, out_exit_code);
    else if (out_exit_code) *out_exit_code = 0;
    free(new_agent_hex);
    free(state_json);
    free(txid);
    free(raw_hex);
    for (int i = 0; i < AGENTD_RECOVERY_KEYS; i++) {
        rabin_sig_free(&rsigs[i]);
        rabin_key_free(&rkeys[i]);
        bn_free(ext_s[i]);
    }
    byte_buf_free(&recovery_msg);
    tx_builder_free(&b);
    free(fund);
    byte_buf_free(&fund_script);
    byte_buf_free(&script_code);
    if (inst_ok) agent_tea_free(&inst);
    if (artifact_ok) scrypt_artifact_free(&artifact);
    funding_utxos_free(&funding);
    ecdsa_key_free(funder_key);
    ecdsa_key_free(new_agent_key);
    chain_broadcast_woc_free(woc);
    if (cli_ok) cli_ctx_free(&c);
    agent_state_free(&st);
    return BNS_OK;
}

/* ------------------------------------------------------------------------- *
 * dispatch — mirrors cliMain.
 * ------------------------------------------------------------------------- */
int agentd_run(int argc, char **argv, int *out_exit_code)
{
    int dummy_exit = 0;
    if (out_exit_code == NULL) out_exit_code = &dummy_exit;
    *out_exit_code = 0;

    const char *cmd = (argc >= 2) ? argv[1] : NULL;

    bool is_known = cmd && (strcmp(cmd, "deploy") == 0 || strcmp(cmd, "action") == 0 ||
                            strcmp(cmd, "recover") == 0 ||
                            strcmp(cmd, "revoke") == 0 || strcmp(cmd, "status") == 0);
    bool is_help = cmd && (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0);

    if (cmd == NULL || is_help || !is_known) {
        printf("%s\n", HELP);
        /* unknown (non-help) command -> exit 2; help/no-arg -> exit 0. */
        if (cmd && !is_known && !is_help) *out_exit_code = 2;
        return BNS_OK;
    }

    /* STATE_FILE is required (throws "STATE_FILE is required"). */
    const char *state_file = env_get("STATE_FILE");
    if (state_file == NULL || state_file[0] == '\0')
        return agentd_failed("STATE_FILE is required", out_exit_code);

    if (strcmp(cmd, "status") == 0)
        return cmd_status(state_file, out_exit_code);

    bool confirm = confirm_mainnet_broadcast();

    if (strcmp(cmd, "deploy") == 0) return cmd_deploy(state_file, confirm, out_exit_code);
    if (strcmp(cmd, "action") == 0) return cmd_action(state_file, confirm, out_exit_code);
    if (strcmp(cmd, "recover") == 0) return cmd_recover(state_file, confirm, out_exit_code);
    if (strcmp(cmd, "revoke") == 0) return cmd_revoke(state_file, confirm, out_exit_code);

    return agentd_failed("unknown command", out_exit_code);
}
