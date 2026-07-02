/*
 * live_agent_smoke_lib.c — C port of scripts/liveAgentSmoke.ts.
 *
 * LIVE Pillar-B AgentTea lifecycle smoke: deploy a 1-sat identity UTXO, run one
 * metered executeAction (below the validator threshold, committing a TEA receipt
 * hash in OP_RETURN), then revoke via the Elder kill switch. DRY-RUN by default —
 * it prints the plan and derived values without broadcasting; set
 * CONFIRM_MAINNET_BROADCAST=yes to actually send.
 *
 * The dry-run path (the only path exercised without a funded key and live WoC)
 * is faithful to the TS:
 *   - read KEY_FILE {wif,address}, derive the Elder address, verify WIF/address;
 *   - load-or-create the persisted ephemeral agent/counterparty keypair (mode
 *     0600) so the lifecycle is recoverable across re-runs;
 *   - build the AgentTea instance from the pinned charter params, reconstruct the
 *     genesis locking script;
 *   - print Network / Elder / ricardianHash / actionHash / identity sats /
 *     action cost units / script bytes;
 *   - print "DRY RUN — not broadcasting. ..." and return 0.
 *
 * The live broadcast branch (deploy -> action -> revoke) is wired through the
 * shared WoC-backed funding/broadcast helper (chain_broadcast.h), the AgentTea
 * unsigned-tx layout, and the per-method sign+finalize entry points
 * (txbuilders/contract_sign.h): each step selects funding from the Elder address,
 * builds the byte-exact unsigned tx, signs it, prints the signed raw hex + txid,
 * broadcasts it, and waits for confirmation before the next step. See
 * live_agent_smoke_broadcast() below.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include "scripts/live_agent_smoke.h"
#include "scripts/script_support.h"
#include "common/error.h"
#include "common/bytes.h"
#include "common/hex.h"
#include "crypto/hash.h"
#include "crypto/ecdsa.h"
#include "crypto/rabin.h"
#include "crypto/bignum.h"
#include "bsv/address.h"
#include "bsv/tx.h"
#include "bsv/tx_builder.h"
#include "bsv/script_utils.h"
#include "scrypt/scrypt_contract.h"
#include "scrypt/artifact_loader.h"
#include "contracts_next/agent_tea.h"
#include "txbuilders/agent_tea_tx_builder.h"
#include "txbuilders/contract_sign.h"
#include "scripts/chain_broadcast.h"
#include "chainSources/woc_client.h"

/* ---- pinned charter constants (TS liveAgentSmoke.ts) -------------------- */
#define LAS_IDENTITY_SATS   1
#define LAS_PER_TX          "100000"
#define LAS_DAILY           "1000000"
#define LAS_WINDOW          "86400"
#define LAS_GRAD            "10000"
#define LAS_VAL_THRESHOLD   "50000"
#define LAS_ACTION_COST     "1000"
#define LAS_RECOVERY_THRESH "2"

/* The action message hashed into actionHash (TS line 138). */
#define LAS_ACTION_MSG \
    "live smoke action: prove the Pillar B lifecycle on mainnet"

/* ---- small helpers ------------------------------------------------------ */

/* sha256(UTF-8 bytes of `s`) as 32 raw bytes — sha256(toByteString(s,true)). */
static void sha256_utf8(const char *s, uint8_t out[BONSAI_SHA256_LEN])
{
    sha256((const uint8_t *)s, strlen(s), out);
}

/* Derive the compressed-pubkey hex of a WIF private key (caller frees *out). */
static int wif_to_pubkey_hex(const char *wif, char **out, bonsai_err_ctx *err)
{
    ecdsa_key_t *k = NULL;
    ecdsa_pubkey_t *pub = NULL;
    int rc = ecdsa_key_from_wif(wif, &k, NULL);
    if (rc != BNS_OK) return bns_fail(err, rc, "bad WIF");
    rc = ecdsa_key_derive_pubkey(k, &pub);
    if (rc == BNS_OK) rc = ecdsa_pubkey_to_hex(pub, out);
    ecdsa_pubkey_free(pub);
    ecdsa_key_free(k);
    return rc;
}

/* Derive the 33-byte compressed pubkey bytes of a WIF key into `out` (init'd). */
static int wif_to_pubkey_bytes(const char *wif, byte_buf_t *out, bonsai_err_ctx *err)
{
    ecdsa_key_t *k = NULL;
    ecdsa_pubkey_t *pub = NULL;
    uint8_t sec[BONSAI_ECDSA_PUBKEY_COMPRESSED_LEN];
    int rc = ecdsa_key_from_wif(wif, &k, NULL);
    if (rc != BNS_OK) return bns_fail(err, rc, "bad WIF");
    rc = ecdsa_key_derive_pubkey(k, &pub);
    if (rc == BNS_OK) rc = ecdsa_pubkey_serialize_compressed(pub, sec);
    if (rc == BNS_OK) rc = byte_buf_from(out, sec, sizeof sec);
    ecdsa_pubkey_free(pub);
    ecdsa_key_free(k);
    return rc;
}

/* Resolve the AgentTea compiled-artifact JSON path. Env AGENT_TEA_ARTIFACT
 * overrides; otherwise probe known repo-relative locations. Returns a pointer
 * to a static buffer, or NULL if none is readable. */
static const char *agent_tea_artifact_path(void)
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

/* ---- ephemeral agent/counterparty keys --------------------------------- */

typedef struct {
    char *agent_wif;        /* owned */
    char *counterparty_wif; /* owned */
} ephemeral_keys_t;

static void ephemeral_keys_free(ephemeral_keys_t *e)
{
    if (e == NULL) return;
    free(e->agent_wif);
    free(e->counterparty_wif);
    e->agent_wif = e->counterparty_wif = NULL;
}

/* Read a JSON string field "key": "value" from a small flat object. Returns a
 * freshly malloc'd value or NULL. (The ephemeral file is written by this tool,
 * so a minimal extractor is sufficient and avoids a JSON dep here.) */
static char *json_string_field(const char *text, const char *key)
{
    char needle[64];
    snprintf(needle, sizeof needle, "\"%s\"", key);
    const char *p = strstr(text, needle);
    if (p == NULL) return NULL;
    p = strchr(p + strlen(needle), ':');
    if (p == NULL) return NULL;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != '"') return NULL;
    p++;
    const char *end = strchr(p, '"');
    if (end == NULL) return NULL;
    size_t n = (size_t)(end - p);
    char *out = malloc(n + 1);
    if (out == NULL) return NULL;
    memcpy(out, p, n);
    out[n] = '\0';
    return out;
}

/* Generate a fresh mainnet WIF (compressed). Caller frees *out. */
static int new_mainnet_wif(char **out, bonsai_err_ctx *err)
{
    ecdsa_key_t *k = NULL;
    uint8_t sec[BONSAI_ECDSA_SECKEY_LEN];
    int rc = ecdsa_key_random(&k);
    if (rc != BNS_OK) return bns_fail(err, rc, "key generate failed");
    rc = ecdsa_key_to_bytes(k, sec);
    if (rc == BNS_OK) rc = wif_encode(sec, true, BSV_MAINNET, out);
    ecdsa_key_free(k);
    if (rc != BNS_OK) bns_fail(err, rc, "wif encode failed");
    return rc;
}

/* Load EPHEMERAL_FILE, or create-and-persist a fresh pair (mode 0600).
 * Mirrors loadOrCreateEphemeral() in the TS. */
static int load_or_create_ephemeral(const char *path, ephemeral_keys_t *out,
                                    bonsai_err_ctx *err)
{
    memset(out, 0, sizeof *out);

    FILE *f = fopen(path, "rb");
    if (f != NULL) {
        char buf[4096];
        size_t n = fread(buf, 1, sizeof buf - 1, f);
        fclose(f);
        buf[n] = '\0';
        char *a = json_string_field(buf, "agentWif");
        char *c = json_string_field(buf, "counterpartyWif");
        if (a != NULL && c != NULL) {
            out->agent_wif = a;
            out->counterparty_wif = c;
            return BNS_OK;
        }
        free(a);
        free(c);
        /* fall through to regenerate on a malformed file (matches TS catch) */
    }

    int rc = new_mainnet_wif(&out->agent_wif, err);
    if (rc != BNS_OK) { ephemeral_keys_free(out); return rc; }
    rc = new_mainnet_wif(&out->counterparty_wif, err);
    if (rc != BNS_OK) { ephemeral_keys_free(out); return rc; }

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        ephemeral_keys_free(out);
        return bns_fail(err, BNS_EPERSIST, "cannot write %s: %s",
                        path, strerror(errno));
    }
    char json[1024];
    int len = snprintf(json, sizeof json,
        "{\n  \"agentWif\": \"%s\",\n  \"counterpartyWif\": \"%s\"\n}\n",
        out->agent_wif, out->counterparty_wif);
    ssize_t w = write(fd, json, (size_t)len);
    close(fd);
    if (w != len) {
        ephemeral_keys_free(out);
        return bns_fail(err, BNS_EPERSIST, "short write to %s", path);
    }
    return BNS_OK;
}

/* ---- AgentTea params assembly ------------------------------------------ */

/* Fresh Rabin modulus n (= p*q) into *out. Mirrors rabinPubKey(genRabinKey()). */
static int new_rabin_pubkey(bn_t **out, bonsai_err_ctx *err)
{
    rabin_key_t key = {0};
    int rc = rabin_keygen(&key);
    if (rc != BNS_OK) { bns_fail(err, rc, "rabin keygen failed"); return rc; }
    rc = rabin_pubkey(&key, out);
    rabin_key_free(&key);
    if (rc != BNS_OK) bns_fail(err, rc, "rabin pubkey failed");
    return rc;
}

static int bn_dec(const char *dec, bn_t **out, bonsai_err_ctx *err)
{
    int rc = bn_parse_dec(dec, out);
    if (rc != BNS_OK) bns_fail(err, rc, "bad constant %s", dec);
    return rc;
}

/* ---- live broadcast helpers ------------------------------------------- */

/* Fee rate pinned by the TS (FEE_PER_KB = 100 sats/KB). */
#define LAS_FEE_PER_KB 100

/* Signed-size estimates used for the explicit per-tx fee windows. These MUST be
 * derived from the ACTUAL AgentTea locking-script length (`genesis_lock->len`,
 * in scope at every use site), not a fixed guess: the executeAction unlocking
 * script embeds the full locking script in its SigHashPreimage (~1x) and the tx
 * recreates the identity output (~1x), so the action tx is ≈ 2x the locking
 * script; the revoke carries the unlocking script (~1x). Under-sizing here
 * underpays the fee and the tx sticks in mempool (observed: a 55 KB action sized
 * as 31 KB paid ~72 sat/KB and was not mined while the 131 sat/KB deploy was). */
#define LAS_ACTION_SIGNED_BYTES (2 * (int64_t)genesis_lock->len + 4000)
#define LAS_REVOKE_SIGNED_BYTES ((int64_t)genesis_lock->len + 2500)
/* The deploy carries the ~15 KB AgentTea identity locking script as output[0];
 * size its fee from the actual locking-script length plus a generous overhead
 * for the funding input + change output + headers. */
#define LAS_DEPLOY_OVERHEAD_BYTES 400

/* Derive an owned ecdsa_key_t + its 33-byte compressed pubkey from a WIF. */
static int key_and_pub_from_wif(const char *wif, ecdsa_key_t **out_key,
                                uint8_t out_pub33[33], bonsai_err_ctx *err)
{
    ecdsa_key_t *k = NULL;
    ecdsa_pubkey_t *pub = NULL;
    int rc = ecdsa_key_from_wif(wif, &k, NULL);
    if (rc != BNS_OK) return bns_fail(err, rc, "bad WIF");
    rc = ecdsa_key_derive_pubkey(k, &pub);
    if (rc == BNS_OK) rc = ecdsa_pubkey_serialize_compressed(pub, out_pub33);
    ecdsa_pubkey_free(pub);
    if (rc != BNS_OK) { ecdsa_key_free(k); return bns_fail(err, rc, "key derive failed"); }
    *out_key = k;
    return BNS_OK;
}

/* Set up the contract_funding_input_t array for `funding` against the elder
 * P2PKH script (elder_h160). The input indices start at `first_input_index`
 * (input[0] is the contract identity). `script_buf` is one shared P2PKH buffer
 * the caller owns/frees; all entries borrow it. */
static int build_funding_inputs(const funding_utxos_t *funding,
                                size_t first_input_index,
                                const ecdsa_key_t *elder_key,
                                const byte_buf_t *p2pkh,
                                contract_funding_input_t *out, size_t out_cap)
{
    if (funding->count > out_cap) return BNS_ERANGE;
    for (size_t i = 0; i < funding->count; i++) {
        out[i].input_index = first_input_index + i;
        out[i].script_code = p2pkh->data;
        out[i].script_code_len = p2pkh->len;
        out[i].value = (uint64_t)funding->items[i].satoshis;
        out[i].key = elder_key;
    }
    return BNS_OK;
}

/* The last output's satoshis (the change output the builders append last), or 0
 * if the change was dropped as dust / there is no change output. Also reports
 * whether a change output is present. */
static int64_t last_output_change(const tx_builder_t *b, bool *has_change)
{
    if (b->tx.num_outputs == 0) { *has_change = false; return 0; }
    /* The change output is the P2PKH last output; the builders only append it
     * when non-dust. We treat the last output as change iff it is a 25-byte
     * P2PKH (76a914..88ac). State/OP_RETURN/payout outputs are larger or 0-sat. */
    const bsv_txout_t *o = &b->tx.outputs[b->tx.num_outputs - 1];
    if (o->script.len == 25 && o->script.data[0] == 0x76 &&
        o->script.data[1] == 0xa9 && o->script.data[2] == 0x14) {
        *has_change = true;
        return (int64_t)o->satoshis;
    }
    *has_change = false;
    return 0;
}

/* Broadcast one fully-signed raw tx: print the signed hex + txid, send, wait for
 * confirmation. *out_txid receives the freshly malloc'd txid (caller frees). */
static int broadcast_and_confirm(woc_client_t *woc, const char *raw_hex,
                                 const char *label, char **out_txid,
                                 bonsai_err_ctx *err)
{
    *out_txid = NULL;
    printf("%s signed raw tx : %s\n", label, raw_hex);
    char *txid = NULL;
    int rc = chain_broadcast_send(woc, raw_hex, &txid, err);
    if (rc != BNS_OK) return rc;
    printf("%s broadcast    : %s\n", label, txid);
    printf("BROADCAST OK: %s\n", txid);

    /* Wait for a CONFIRMED parent before the next step (matches the TS
     * waitConfirmed; the action/revoke chain onto a confirmed contract so large
     * unconfirmed-ancestor packages are never dropped). */
    tx_status_t status;
    memset(&status, 0, sizeof status);
    rc = woc_client_wait_for_confirmation(woc, txid, NULL, &status);
    if (rc != BNS_OK) {
        bns_fail(err, rc, "%s: confirmation wait failed", label);
        free(txid);
        return rc;
    }
    *out_txid = txid;
    return BNS_OK;
}

/* Drive the live deploy -> executeAction -> revoke lifecycle on mainnet.
 *
 * `inst` is the GENESIS AgentTea instance (its locking script == `genesis_lock`).
 * Funding for every step is selected from the Elder address via the shared WoC
 * helper; each tx is signed byte-exact and broadcast, and we wait for a confirmed
 * parent before chaining the next spend. SKIP_ACTION=1 deploys then revokes.
 *
 * Returns BNS_OK with *out_exit_code set; on failure records `err` and returns a
 * non-OK code (the caller prints "LIVE SMOKE FAILED: ...").
 */
static int live_agent_smoke_broadcast(agent_tea_t *inst,
                                      const byte_buf_t *genesis_lock,
                                      const key_file_t *kf,
                                      const ephemeral_keys_t *eph,
                                      const char *elder_address,
                                      const uint8_t action_hash[32],
                                      bonsai_err_ctx *err,
                                      int *out_exit_code)
{
    int rc = BNS_OK;
    *out_exit_code = 1;

    /* Owned state. */
    ecdsa_key_t *elder_key = NULL, *agent_key = NULL, *cp_key = NULL;
    uint8_t elder_pub[33], agent_pub[33], cp_pub[33];
    uint8_t elder_h160[20];
    byte_buf_t elder_p2pkh; byte_buf_init(&elder_p2pkh);
    woc_client_t *woc = NULL;
    bn_t *amount = NULL;          /* ACTION_COST */
    bn_t *attested_limit = NULL;  /* == ACTION_COST */
    bn_t *rabin_s = NULL;         /* dummy 0 */
    char *deploy_txid = NULL, *action_txid = NULL, *revoke_txid = NULL;
    funding_utxos_t funding; memset(&funding, 0, sizeof funding);
    bool funding_init = false;
    agent_tea_state_t next_state; memset(&next_state, 0, sizeof next_state);
    bool next_state_init = false;

    /* Provenance hash is all-zero (TS: no provenance for the smoke action). */
    uint8_t provenance_hash[32];
    memset(provenance_hash, 0, sizeof provenance_hash);

    /* ---- keys ---- */
    rc = key_and_pub_from_wif(kf->wif, &elder_key, elder_pub, err);
    if (rc != BNS_OK) goto out;
    rc = key_and_pub_from_wif(eph->agent_wif, &agent_key, agent_pub, err);
    if (rc != BNS_OK) goto out;
    rc = key_and_pub_from_wif(eph->counterparty_wif, &cp_key, cp_pub, err);
    if (rc != BNS_OK) goto out;
    hash160(elder_pub, 33, elder_h160);
    rc = build_p2pkh_script(elder_h160, &elder_p2pkh);
    if (rc != BNS_OK) { bns_fail(err, rc, "elder P2PKH build failed"); goto out; }

    /* ACTION_COST + dummy validator sig (below the validator threshold). */
    rc = bn_dec(LAS_ACTION_COST, &amount, err);
    if (rc != BNS_OK) goto out;
    rc = bn_dec(LAS_ACTION_COST, &attested_limit, err);
    if (rc != BNS_OK) goto out;
    rc = bn_dec("0", &rabin_s, err);
    if (rc != BNS_OK) goto out;

    /* ---- WoC client (mainnet) ---- */
    woc = chain_broadcast_woc_new(BSV_MAINNET, err);
    if (woc == NULL) { rc = err->code ? err->code : BNS_ENET; goto out; }

    /* Fee windows (TS: sendTimeFeeWindow(..).recommended at FEE_PER_KB). */
    fee_window_t fw_deploy, fw_action, fw_revoke;
    int64_t deploy_size = (int64_t)genesis_lock->len + LAS_DEPLOY_OVERHEAD_BYTES;
    rc = chain_broadcast_fee_window(deploy_size, LAS_FEE_PER_KB, &fw_deploy, err);
    if (rc == BNS_OK) rc = chain_broadcast_fee_window(LAS_ACTION_SIGNED_BYTES, LAS_FEE_PER_KB, &fw_action, err);
    if (rc == BNS_OK) rc = chain_broadcast_fee_window(LAS_REVOKE_SIGNED_BYTES, LAS_FEE_PER_KB, &fw_revoke, err);
    if (rc != BNS_OK) goto out;

    /* =====================================================================
     * 1. DEPLOY — funded P2PKH input(s) -> 1-sat identity output + change.
     * ===================================================================== */
    {
        int64_t need = (int64_t)LAS_IDENTITY_SATS + fw_deploy.recommended;
        rc = chain_broadcast_select_funding(woc, elder_address, need, &funding, err);
        if (rc != BNS_OK) goto out;
        funding_init = true;

        tx_builder_t b; tx_builder_init(&b);
        uint64_t total_in = 0;
        for (size_t i = 0; i < funding.count; i++) {
            rc = tx_builder_add_input(&b, funding.items[i].tx_id,
                                      funding.items[i].output_index, NULL, 0,
                                      0xffffffffu);
            if (rc != BNS_OK) { tx_builder_free(&b); bns_fail(err, rc, "deploy input"); goto out; }
            total_in += (uint64_t)funding.items[i].satoshis;
        }
        /* output[0]: genesis identity locking script @ IDENTITY_SATS. */
        rc = tx_builder_add_output(&b, genesis_lock->data, genesis_lock->len,
                                   LAS_IDENTITY_SATS);
        if (rc != BNS_OK) { tx_builder_free(&b); bns_fail(err, rc, "deploy id output"); goto out; }
        /* output[1]: change to Elder = total_in - IDENTITY_SATS - fee. */
        uint64_t fee = (uint64_t)fw_deploy.recommended;
        if (total_in < (uint64_t)LAS_IDENTITY_SATS + fee) {
            tx_builder_free(&b);
            rc = bns_fail(err, BNS_ERANGE, "deploy: insufficient funding for fee");
            goto out;
        }
        uint64_t change = total_in - (uint64_t)LAS_IDENTITY_SATS - fee;
        if (change >= 1) {
            rc = tx_builder_add_output(&b, elder_p2pkh.data, elder_p2pkh.len, change);
            if (rc != BNS_OK) { tx_builder_free(&b); bns_fail(err, rc, "deploy change"); goto out; }
        }

        contract_funding_input_t fin[16];
        rc = build_funding_inputs(&funding, 0, elder_key, &elder_p2pkh, fin, 16);
        if (rc != BNS_OK) { tx_builder_free(&b); bns_fail(err, rc, "deploy funding inputs"); goto out; }

        char *hex = NULL;
        rc = build_contract_deploy(&b, fin, funding.count, &hex);
        tx_builder_free(&b);
        if (rc != BNS_OK) { bns_fail(err, rc, "deploy sign failed"); goto out; }

        printf("\n[1/3] DEPLOY\n");
        rc = broadcast_and_confirm(woc, hex, "[1/3] DEPLOY", &deploy_txid, err);
        free(hex);
        if (rc != BNS_OK) goto out;

        funding_utxos_free(&funding);
        funding_init = false;
    }

    bool skip_action = false;
    {
        const char *sa = env_get("SKIP_ACTION");
        skip_action = (sa != NULL && strcmp(sa, "1") == 0);
    }

    /* The identity UTXO being spent next: deploy output 0, value IDENTITY_SATS. */
    agent_tea_utxo_t identity;
    memset(&identity, 0, sizeof identity);
    snprintf(identity.txid_display, sizeof identity.txid_display, "%s", deploy_txid);
    identity.vout = 0;
    identity.value = LAS_IDENTITY_SATS;

    /* The contract script being spent at input[0] is the GENESIS locking script. */
    /* `revoke_target_lock` tracks the locking script of the identity the revoke
     * will spend (genesis if action skipped, else the recreated next-state). */
    byte_buf_t revoke_target_lock; byte_buf_init(&revoke_target_lock);
    rc = byte_buf_append(&revoke_target_lock, genesis_lock->data, genesis_lock->len);
    if (rc != BNS_OK) { bns_fail(err, rc, "lock copy"); goto out_lock; }

    /* =====================================================================
     * 2. executeAction — metered action below the validator threshold.
     *    Hand-built so output[0] carries the NEXT state (txCount=1, ...) while
     *    the OP_RETURN receipt commits the PRE-increment state (txCount=0).
     * ===================================================================== */
    if (!skip_action) {
        /* now = floor(Date.now()/1000) - 600 (TS: slightly past vs miner clocks). */
        int64_t now = (int64_t)time(NULL) - 600;

        /* Build the NEXT-state instance for output[0]: txCount=1,
         * spentInWindow=ACTION_COST, windowStart=now, tier=1, recoveryCount=0. */
        char nowdec[32];
        snprintf(nowdec, sizeof nowdec, "%lld", (long long)now);
        rc = bn_parse_dec("1", &next_state.tx_count);
        if (rc == BNS_OK) rc = bn_parse_dec(LAS_ACTION_COST, &next_state.spent_in_window);
        if (rc == BNS_OK) rc = bn_parse_dec(nowdec, &next_state.window_start);
        if (rc == BNS_OK) rc = bn_parse_dec("1", &next_state.tier);
        if (rc == BNS_OK) rc = bn_parse_dec("0", &next_state.recovery_count);
        if (rc != BNS_OK) { bns_fail(err, rc, "next state"); goto out_lock; }
        next_state_init = true;

        agent_tea_t next = *inst;        /* share params + artifact (borrowed) */
        next.state = next_state;

        /* receiptHash from the PRE-state instance (txCount=0). */
        char *receipt_hex = NULL;
        rc = agent_tea_receipt_hash(inst, cp_pub, amount, action_hash,
                                    provenance_hash, now, &receipt_hex);
        if (rc != BNS_OK) { bns_fail(err, rc, "receipt hash"); goto out_lock; }
        uint8_t receipt_hash[32];
        rc = hex_decode_fixed(receipt_hex, receipt_hash, sizeof receipt_hash);
        free(receipt_hex);
        if (rc != BNS_OK) { bns_fail(err, rc, "receipt decode"); goto out_lock; }

        /* recreated identity (NEXT-state) locking script for output[0] + the
         * revoke target lock. */
        byte_buf_t next_lock; byte_buf_init(&next_lock);
        rc = agent_tea_locking_script(&next, /*is_genesis=*/false, &next_lock);
        if (rc != BNS_OK) { byte_buf_free(&next_lock); bns_fail(err, rc, "next lock"); goto out_lock; }

        /* funding for the action fee. */
        rc = chain_broadcast_select_funding(woc, elder_address,
                                            fw_action.recommended, &funding, err);
        if (rc != BNS_OK) { byte_buf_free(&next_lock); goto out_lock; }
        funding_init = true;

        tx_builder_t b; tx_builder_init(&b);
        /* input[0]: identity (sequence 0, < 0xffffffff for nLockTime). */
        rc = tx_builder_add_input(&b, identity.txid_display, identity.vout, NULL, 0, 0u);
        uint64_t total_in = identity.value;
        for (size_t i = 0; rc == BNS_OK && i < funding.count; i++) {
            rc = tx_builder_add_input(&b, funding.items[i].tx_id,
                                      funding.items[i].output_index, NULL, 0,
                                      0xffffffffu);
            total_in += (uint64_t)funding.items[i].satoshis;
        }
        /* output[0]: recreated identity (constant balance, NEXT state). */
        if (rc == BNS_OK)
            rc = tx_builder_add_output(&b, next_lock.data, next_lock.len, identity.value);
        byte_buf_free(&next_lock);
        /* output[1]: OP_RETURN <receiptHash> (0 sat). */
        if (rc == BNS_OK) {
            byte_buf_t op; byte_buf_init(&op);
            rc = build_opreturn_script(receipt_hash, 32, &op);
            if (rc == BNS_OK) rc = tx_builder_add_output(&b, op.data, op.len, 0);
            byte_buf_free(&op);
        }
        if (rc != BNS_OK) { tx_builder_free(&b); bns_fail(err, rc, "action outputs"); goto out_lock; }
        /* output[2]: change = total_in - identity.value(recreated) - fee. */
        uint64_t fee = (uint64_t)fw_action.recommended;
        /* available = total_in - output[0] (identity.value) - output[1] (0). */
        if (total_in < identity.value + fee) {
            tx_builder_free(&b);
            rc = bns_fail(err, BNS_ERANGE, "action: insufficient funding for fee");
            goto out_lock;
        }
        uint64_t change = total_in - identity.value - fee;
        if (change >= 1) {
            rc = tx_builder_add_output(&b, elder_p2pkh.data, elder_p2pkh.len, change);
            if (rc != BNS_OK) { tx_builder_free(&b); bns_fail(err, rc, "action change"); goto out_lock; }
        }
        tx_builder_set_locktime(&b, (uint32_t)now);

        contract_funding_input_t fin[16];
        rc = build_funding_inputs(&funding, 1, elder_key, &elder_p2pkh, fin, 16);
        if (rc != BNS_OK) { tx_builder_free(&b); bns_fail(err, rc, "action funding inputs"); goto out_lock; }

        bool has_change = false;
        int64_t change_amount = last_output_change(&b, &has_change);

        contract_execute_args_t args; memset(&args, 0, sizeof args);
        args.agent_key = agent_key;
        args.counterparty_key = cp_key;
        args.counterparty_pub33 = cp_pub;
        args.amount = amount;
        args.hash32 = action_hash;
        args.provenance_hash32 = provenance_hash;
        args.attested_limit = attested_limit;
        args.rabin_s = rabin_s;
        args.rabin_padding = NULL;
        args.rabin_padding_len = 0;

        char *hex = NULL;
        rc = contract_execute_sign(&b, 0, genesis_lock->data, genesis_lock->len,
                                   identity.value, &args, change_amount, elder_h160,
                                   /*selector executeAction=*/0,
                                   fin, funding.count, &hex);
        tx_builder_free(&b);
        if (rc != BNS_OK) { bns_fail(err, rc, "action sign failed"); goto out_lock; }

        printf("\n[2/3] EXECUTE\n");
        rc = broadcast_and_confirm(woc, hex, "[2/3] EXECUTE", &action_txid, err);
        if (rc == BNS_OK) {
            /* TS prints actionTx.outputs[1].script.toHex() (the full OP_RETURN
             * script: 006a20 || receiptHash). */
            byte_buf_t op; byte_buf_init(&op);
            if (build_opreturn_script(receipt_hash, 32, &op) == BNS_OK) {
                printf("      receipt OP_RETURN  : ");
                for (size_t i = 0; i < op.len; i++) printf("%02x", op.data[i]);
                printf("\n");
            }
            byte_buf_free(&op);
        }
        free(hex);
        if (rc != BNS_OK) goto out_lock;

        funding_utxos_free(&funding);
        funding_init = false;

        /* The revoke now spends the recreated NEXT-state identity (action tx
         * output 0). Rebuild the revoke target lock + identity outpoint. */
        snprintf(identity.txid_display, sizeof identity.txid_display, "%s", action_txid);
        identity.vout = 0;
        identity.value = LAS_IDENTITY_SATS;

        byte_buf_free(&revoke_target_lock);
        byte_buf_init(&revoke_target_lock);
        rc = agent_tea_locking_script(&next, false, &revoke_target_lock);
        if (rc != BNS_OK) { bns_fail(err, rc, "revoke target lock"); goto out_lock; }
    } else {
        printf("\n[2/3] EXECUTE skipped (SKIP_ACTION=1) — revoking the deployed identity\n");
    }

    /* =====================================================================
     * 3. REVOKE — the Elder kill switch: full balance back to the Elder.
     * ===================================================================== */
    {
        /* Build the revoke target instance: genesis when action skipped, else
         * the next-state instance (its locking script is revoke_target_lock,
         * which contract_revoke_sign re-derives via the passed scriptCode). The
         * revoke builder only needs params.owner + identity, so `inst`/`next`
         * params suffice; we reuse `inst` (params are identical, state is unused
         * by revoke's output layout). */
        rc = chain_broadcast_select_funding(woc, elder_address,
                                            fw_revoke.recommended, &funding, err);
        if (rc != BNS_OK) goto out_lock;
        funding_init = true;

        agent_tea_builder_opts_t opts; memset(&opts, 0, sizeof opts);
        opts.funding = &funding;
        opts.change_hash160 = elder_h160;
        opts.has_change = true;
        opts.fee_sats = (uint64_t)fw_revoke.recommended;
        opts.has_fee_sats = true;

        tx_builder_t b; tx_builder_init(&b);
        rc = build_agent_tea_revoke(inst, &identity, &opts, &b);
        if (rc != BNS_OK) { tx_builder_free(&b); bns_fail(err, rc, "revoke build failed"); goto out_lock; }

        contract_funding_input_t fin[16];
        rc = build_funding_inputs(&funding, 1, elder_key, &elder_p2pkh, fin, 16);
        if (rc != BNS_OK) { tx_builder_free(&b); bns_fail(err, rc, "revoke funding inputs"); goto out_lock; }

        bool has_change = false;
        int64_t change_amount = last_output_change(&b, &has_change);

        char *hex = NULL;
        rc = contract_revoke_sign(&b, 0, revoke_target_lock.data,
                                  revoke_target_lock.len, identity.value, elder_key,
                                  change_amount, elder_h160,
                                  /*selector AgentTea.revoke=*/4,
                                  fin, funding.count, &hex);
        tx_builder_free(&b);
        if (rc != BNS_OK) { bns_fail(err, rc, "revoke sign failed"); goto out_lock; }

        printf("\n[3/3] REVOKE\n");
        rc = broadcast_and_confirm(woc, hex, "[3/3] REVOKE", &revoke_txid, err);
        free(hex);
        if (rc != BNS_OK) goto out_lock;

        funding_utxos_free(&funding);
        funding_init = false;
    }

    /* ---- success summary (TS LIVE SMOKE COMPLETE block) ---- */
    printf("\nLIVE SMOKE COMPLETE — on mainnet:\n");
    printf("  deploy : https://whatsonchain.com/tx/%s\n", deploy_txid);
    if (action_txid)
        printf("  action : https://whatsonchain.com/tx/%s\n", action_txid);
    printf("  revoke : https://whatsonchain.com/tx/%s\n", revoke_txid);
    *out_exit_code = 0;
    rc = BNS_OK;

out_lock:
    byte_buf_free(&revoke_target_lock);
out:
    if (funding_init) funding_utxos_free(&funding);
    if (next_state_init) agent_tea_state_free(&next_state);
    free(deploy_txid);
    free(action_txid);
    free(revoke_txid);
    bn_free(amount);
    bn_free(attested_limit);
    bn_free(rabin_s);
    if (woc) chain_broadcast_woc_free(woc);
    byte_buf_free(&elder_p2pkh);
    ecdsa_key_free(elder_key);
    ecdsa_key_free(agent_key);
    ecdsa_key_free(cp_key);
    return rc;
}

/* ---- dry-build: build+sign all 3 lifecycle txs, thread them internally from
 * ONE funding UTXO (deploy's change funds the action, the action's change funds
 * the revoke), and emit {txs:[{name,rawTx,inputs:[{scriptHex,satoshis}]}]} to a
 * JSON file WITHOUT broadcasting. This lets the whole lifecycle be verified
 * (scryptlib Interpreter) before any irreversible spend. The exact bytes emitted
 * here are what gets broadcast. ----------------------------------------------- */

static int las_compute_txid(const char *rawhex, char **out)
{
    bsv_tx_t t; tx_init(&t);
    int rc = tx_deserialize(rawhex, &t);
    if (rc == BNS_OK) rc = tx_id(&t, out);
    tx_free(&t);
    return rc;
}

static int las_emit_tx_json(FILE *fp, bool first, const char *name,
                            const char *rawhex,
                            const byte_buf_t *const prev_scripts[],
                            const int64_t prev_vals[], size_t n)
{
    fprintf(fp, "%s\n  {\"name\":\"%s\",\"rawTx\":\"%s\",\"inputs\":[",
            first ? "" : ",", name, rawhex);
    for (size_t i = 0; i < n; i++) {
        char *h = hex_encode(prev_scripts[i]->data, prev_scripts[i]->len);
        if (h == NULL) return BNS_ENOMEM;
        fprintf(fp, "%s{\"scriptHex\":\"%s\",\"satoshis\":%lld}",
                i ? "," : "", h, (long long)prev_vals[i]);
        free(h);
    }
    fprintf(fp, "]}");
    return BNS_OK;
}

static int live_agent_smoke_drybuild(agent_tea_t *inst,
                                     const byte_buf_t *genesis_lock,
                                     const key_file_t *kf,
                                     const ephemeral_keys_t *eph,
                                     const char *elder_address,
                                     const uint8_t action_hash[32],
                                     const char *out_path,
                                     bonsai_err_ctx *err,
                                     int *out_exit_code)
{
    int rc = BNS_OK;
    *out_exit_code = 1;

    ecdsa_key_t *elder_key = NULL, *agent_key = NULL, *cp_key = NULL;
    uint8_t elder_pub[33], agent_pub[33], cp_pub[33];
    uint8_t elder_h160[20];
    byte_buf_t elder_p2pkh; byte_buf_init(&elder_p2pkh);
    woc_client_t *woc = NULL;
    bn_t *amount = NULL, *attested_limit = NULL, *rabin_s = NULL;
    char *deploy_txid = NULL, *action_txid = NULL;
    funding_utxos_t funding; memset(&funding, 0, sizeof funding);
    bool funding_init = false;
    agent_tea_state_t next_state; memset(&next_state, 0, sizeof next_state);
    bool next_state_init = false;
    byte_buf_t next_lock; byte_buf_init(&next_lock);
    byte_buf_t revoke_target_lock; byte_buf_init(&revoke_target_lock);
    FILE *fp = NULL;
    uint8_t provenance_hash[32]; memset(provenance_hash, 0, sizeof provenance_hash);

    char prev_txid[65] = {0};      /* the change UTXO that funds the next step */
    uint32_t prev_vout = 0;
    int64_t prev_val = 0;

    rc = key_and_pub_from_wif(kf->wif, &elder_key, elder_pub, err); if (rc) goto out;
    rc = key_and_pub_from_wif(eph->agent_wif, &agent_key, agent_pub, err); if (rc) goto out;
    rc = key_and_pub_from_wif(eph->counterparty_wif, &cp_key, cp_pub, err); if (rc) goto out;
    hash160(elder_pub, 33, elder_h160);
    rc = build_p2pkh_script(elder_h160, &elder_p2pkh);
    if (rc) { bns_fail(err, rc, "elder P2PKH"); goto out; }

    rc = bn_dec(LAS_ACTION_COST, &amount, err); if (rc) goto out;
    rc = bn_dec(LAS_ACTION_COST, &attested_limit, err); if (rc) goto out;
    rc = bn_dec("0", &rabin_s, err); if (rc) goto out;

    woc = chain_broadcast_woc_new(BSV_MAINNET, err);
    if (!woc) { rc = err->code ? err->code : BNS_ENET; goto out; }

    fee_window_t fw_deploy, fw_action, fw_revoke;
    int64_t deploy_size = (int64_t)genesis_lock->len + LAS_DEPLOY_OVERHEAD_BYTES;
    rc = chain_broadcast_fee_window(deploy_size, LAS_FEE_PER_KB, &fw_deploy, err);
    if (!rc) rc = chain_broadcast_fee_window(LAS_ACTION_SIGNED_BYTES, LAS_FEE_PER_KB, &fw_action, err);
    if (!rc) rc = chain_broadcast_fee_window(LAS_REVOKE_SIGNED_BYTES, LAS_FEE_PER_KB, &fw_revoke, err);
    if (rc) goto out;

    fp = fopen(out_path, "w");
    if (!fp) { rc = bns_fail(err, BNS_EPERSIST, "cannot write %s", out_path); goto out; }
    fprintf(fp, "{\"txs\":[");

    bool skip_action = false;
    { const char *sa = env_get("SKIP_ACTION"); skip_action = (sa && strcmp(sa, "1") == 0); }

    /* ===== 1. DEPLOY (funded from one real WoC UTXO) ===== */
    {
        int64_t need = (int64_t)LAS_IDENTITY_SATS + fw_deploy.recommended;
        rc = chain_broadcast_select_funding(woc, elder_address, need, &funding, err);
        if (rc) goto out;
        funding_init = true;

        tx_builder_t b; tx_builder_init(&b);
        uint64_t total_in = 0;
        for (size_t i = 0; i < funding.count; i++) {
            rc = tx_builder_add_input(&b, funding.items[i].tx_id, funding.items[i].output_index, NULL, 0, 0xffffffffu);
            if (rc) { tx_builder_free(&b); bns_fail(err, rc, "deploy input"); goto out; }
            total_in += (uint64_t)funding.items[i].satoshis;
        }
        rc = tx_builder_add_output(&b, genesis_lock->data, genesis_lock->len, LAS_IDENTITY_SATS);
        if (rc) { tx_builder_free(&b); bns_fail(err, rc, "deploy id out"); goto out; }
        uint64_t fee = (uint64_t)fw_deploy.recommended;
        if (total_in < (uint64_t)LAS_IDENTITY_SATS + fee) { tx_builder_free(&b); rc = bns_fail(err, BNS_ERANGE, "deploy underfunded"); goto out; }
        uint64_t change = total_in - (uint64_t)LAS_IDENTITY_SATS - fee;
        if (change < 1) { tx_builder_free(&b); rc = bns_fail(err, BNS_ERANGE, "deploy: no change to thread"); goto out; }
        rc = tx_builder_add_output(&b, elder_p2pkh.data, elder_p2pkh.len, change);
        if (rc) { tx_builder_free(&b); bns_fail(err, rc, "deploy change"); goto out; }

        contract_funding_input_t fin[16];
        rc = build_funding_inputs(&funding, 0, elder_key, &elder_p2pkh, fin, 16);
        if (rc) { tx_builder_free(&b); bns_fail(err, rc, "deploy fin"); goto out; }
        char *hex = NULL;
        rc = build_contract_deploy(&b, fin, funding.count, &hex);
        tx_builder_free(&b);
        if (rc) { bns_fail(err, rc, "deploy sign"); goto out; }

        const byte_buf_t *ps[16]; int64_t pv[16];
        for (size_t i = 0; i < funding.count; i++) { ps[i] = &elder_p2pkh; pv[i] = funding.items[i].satoshis; }
        rc = las_emit_tx_json(fp, true, "deploy", hex, ps, pv, funding.count);
        if (rc == BNS_OK) rc = las_compute_txid(hex, &deploy_txid);
        free(hex);
        if (rc) { bns_fail(err, rc, "deploy emit/txid"); goto out; }

        snprintf(prev_txid, sizeof prev_txid, "%s", deploy_txid);
        prev_vout = 1; prev_val = (int64_t)change;   /* out0 id, out1 change */
        funding_utxos_free(&funding); funding_init = false;
        printf("[1/3] deploy built   txid=%s  change=%lld (threads action)\n", deploy_txid, (long long)change);
    }

    agent_tea_utxo_t identity; memset(&identity, 0, sizeof identity);
    snprintf(identity.txid_display, sizeof identity.txid_display, "%s", deploy_txid);
    identity.vout = 0; identity.value = LAS_IDENTITY_SATS;
    rc = byte_buf_append(&revoke_target_lock, genesis_lock->data, genesis_lock->len);
    if (rc) { bns_fail(err, rc, "lock copy"); goto out; }

    /* ===== 2. executeAction (funded from deploy's change) ===== */
    if (!skip_action) {
        int64_t now = (int64_t)time(NULL) - 600;
        char nowdec[32]; snprintf(nowdec, sizeof nowdec, "%lld", (long long)now);
        rc = bn_parse_dec("1", &next_state.tx_count);
        if (!rc) rc = bn_parse_dec(LAS_ACTION_COST, &next_state.spent_in_window);
        if (!rc) rc = bn_parse_dec(nowdec, &next_state.window_start);
        if (!rc) rc = bn_parse_dec("1", &next_state.tier);
        if (!rc) rc = bn_parse_dec("0", &next_state.recovery_count);
        if (rc) { bns_fail(err, rc, "next state"); goto out; }
        next_state_init = true;
        agent_tea_t next = *inst; next.state = next_state;

        char *receipt_hex = NULL;
        rc = agent_tea_receipt_hash(inst, cp_pub, amount, action_hash, provenance_hash, now, &receipt_hex);
        if (rc) { bns_fail(err, rc, "receipt"); goto out; }
        uint8_t receipt_hash[32];
        rc = hex_decode_fixed(receipt_hex, receipt_hash, 32); free(receipt_hex);
        if (rc) { bns_fail(err, rc, "receipt dec"); goto out; }

        rc = agent_tea_locking_script(&next, false, &next_lock);
        if (rc) { bns_fail(err, rc, "next lock"); goto out; }

        funding.items = calloc(1, sizeof *funding.items);
        if (!funding.items) { rc = BNS_ENOMEM; goto out; }
        funding.count = 1; funding_init = true;
        snprintf(funding.items[0].tx_id, sizeof funding.items[0].tx_id, "%s", prev_txid);
        funding.items[0].output_index = prev_vout; funding.items[0].satoshis = prev_val;

        tx_builder_t b; tx_builder_init(&b);
        rc = tx_builder_add_input(&b, identity.txid_display, identity.vout, NULL, 0, 0u);
        uint64_t total_in = identity.value;
        if (!rc) { rc = tx_builder_add_input(&b, funding.items[0].tx_id, funding.items[0].output_index, NULL, 0, 0xffffffffu); total_in += (uint64_t)prev_val; }
        if (!rc) rc = tx_builder_add_output(&b, next_lock.data, next_lock.len, identity.value);
        if (!rc) { byte_buf_t op; byte_buf_init(&op); rc = build_opreturn_script(receipt_hash, 32, &op); if (!rc) rc = tx_builder_add_output(&b, op.data, op.len, 0); byte_buf_free(&op); }
        if (rc) { tx_builder_free(&b); bns_fail(err, rc, "action outs"); goto out; }
        uint64_t fee = (uint64_t)fw_action.recommended;
        if (total_in < identity.value + fee) { tx_builder_free(&b); rc = bns_fail(err, BNS_ERANGE, "action underfunded"); goto out; }
        uint64_t change = total_in - identity.value - fee;
        if (change < 1) { tx_builder_free(&b); rc = bns_fail(err, BNS_ERANGE, "action no change"); goto out; }
        rc = tx_builder_add_output(&b, elder_p2pkh.data, elder_p2pkh.len, change);
        if (rc) { tx_builder_free(&b); bns_fail(err, rc, "action change"); goto out; }
        tx_builder_set_locktime(&b, (uint32_t)now);

        contract_funding_input_t fin[16];
        rc = build_funding_inputs(&funding, 1, elder_key, &elder_p2pkh, fin, 16);
        if (rc) { tx_builder_free(&b); bns_fail(err, rc, "action fin"); goto out; }
        bool hc = false; int64_t change_amount = last_output_change(&b, &hc);

        contract_execute_args_t args; memset(&args, 0, sizeof args);
        args.agent_key = agent_key; args.counterparty_key = cp_key; args.counterparty_pub33 = cp_pub;
        args.amount = amount; args.hash32 = action_hash; args.provenance_hash32 = provenance_hash;
        args.attested_limit = attested_limit; args.rabin_s = rabin_s; args.rabin_padding = NULL; args.rabin_padding_len = 0;

        char *hex = NULL;
        rc = contract_execute_sign(&b, 0, genesis_lock->data, genesis_lock->len, identity.value, &args, change_amount, elder_h160, 0, fin, funding.count, &hex);
        tx_builder_free(&b);
        if (rc) { bns_fail(err, rc, "action sign"); goto out; }

        const byte_buf_t *ps[2] = { genesis_lock, &elder_p2pkh }; int64_t pv[2] = { (int64_t)identity.value, prev_val };
        rc = las_emit_tx_json(fp, false, "executeAction", hex, ps, pv, 2);
        if (!rc) rc = las_compute_txid(hex, &action_txid);
        free(hex);
        if (rc) { bns_fail(err, rc, "action emit"); goto out; }

        snprintf(prev_txid, sizeof prev_txid, "%s", action_txid);
        prev_vout = 2; prev_val = (int64_t)change;    /* out0 id, out1 opreturn, out2 change */
        funding_utxos_free(&funding); funding_init = false;

        snprintf(identity.txid_display, sizeof identity.txid_display, "%s", action_txid);
        identity.vout = 0; identity.value = LAS_IDENTITY_SATS;
        byte_buf_free(&revoke_target_lock); byte_buf_init(&revoke_target_lock);
        rc = byte_buf_append(&revoke_target_lock, next_lock.data, next_lock.len);
        if (rc) { bns_fail(err, rc, "revoke lock copy"); goto out; }
        printf("[2/3] executeAction  txid=%s  change=%lld (threads revoke)\n", action_txid, (long long)change);
    } else {
        printf("[2/3] executeAction skipped (SKIP_ACTION=1)\n");
    }

    /* ===== 3. REVOKE (funded from the prior change) ===== */
    {
        funding.items = calloc(1, sizeof *funding.items);
        if (!funding.items) { rc = BNS_ENOMEM; goto out; }
        funding.count = 1; funding_init = true;
        snprintf(funding.items[0].tx_id, sizeof funding.items[0].tx_id, "%s", prev_txid);
        funding.items[0].output_index = prev_vout; funding.items[0].satoshis = prev_val;

        agent_tea_builder_opts_t opts; memset(&opts, 0, sizeof opts);
        opts.funding = &funding; opts.change_hash160 = elder_h160; opts.has_change = true;
        opts.fee_sats = (uint64_t)fw_revoke.recommended; opts.has_fee_sats = true;

        tx_builder_t b; tx_builder_init(&b);
        rc = build_agent_tea_revoke(inst, &identity, &opts, &b);
        if (rc) { tx_builder_free(&b); bns_fail(err, rc, "revoke build"); goto out; }
        contract_funding_input_t fin[16];
        rc = build_funding_inputs(&funding, 1, elder_key, &elder_p2pkh, fin, 16);
        if (rc) { tx_builder_free(&b); bns_fail(err, rc, "revoke fin"); goto out; }
        bool hc = false; int64_t change_amount = last_output_change(&b, &hc);
        char *hex = NULL;
        rc = contract_revoke_sign(&b, 0, revoke_target_lock.data, revoke_target_lock.len, identity.value, elder_key, change_amount, elder_h160, 4, fin, funding.count, &hex);
        tx_builder_free(&b);
        if (rc) { bns_fail(err, rc, "revoke sign"); goto out; }
        const byte_buf_t *ps[2] = { &revoke_target_lock, &elder_p2pkh }; int64_t pv[2] = { (int64_t)identity.value, prev_val };
        rc = las_emit_tx_json(fp, false, "revoke", hex, ps, pv, 2);
        char *revoke_txid = NULL; if (!rc) rc = las_compute_txid(hex, &revoke_txid);
        free(hex);
        if (rc) { bns_fail(err, rc, "revoke emit"); goto out; }
        printf("[3/3] revoke built   txid=%s\n", revoke_txid ? revoke_txid : "?");
        free(revoke_txid);
        funding_utxos_free(&funding); funding_init = false;
    }

    fprintf(fp, "\n]}\n");
    fclose(fp); fp = NULL;
    printf("\nlifecycle txs written to %s — verify before broadcasting.\n", out_path);
    *out_exit_code = 0;
    rc = BNS_OK;

out:
    if (fp) fclose(fp);
    if (funding_init) funding_utxos_free(&funding);
    if (next_state_init) agent_tea_state_free(&next_state);
    byte_buf_free(&next_lock);
    byte_buf_free(&revoke_target_lock);
    free(deploy_txid); free(action_txid);
    bn_free(amount); bn_free(attested_limit); bn_free(rabin_s);
    if (woc) chain_broadcast_woc_free(woc);
    byte_buf_free(&elder_p2pkh);
    ecdsa_key_free(elder_key); ecdsa_key_free(agent_key); ecdsa_key_free(cp_key);
    return rc;
}

/* ---- run --------------------------------------------------------------- */

int live_agent_smoke_run(int argc, char **argv, int *out_exit_code)
{
    (void)argc; (void)argv;
    bonsai_err_ctx err = {0};
    int rc = BNS_OK;
    int exit_code = 0;

    if (out_exit_code) *out_exit_code = 0;

    /* Paths (TS: BONSAI_NOTARY_HOME / KEY_FILE / EPHEMERAL_FILE). */
    const char *home = bonsai_home();
    char key_file_default[1024];
    char eph_file_default[1024];
    snprintf(key_file_default, sizeof key_file_default, "%s/chain/test_bsv.json", home);
    snprintf(eph_file_default, sizeof eph_file_default, "%s/chain/live-smoke-keys.json", home);
    const char *key_file = env_or("KEY_FILE", key_file_default);
    const char *eph_file = env_or("EPHEMERAL_FILE", eph_file_default);

    /* Owned state to free on exit. */
    key_file_t kf = {0};
    ephemeral_keys_t eph = {0};
    char *elder_pub_hex = NULL, *agent_pub_hex = NULL;
    char *elder_address = NULL;
    scrypt_artifact_t artifact = {0};
    bool artifact_loaded = false;
    agent_tea_t inst = {0};
    bool params_init = false, state_init = false;
    byte_buf_t locking = {0};
    bool locking_init = false;

    /* ---- Elder key (the funded test key) ---- */
    rc = key_file_load(key_file, &kf, &err);
    if (rc != BNS_OK) { exit_code = 1; goto fail; }
    rc = key_file_verify(&kf, BSV_MAINNET, &err);
    if (rc != BNS_OK) {
        /* TS message: 'WIF does not derive the expected address ...' */
        snprintf(err.msg, sizeof err.msg,
                 "WIF does not derive the expected address — refusing to continue");
        exit_code = 1;
        goto fail;
    }

    {
        ecdsa_key_t *ek = NULL;
        ecdsa_pubkey_t *ep = NULL;
        rc = ecdsa_key_from_wif(kf.wif, &ek, NULL);
        if (rc == BNS_OK) rc = ecdsa_key_derive_pubkey(ek, &ep);
        if (rc == BNS_OK) rc = ecdsa_pubkey_to_hex(ep, &elder_pub_hex);
        if (rc == BNS_OK) rc = address_from_pubkey(ep, BSV_MAINNET, &elder_address);
        ecdsa_pubkey_free(ep);
        ecdsa_key_free(ek);
        if (rc != BNS_OK) { bns_fail(&err, rc, "elder key derive failed"); exit_code = 1; goto fail; }
    }

    /* ---- ephemeral agent/counterparty (persisted, recoverable) ---- */
    rc = load_or_create_ephemeral(eph_file, &eph, &err);
    if (rc != BNS_OK) { exit_code = 1; goto fail; }
    rc = wif_to_pubkey_hex(eph.agent_wif, &agent_pub_hex, &err);
    if (rc != BNS_OK) { exit_code = 1; goto fail; }

    /* ---- hashes (per-run; ricardianHash embeds the ISO8601 timestamp) ---- */
    char iso[32];
    {
        time_t now = time(NULL);
        struct tm tmv;
        gmtime_r(&now, &tmv);
        /* JS new Date().toISOString(): YYYY-MM-DDTHH:MM:SS.sssZ; the ms field is
         * non-deterministic and irrelevant to the smoke surface — use .000Z. */
        strftime(iso, sizeof iso, "%Y-%m-%dT%H:%M:%S.000Z", &tmv);
    }
    char charter[256];
    snprintf(charter, sizeof charter,
        "chain_c live smoke %s — ephemeral test identity",
        iso);

    uint8_t ricardian_hash[BONSAI_SHA256_LEN];
    uint8_t action_hash[BONSAI_SHA256_LEN];
    sha256_utf8(charter, ricardian_hash);
    sha256_utf8(LAS_ACTION_MSG, action_hash);
    char *ricardian_hex = hex_encode(ricardian_hash, sizeof ricardian_hash);
    char *action_hex = hex_encode(action_hash, sizeof action_hash);
    if (ricardian_hex == NULL || action_hex == NULL) {
        free(ricardian_hex); free(action_hex);
        bns_fail(&err, BNS_ENOMEM, "hex encode failed");
        exit_code = 1; goto fail;
    }

    /* ---- build the AgentTea instance ---- */
    const char *apath = agent_tea_artifact_path();
    if (apath == NULL) {
        bns_fail(&err, BNS_ENOTFOUND,
                 "AgentTea artifact not found (set AGENT_TEA_ARTIFACT)");
        free(ricardian_hex); free(action_hex);
        exit_code = 1; goto fail;
    }
    rc = load_artifact(apath, &artifact);
    if (rc != BNS_OK) {
        bns_fail(&err, rc, "load_artifact(%s) failed", apath);
        free(ricardian_hex); free(action_hex);
        exit_code = 1; goto fail;
    }
    artifact_loaded = true;

    agent_tea_params_t *p = &inst.params;
    memset(p, 0, sizeof *p);
    byte_buf_init(&p->owner);
    byte_buf_init(&p->agent);
    byte_buf_init(&p->ricardian_hash);
    params_init = true;

    rc = wif_to_pubkey_bytes(kf.wif, &p->owner, &err);
    if (rc == BNS_OK) rc = wif_to_pubkey_bytes(eph.agent_wif, &p->agent, &err);
    if (rc == BNS_OK) rc = byte_buf_from(&p->ricardian_hash, ricardian_hash, sizeof ricardian_hash);
    if (rc == BNS_OK) rc = bn_dec(LAS_PER_TX, &p->per_tx_limit, &err);
    if (rc == BNS_OK) rc = bn_dec(LAS_DAILY, &p->daily_limit, &err);
    if (rc == BNS_OK) rc = bn_dec(LAS_WINDOW, &p->window_duration, &err);
    if (rc == BNS_OK) rc = bn_dec(LAS_GRAD, &p->graduation_threshold, &err);
    if (rc == BNS_OK) rc = bn_dec(LAS_VAL_THRESHOLD, &p->validator_threshold, &err);
    if (rc == BNS_OK) rc = new_rabin_pubkey(&p->designated_validator_pubkey, &err);
    if (rc == BNS_OK) rc = new_rabin_pubkey(&p->validator_rabin_pubkey, &err);
    for (int i = 0; rc == BNS_OK && i < BONSAI_AGENT_TEA_RECOVERY_KEYS; i++)
        rc = new_rabin_pubkey(&p->recovery_keys[i], &err);
    if (rc == BNS_OK) rc = bn_dec(LAS_RECOVERY_THRESH, &p->recovery_threshold, &err);
    if (rc != BNS_OK) { free(ricardian_hex); free(action_hex); exit_code = 1; goto fail; }

    rc = agent_tea_genesis_state(&inst.state);
    if (rc != BNS_OK) { bns_fail(&err, rc, "genesis state failed");
        free(ricardian_hex); free(action_hex); exit_code = 1; goto fail; }
    state_init = true;

    inst.artifact = &artifact;

    byte_buf_init(&locking);
    locking_init = true;
    rc = agent_tea_locking_script(&inst, /*is_genesis=*/true, &locking);
    if (rc != BNS_OK) { bns_fail(&err, rc, "locking script reconstruction failed");
        free(ricardian_hex); free(action_hex); exit_code = 1; goto fail; }

    /* ---- plan output (TS console.log block) ---- */
    printf("Network        : %s\n", "livenet");
    printf("Elder (funded) : %s\n", elder_address);
    printf("ricardianHash  : %s\n", ricardian_hex);
    printf("actionHash     : %s\n", action_hex);
    printf("identity sats  : %d · action cost units: %s\n",
           LAS_IDENTITY_SATS, LAS_ACTION_COST);
    printf("script bytes   : %zu\n", locking.len);

    free(ricardian_hex);
    free(action_hex);

    /* ---- dry-BUILD gate: BONSAI_LIFECYCLE_DRYBUILD=<path> builds+signs all 3
     * lifecycle txs (threaded internally from one funding UTXO) and writes them
     * to <path> for offline verification — NO broadcast. Takes precedence. ---- */
    {
        const char *drybuild_out = env_get("BONSAI_LIFECYCLE_DRYBUILD");
        if (drybuild_out && drybuild_out[0]) {
            rc = live_agent_smoke_drybuild(&inst, &locking, &kf, &eph,
                                           elder_address, action_hash,
                                           drybuild_out, &err, &exit_code);
            if (rc != BNS_OK || exit_code != 0) { if (exit_code == 0) exit_code = 1; goto fail; }
            goto done;
        }
    }

    /* ---- dry-run gate (TS: CONFIRM_MAINNET_BROADCAST !== 'yes') ---- */
    if (!confirm_mainnet_broadcast()) {
        printf("\nDRY RUN — not broadcasting. "
               "Set CONFIRM_MAINNET_BROADCAST=yes to run live.\n");
        exit_code = 0;
        goto done;
    }

    /* ---- live broadcast (deploy -> action -> revoke) ---- */
    rc = live_agent_smoke_broadcast(&inst, &locking, &kf, &eph, elder_address,
                                    action_hash, &err, &exit_code);
    if (rc != BNS_OK || exit_code != 0) {
        if (exit_code == 0) exit_code = 1;
        goto fail;
    }
    goto done;

fail:
    if (err.msg[0])
        fprintf(stderr, "LIVE SMOKE FAILED: %s\n", err.msg);
    else
        fprintf(stderr, "LIVE SMOKE FAILED: %s\n", bns_err_name(rc));
    if (exit_code == 0) exit_code = 1;

done:
    if (locking_init) byte_buf_free(&locking);
    if (state_init) agent_tea_state_free(&inst.state);
    if (params_init) agent_tea_params_free(&inst.params);
    if (artifact_loaded) scrypt_artifact_free(&artifact);
    free(elder_address);
    free(elder_pub_hex);
    free(agent_pub_hex);
    ephemeral_keys_free(&eph);
    key_file_free(&kf);

    if (out_exit_code) *out_exit_code = exit_code;
    return BNS_OK;
}
