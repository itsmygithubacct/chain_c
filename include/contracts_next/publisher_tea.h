/*
 * contracts_next/publisher_tea.h — the ARP-1 publisher-identity STATEFUL contract
 * (Pillar A on-chain half of ANNOUNCE -> delay -> ACTIVATE release). Enforces a
 * one-pending-release invariant, 2-of-2 announce co-sign, an in-script nLocktime
 * delay floor, K-of-3 charter-attestor Rabin quorum on activate, emergency cancel/
 * invalidate via a separate key, and domain-separated OP_RETURN receipts; the
 * 4-field mutable state is recreated on every spend.
 *
 * The C port reconstructs the lockingScript from the compiled PublisherTea
 * artifact (NOT yet in artifacts/) by substituting the 7 ctor @props + the 4
 * mutable state props as trailing state (scrypt/script_codec.h). It also owns the
 * per-method receipt preimage builders (each a DIFFERENT domain tag length and a
 * DIFFERENT field set — a single generic template would produce wrong lengths).
 *
 * TS origin: src/contracts-next/publisherTea.ts (PublisherTea: ZERO,
 * publisherKey, approverKey, cancelKey, publisherHash, delaySeconds,
 * attestorPubKeys[3], quorum; pending* + releaseCount state; announceRelease,
 * activateRelease, cancelPending, invalidateRelease, retire,
 * stateAndReceiptOutputs).
 *
 * DETERMINISM PINS (publisherTea.ts notes):
 *  (1) ACTIVATE commits releaseCount at PRE-increment value.
 *  (2) CANCEL commits pendingBundleHash BEFORE clearing.
 *  (3) the 4 domain tags have DIFFERENT byte lengths — do not assume 14.
 *  (4) int2ByteString(now,4) is a SIGNED 4-byte CScriptNum (2038 bound) — in
 *      lockstep with the arp/agent builders and the Python verifier.
 *  (5) hashOutputs is hash256 (double SHA256); receipts are single sha256 — do
 *      not confuse them.
 *  (6) ZERO is a literal 32-zero-byte Sha256; bundleHash != ZERO on announce.
 *  (7) attSeqs are per-attestor and independent; quorum messages are
 *      ArpAttest.attestationMsg(attSeqs[i], activateDigest) (arp_attest.h).
 */
#ifndef BONSAI_CONTRACTS_NEXT_PUBLISHER_TEA_H
#define BONSAI_CONTRACTS_NEXT_PUBLISHER_TEA_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/bignum.h"
#include "scrypt/scrypt_contract.h"
#include "contracts_next/arp_attest.h"
#include "lib/rabin_verifier.h"

/* Fixed charter attestor-set size (K-of-3). TS: FixedArray<RabinPubKey,3>. */
#define BONSAI_PUBLISHER_TEA_ATTESTORS 3

/* The 'no pending release' sentinel: 32 zero bytes as a 64-char hex string.
 * TS: PublisherTea.ZERO = Sha256(toByteString('00'.repeat(32))). */
#define BONSAI_PUBLISHER_TEA_ZERO_HEX \
    "0000000000000000000000000000000000000000000000000000000000000000"

/* The 4 ARP-1 publisher receipt domain tags, as exact preimage bytes. NOTE the
 * differing lengths — each receipt preimage is built separately. TS: arpTxBuilder
 * / publisherTea receipt domains. */
#define BONSAI_ARP_ANNOUNCE_TAG_HEX   "415250315f414e4e4f554e43455f5631"   /* 'ARP1_ANNOUNCE_V1' 16B   */
#define BONSAI_ARP_ACTRCPT_TAG_HEX    "415250315f414354524350545f5631"     /* 'ARP1_ACTRCPT_V1' 15B    */
#define BONSAI_ARP_CANCEL_TAG_HEX     "415250315f43414e43454c5f5631"       /* 'ARP1_CANCEL_V1' 14B     */
#define BONSAI_ARP_INVALIDATE_TAG_HEX "415250315f494e56414c49444154455f5631" /* 'ARP1_INVALIDATE_V1' 18B */

/* The 7 PublisherTea constructor arguments, in @prop declaration order. The
 * three keys are 33-byte compressed PubKeys; publisherHash is 32 raw bytes;
 * delaySeconds and quorum are bigint; attestorPubKeys is exactly 3 Rabin moduli.
 * Owns its members; *_free releases. TS: publisherTea.ts constructor. */
typedef struct {
    byte_buf_t publisher_key;     /* publisherKey (33B) — steal-target           */
    byte_buf_t approver_key;      /* approverKey (33B) — 2-of-2 co-sign          */
    byte_buf_t cancel_key;        /* cancelKey (33B) — emergency                 */
    byte_buf_t publisher_hash;    /* publisherHash Sha256 (32B) — identity binding*/
    bn_t      *delay_seconds;     /* delaySeconds (activation floor)             */
    bn_t      *attestor_pubkeys[BONSAI_PUBLISHER_TEA_ATTESTORS]; /* attestorPubKeys[3] (Rabin n) */
    bn_t      *quorum;            /* quorum K of 3                               */
} publisher_tea_params_t;

/* The 4 mutable @prop(true) state fields, in declaration order. Genesis:
 * pendingBundleHash/pendingFileSetRoot = ZERO, pendingAnnounceTime=0,
 * releaseCount=0. Hash fields are 32 raw bytes. Owns its members.
 * TS: publisherTea.ts @prop(true) pendingBundleHash/pendingFileSetRoot/
 * pendingAnnounceTime/releaseCount. */
typedef struct {
    byte_buf_t pending_bundle_hash;   /* pendingBundleHash Sha256 (32B); ZERO = none */
    byte_buf_t pending_file_set_root; /* pendingFileSetRoot Sha256 (32B)             */
    bn_t      *pending_announce_time; /* pendingAnnounceTime (nLocktime)             */
    bn_t      *release_count;         /* releaseCount                                */
} publisher_tea_state_t;

/* A live PublisherTea instance. The artifact is borrowed. TS: an instantiated
 * PublisherTea SmartContract. */
typedef struct {
    const scrypt_artifact_t *artifact; /* borrowed compiled publisherTea.json      */
    publisher_tea_params_t   params;   /* owned ctor args                          */
    publisher_tea_state_t    state;    /* owned current state                      */
} publisher_tea_t;

/* ---- lifecycle ---------------------------------------------------------- */

void publisher_tea_params_free(publisher_tea_params_t *p);
void publisher_tea_state_free(publisher_tea_state_t *s);
void publisher_tea_free(publisher_tea_t *c);

/* Initialise genesis state (pending* = ZERO/0, releaseCount=0). TS: publisherTea.ts
 * constructor state init. BNS_OK / BNS_ENOMEM. */
int publisher_tea_genesis_state(publisher_tea_state_t *out);

/* ---- locking-script reconstruction -------------------------------------- */

/* Reconstruct the stateful locking script bytes into `out` (init'd): substitutes
 * the 7 ctor args (ctor encoders) and appends the 4-field state suffix (state
 * encoders). Delegates to scrypt/script_codec.h.
 * BNS_OK / BNS_EINVAL / BNS_EPARSE / BNS_ENOMEM. */
int publisher_tea_locking_script(const publisher_tea_t *c, bool is_genesis,
                                 byte_buf_t *out);

/* ---- per-method receipt preimage builders ------------------------------- */
/* Each builds its receipt preimage (DIFFERENT tag + field set) appended to `out`
 * (init'd); the contract single-sha256's the result. `bundle_hash`/`file_set_root`/
 * `activate_digest`/`pending_bundle_hash` are 32 raw bytes; releaseCount/now are
 * taken at the values documented per pin above. */

/* ANNOUNCE receipt: tag(16) || ... || bundleHash(32) || fileSetRoot(32) ||
 * int2ByteString(now,4) ... TS: announceRelease receipt. BNS_OK/BNS_EINVAL/BNS_ENOMEM. */
int publisher_tea_announce_receipt(const publisher_tea_t *c,
                                   const uint8_t bundle_hash[32],
                                   const uint8_t file_set_root[32],
                                   int64_t now, byte_buf_t *out);

/* ACTIVATE receipt: tag(15) || ... || activateDigest(32) || releaseCount at
 * PRE-increment ... TS: activateRelease receipt. BNS_OK/BNS_EINVAL/BNS_ENOMEM. */
int publisher_tea_activate_receipt(const publisher_tea_t *c,
                                   const uint8_t activate_digest[32],
                                   byte_buf_t *out);

/* CANCEL receipt: tag(14) || ... || pendingBundleHash(32) committed BEFORE clear.
 * TS: cancelPending receipt. BNS_OK/BNS_EINVAL/BNS_ENOMEM. */
int publisher_tea_cancel_receipt(const publisher_tea_t *c, byte_buf_t *out);

/* INVALIDATE receipt: tag(18) || ... || activateDigest(32). TS: invalidateRelease
 * receipt. BNS_OK/BNS_EINVAL/BNS_ENOMEM. */
int publisher_tea_invalidate_receipt(const publisher_tea_t *c,
                                     const uint8_t activate_digest[32],
                                     byte_buf_t *out);

/* ---- activate quorum check ---------------------------------------------- */

/* Model activateRelease()'s K-of-3 quorum off-chain: for each i in 0..2 with
 * att_used[i] true, verify att_sigs[i] Rabin-verifies under attestorPubKeys[i]
 * over ArpAttest.attestationMsg(att_seqs[i], activateDigest); set *out_ok =
 * (validCount >= quorum). att_seqs are per-attestor independent bn_t. `activate_
 * digest` is 32 raw bytes. TS: publisherTea.ts::activateRelease quorum loop.
 * BNS_OK (result in *out_ok) / BNS_EINVAL / BNS_ENOMEM. */
int publisher_tea_check_quorum(const publisher_tea_t *c,
                               const uint8_t activate_digest[32],
                               const bn_t *att_seqs[BONSAI_PUBLISHER_TEA_ATTESTORS],
                               const rabin_verifier_sig_t *att_sigs[BONSAI_PUBLISHER_TEA_ATTESTORS],
                               const bool att_used[BONSAI_PUBLISHER_TEA_ATTESTORS],
                               bool *out_ok);

#endif /* BONSAI_CONTRACTS_NEXT_PUBLISHER_TEA_H */
