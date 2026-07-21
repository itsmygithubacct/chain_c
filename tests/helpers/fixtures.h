/*
 * fixtures.h — shared test constants + small fixture builders used across the
 * chain_c Unity suite (the C analogue of the `const`/`before()` blocks scattered
 * through the chain/tests TypeScript suites).
 *
 * Centralises: the agentd cross-language golden receipt hash, fixed test
 * pubkeys/hashes, the canonical charter prose path, a sample ProvenanceRecord,
 * the ricardianCharter VALID_BODY / BINDING fixtures, and a few helpers to
 * synthesize raw identity-chain txs (recreated-identity vs P2PKH-terminal,
 * with/without an OP_RETURN receipt) the way the TS FakeChain/MockChain do.
 *
 * Pure data + tiny builders — no ownership surprises: every char* returned is
 * documented as borrowed (static) or owned (caller frees).
 */
#ifndef BONSAI_TEST_FIXTURES_H
#define BONSAI_TEST_FIXTURES_H

#include <stddef.h>
#include <stdint.h>
#include "common/error.h"
#include "provenance.h"
#include "ricardian_charter.h"

/* ---- golden vectors ----------------------------------------------------- */

/* The agentd action-receipt cross-language golden (tests/agentd.test.ts: the
 * sha256 of the fixed 'aa..|02|bb..|03|cc..|..' receipt; also pinned in the
 * Python verifier). 64-char lowercase hex. */
#define FIX_AGENTD_GOLDEN_RECEIPT_HASH \
    "cdc6a3e1b4bfd4ac931e25d31aa0309938d10900807cd403f74222ed2a00a33d"

/* The exact receipt preimage hex whose sha256 == FIX_AGENTD_GOLDEN_RECEIPT_HASH:
 *   'aa'*32 || 02 || 'bb'*32 || 03 || 'cc'*32 || int2ByteString(1234,8) ||
 *   'dd'*32 || 'ee'*32 || int2ByteString(7,8) || int2ByteString(1700000000,4)
 * (lowercase, NUL-terminated). TS: tests/agentd.test.ts golden vector. */
extern const char FIX_AGENTD_GOLDEN_RECEIPT_PREIMAGE_HEX[];

/* ---- fixed test hashes / keys ------------------------------------------- */

/* A 64-char all-'a' / all-'b' / all-zero Sha256-shaped hex string. The TS
 * suites lean on 'a'.repeat(64) / 'b'.repeat(64) txids and 'aa'.repeat(32)
 * receipt hashes; these mirror the common literals. */
#define FIX_TXID_A   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define FIX_TXID_B   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define FIX_TXID_G   "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"  /* NOT hex */
#define FIX_ZERO32_HEX BONSAI_ZERO_PROVENANCE  /* 64 zero chars */

/* A fixed, valid 33-byte compressed secp256k1 pubkey (02-prefixed) as 66-hex.
 * Deterministic so identity/charter tests can pin a literal agentPubKey. This is
 * the compressed pubkey of secret = 0x01..01 (32 bytes of 0x01); see tx_helper.h
 * fix_test_seckey() to obtain the matching private key. */
extern const char FIX_PUBKEY_COMPRESSED_HEX[];

/* ---- charter fixtures (tests/priscilla/ricardianCharter.test.ts) -------- */

/* The canonical legal prose, relative to the chain_c source root (ctest runs
 * with WORKING_DIRECTORY = chain_c). TS: legal/ricardian-prose.md. */
#define FIX_CHARTER_PROSE_PATH "legal/ricardian-prose.md"

/* The five-line VALID_BODY of a params block (no markers). TS: VALID_BODY. */
extern const char FIX_CHARTER_VALID_BODY[];

/* Wrap a params body in the begin/end-marker charter envelope exactly as the TS
 * `block(body)` helper:
 *   "# charter\n\n<!-- ricardian:params:begin -->\n<body>\n<!-- ricardian:params:end -->\n"
 * Returns a freshly malloc'd NUL-terminated string (caller frees) or NULL on OOM.
 * TS: tests/priscilla/ricardianCharter.test.ts::block. */
char *fix_charter_block(const char *body);

/* Fill *out with the canonical test DeploymentBinding (TS: BINDING):
 *   agentPubKey='02aa', designatedValidatorPubKey='3', validatorRabinPubKey='5',
 *   maxSlashingTarget='7', minSlashConfirmations='1',
 *   initialSlashCheckpointHash='ab'*32.
 * Allocates owned strings; release with deployment_binding_free.
 * BNS_OK / BNS_ENOMEM. */
int fix_charter_binding(deployment_binding_t *out);

/* ---- provenance fixture (tests/priscilla/provenance.test.ts::REC) ------- */

/* Fill *out with the canonical sample ProvenanceRecord (borrowed static
 * strings; no free needed):
 *   datasetId='sha256:dataset-xyz', modelId='agent-fable-5',
 *   version='2026-01', licenceTag='CC-BY-4.0'. */
void fix_provenance_record(provenance_record_t *out);

/* ---- raw identity-chain tx builders ------------------------------------- */
/* These mirror the TS FakeChain.rawTx / MockChain.addStateTx|addTerminalTx /
 * whatsOnChain makeTeaTx helpers: assemble a raw-tx hex (uncheckedSerialize
 * form) with a chosen output[0] and an optional OP_RETURN receipt at output[1].
 * Each writes a freshly malloc'd lowercase raw-tx hex string to *out_hex (caller
 * frees). BNS_OK / BNS_ENOMEM (or BNS_EPARSE on a bad receipt hex). */

/* output[0] = OP_1 (0x51) "recreated identity" placeholder (NON-terminal),
 * optional output[1] = OP_RETURN <receipt32>. `receipt_hash_hex` may be NULL
 * (no receipt output) else a 64-char hex 32-byte value.
 * TS: rawTx(RECREATED [, receiptHex]). */
int fix_raw_tx_recreated(const char *receipt_hash_hex, char **out_hex);

/* output[0] = canonical 25-byte P2PKH (76a914 <20B> 88ac) over a fixed dummy
 * hash160 => a TERMINAL revoke/slash spend; no receipt. TS: rawTx(P2PKH) /
 * MockChain.addTerminalTx. */
int fix_raw_tx_p2pkh_terminal(char **out_hex);

/* A tx with NO outputs at all (degenerate terminal). TS: MockChain.addNoOutputTx
 * / new bsv.Transaction().uncheckedSerialize(). */
int fix_raw_tx_no_outputs(char **out_hex);

/* General form: output[0] = the given raw locking-script hex; optional output[1]
 * = OP_RETURN <receipt32>. `out0_script_hex` is the lowercase script-body hex
 * (e.g. "51" for OP_1, or a full P2PKH); `receipt_hash_hex` NULL => no receipt.
 * TS: makeTeaTx / rawTx(out0Hex, receiptHex). BNS_OK / BNS_EPARSE / BNS_ENOMEM. */
int fix_raw_tx(const char *out0_script_hex, const char *receipt_hash_hex,
               char **out_hex);

#endif /* BONSAI_TEST_FIXTURES_H */
