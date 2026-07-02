/*
 * verify_ricardian.h — the verifyRicardian script LIBRARY entry point: verify the
 * Ricardian charter on read. (1) parse policy params from
 * legal/ricardian-prose.md §2; (2) if legal/ricardian-prose.sig exists, verify
 * the issuer ECDSA signature over canonical {prose||binding} bytes and the
 * embedded ricardianHash; (3) optionally (VERIFY_IDENTITY_TXID set) reconstruct
 * the expected locking script (RicardianTea default, or AgentTea when
 * IDENTITY_KIND=agenttea) and byte-compare it to the live on-chain identity
 * output. CI-usable (non-zero exit on any failure). Logic in
 * src/scripts/verify_ricardian_lib.c.
 *
 * TS origin: scripts/verifyRicardian.ts (main).
 *
 * Env (TS): VERIFY_IDENTITY_TXID, IDENTITY_KIND, ELDER_PUBKEY, AGENT_PUBKEY,
 * DESIGNATED_VALIDATOR_RABIN_PUBKEY, VALIDATOR_RABIN_PUBKEY, RICARDIAN_HASH,
 * RECOVERY_RABIN_PUBKEYS, RECOVERY_THRESHOLD, MAX_SLASHING_TARGET,
 * MIN_SLASH_CONFIRMATIONS, INITIAL_SLASH_CHECKPOINT_HASH, WOC_NETWORK.
 *
 * PINS (module notes): AgentTea reconstruction takes ricardianHash DIRECTLY from
 * env (NOT recomputed); RicardianTea recomputes via computeRicardianHash; on-chain
 * compare via verify_identity_script_on_chain (case-insensitive, vout=0). Exit 1
 * on invalid issuer signature or on-chain mismatch.
 */
#ifndef BONSAI_SCRIPTS_VERIFY_RICARDIAN_H
#define BONSAI_SCRIPTS_VERIFY_RICARDIAN_H

#include "common/error.h"

/* Run the verifyRicardian library from the environment. Returns the CI exit code
 * via *out_exit_code (non-zero on signature/on-chain failure).
 * TS: scripts/verifyRicardian.ts main. BNS_OK (ran; see *out_exit_code) /
 * propagated errors. */
int verify_ricardian_run(int argc, char **argv, int *out_exit_code);

#endif /* BONSAI_SCRIPTS_VERIFY_RICARDIAN_H */
