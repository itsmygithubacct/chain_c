/*
 * deploy.h — the deploy script LIBRARY entry point: deploy ATLAS-01, a
 * RicardianTea identity, to MAINNET. The Ricardian binding is closed here:
 * policy parameters are read out of legal/ricardian-prose.md (single source of
 * truth) and ricardianHash = H(prose || canonical deployment-binding). It also
 * signs the canonical contract bytes with the Elder key and writes a
 * self-contained sidecar legal/ricardian-prose.sig. Dry-run unless
 * CONFIRM_MAINNET_BROADCAST=yes. Logic in src/scripts/deploy_lib.c.
 *
 * TS origin: scripts/deploy.ts (main + computeRicardianHash, signCharter,
 * verifyCharterSignature helpers).
 *
 * Env (TS): PRIVATE_KEY, MAX_SLASHING_TARGET, MIN_SLASH_CONFIRMATIONS,
 * AGENT_PUBKEY, DESIGNATED_VALIDATOR_RABIN_PUBKEY, VALIDATOR_RABIN_PUBKEY,
 * INITIAL_SLASH_CHECKPOINT_HASH, CONFIRM_MAINNET_BROADCAST.
 *
 * PINS (module notes): ricardianHash = sha256(toByteString(
 * canonicalContractBytes.toString('hex'))) where canonicalContractBytes =
 * UTF-8(proseText + '\n\n--- DEPLOYMENT BINDING (canonical) ---\n' +
 * canonicalJSON(binding) + '\n'); signCharter signs the SINGLE-SHA256 32-byte
 * digest with low-S DER ECDSA (the charter does NOT double-hash). Guards:
 * maxSlashingTarget>0; minSlashConfirmations in [1,6]; elderKey network ==
 * mainnet.
 */
#ifndef BONSAI_SCRIPTS_DEPLOY_H
#define BONSAI_SCRIPTS_DEPLOY_H

#include "common/error.h"

/* Run the deploy library from the environment. Dry-run unless
 * CONFIRM_MAINNET_BROADCAST=yes. Returns a process exit code via *out_exit_code.
 * TS: scripts/deploy.ts main. BNS_OK (ran; see *out_exit_code) / propagated errors. */
int deploy_run(int argc, char **argv, int *out_exit_code);

#endif /* BONSAI_SCRIPTS_DEPLOY_H */
