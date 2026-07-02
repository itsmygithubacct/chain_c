/*
 * cpfp.h — the cpfp script LIBRARY entry point: accelerate a stuck/slow BSV
 * parent transaction with a high-fee CPFP (child-pays-for-parent) child that
 * spends one of the parent's P2PKH outputs back to the funded key. BSV is
 * first-seen-final (no RBF), so CPFP is the only fee-bump mechanism. Dry-run
 * unless CONFIRM_MAINNET_BROADCAST=yes. Logic in src/scripts/cpfp_lib.c.
 *
 * TS origin: scripts/cpfp.ts (top-level async main).
 *
 * Env (TS): PARENT (parent txid), VOUT (output index), FEE (child fee sats,
 * default 3000), KEY_FILE (default $BONSAI_NOTARY_HOME/chain/test_bsv.json),
 * BONSAI_NOTARY_HOME, HOME, CONFIRM_MAINNET_BROADCAST.
 *
 * PINS (module notes): value is read from the parent's RAW tx (not WoC's lagging
 * UTXO index); childOut = value - childFee; HARD refusal if childOut < 1000 OR
 * childFee > 50000; single-input single-output P2PKH child to the funded key;
 * BSV sighash SIGHASH_ALL|FORKID (0x41), low-S DER ECDSA; feerate display =
 * round((childFee/size)*1000) sats/KB with size = rawhex.length/2.
 */
#ifndef BONSAI_SCRIPTS_CPFP_H
#define BONSAI_SCRIPTS_CPFP_H

#include "common/error.h"

/* Run the cpfp library from the environment. Dry-run unless
 * CONFIRM_MAINNET_BROADCAST=yes. Returns a process exit code via *out_exit_code
 * (0 success, 1 on the TS `CPFP FAILED:` throw path). TS: scripts/cpfp.ts main.
 * BNS_OK (ran; see *out_exit_code) / propagated errors. */
int cpfp_run(int argc, char **argv, int *out_exit_code);

#endif /* BONSAI_SCRIPTS_CPFP_H */
