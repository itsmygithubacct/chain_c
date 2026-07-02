/*
 * scripts/pay.h — the `pay` CLI: send BSV from a funded key to a P2PKH address.
 *
 * Env-driven (money-safe, mirrors cpfp/deploy):
 *   KEY_FILE     key file {"wif","address"} (default $BONSAI_NOTARY_HOME/chain/test_bsv.json)
 *   TO           recipient base58 P2PKH address (required unless SWEEP)
 *   AMOUNT       satoshis to send (required unless SWEEP)
 *   SWEEP=yes    send the entire balance (minus fee) to TO; ignores AMOUNT
 *   FEE_PER_KB   fee rate sats/KB (optional; default 50)
 *
 * DRY RUN unless CONFIRM_MAINNET_BROADCAST=yes. Mainnet only.
 */
#ifndef BONSAI_SCRIPTS_PAY_H
#define BONSAI_SCRIPTS_PAY_H

#include "common/error.h"

int pay_run(int argc, char **argv, int *out_exit_code);

#endif /* BONSAI_SCRIPTS_PAY_H */
