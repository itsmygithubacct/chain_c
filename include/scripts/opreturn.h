/*
 * scripts/opreturn.h — the `opreturn` CLI: write an OP_RETURN data output.
 *
 * Env-driven:
 *   KEY_FILE     funding key file (default $BONSAI_NOTARY_HOME/chain/test_bsv.json)
 *   DATA         UTF-8 string to embed (use this OR DATA_HEX)
 *   DATA_HEX     hex bytes to embed
 *   FEE_PER_KB   fee rate sats/KB (optional; default 50)
 *
 * The tx has one 0-sat OP_RETURN output plus a change output back to the funding
 * address. DRY RUN unless CONFIRM_MAINNET_BROADCAST=yes. Mainnet only.
 */
#ifndef BONSAI_SCRIPTS_OPRETURN_H
#define BONSAI_SCRIPTS_OPRETURN_H

#include "common/error.h"

int opreturn_run(int argc, char **argv, int *out_exit_code);

#endif /* BONSAI_SCRIPTS_OPRETURN_H */
