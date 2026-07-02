/*
 * woc.h — the `woc` CLI LIBRARY entry point: a rate-limit-respecting
 * WhatsOnChain command dispatcher built on WocClient + utxo_select +
 * bsv_fees. Subcommands:
 *
 *   status   <txid>                      TRUE state (confirmed|mempool|unknown)
 *   tx       <txid>                      confirmations + blockheight ('mempool')
 *   rawtx    <txid>                      raw tx hex or '(not found)'
 *   utxos    <address>                   ranked funding candidates (JSON, indent 1)
 *   fund     <address> [min]             pick ONE verified-unspent funding UTXO
 *   spent    <txid> <vout>               spender state: spent|unspent|unknown
 *   balance  <address>                   {confirmed, unconfirmed}
 *   broadcast <hex>                      broadcast, print txid
 *   wait     <txid> [conf]               poll until >= conf confirmations
 *   mempool  <txid>                      poll until the node has the tx
 *   feewindow <signedBytes> <feePerKb>   the scrypt-ts send-time fee window
 *
 * Logic lives in src/scripts/woc_lib.c; bin/woc_main.c is a thin main().
 *
 * TS origin: scripts/woc.ts (main).
 *
 * PINS (module notes): output via JSON.stringify-equivalent — compact for most
 * commands, indent-1 for `utxos`; key order follows the TS object literals
 * (txid first). `tx` surfaces blockheight as the string 'mempool' when null.
 * Unknown cmd -> stderr usage + exit 2; any error -> stderr 'woc error: <msg>'
 * + exit 1.
 */
#ifndef BONSAI_SCRIPTS_WOC_H
#define BONSAI_SCRIPTS_WOC_H

#include "common/error.h"
#include "chainSources/http_transport.h"

/* Run the woc CLI. `transport` is the (borrowed) HTTP seam used by the
 * underlying WocClient; pass NULL to use the default libcurl transport. Returns
 * the process exit code via *out_exit_code (0 ok / 2 unknown cmd / 1 error).
 * TS: scripts/woc.ts main + the top-level catch. Always returns BNS_OK (the
 * exit code carries the outcome). */
int woc_run(int argc, char **argv, const http_transport_t *transport,
            int *out_exit_code);

#endif /* BONSAI_SCRIPTS_WOC_H */
