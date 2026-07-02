/*
 * txbuilders/arp_tx_builder.h — pinned-output unsigned-tx builders for the ARP-1
 * contracts PublisherTea (announceRelease, activateRelease, cancelPending,
 * invalidateRelease, retire) and AttestorTea (slashEquivocation, stake, withdraw).
 * Mirrors agent_tea_tx_builder: each reproduces the exact output layout the
 * contract's assert(hashOutputs == hash256(...)) pins, and the receipt-bearing
 * builders recompute the domain-tagged sha256 receipts identically to the contracts.
 *
 * TS origin: src/arpTxBuilder.ts (ArpBuilderOpts, bindAnnounceBuilder,
 * bindActivateBuilder, bindCancelBuilder, bindInvalidateBuilder, bindRetireBuilder,
 * bindAttestorSlashBuilder, bindAttestorStakeBuilder, bindWithdrawBuilder).
 *
 * BYTE-EXACTNESS (arpTxBuilder.ts notes):
 *  - next.lockingScript for PublisherTea/AttestorTea is the recreated compiled+
 *    stateful contract script — reconstruct from artifact + statefully-encoded
 *    next-state fields (releaseCount, pending*); never recompile sCrypt.
 *  - Per-method receipt preimages have DIFFERENT domain-tag lengths and DIFFERENT
 *    field sets (cancel/invalidate omit releaseCount) — build each shape
 *    separately (publisher_tea.h per-method receipt builders).
 *  - retire/slashEquivocation/withdraw have NO funding-from here, so they can
 *    produce zero-fee non-relaying txs unless the caller injects fee context.
 *  - The 4-byte `now`/`lockTime` fields are SIGNED CScriptNum, kept at 4 bytes in
 *    lockstep with on-chain + the Python verifier.
 *  - slashEquivocation odd-satoshi goes to BURN: burn = total - floor(total/2);
 *    int64 arithmetic, never floating point.
 */
#ifndef BONSAI_TXBUILDERS_ARP_TX_BUILDER_H
#define BONSAI_TXBUILDERS_ARP_TX_BUILDER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/bignum.h"
#include "bsv/tx_builder.h"
#include "chainSources/utxo_select.h"
#include "contracts_next/publisher_tea.h"
#include "contracts_next/attestor_tea.h"

/* The contract UTXO being spent at input[0] (publisher or attestor). TS: bound
 * instance current UTXO. */
typedef struct {
    char     txid_display[65]; /* 64-hex DISPLAY prev txid + NUL  */
    uint32_t vout;             /* contract output index           */
    uint64_t value;           /* UTXO satoshi balance            */
} arp_utxo_t;

/* Optional funding/change context for the ARP builders. `funding` borrowed (or
 * NULL); `change_hash160` (20 bytes) selected by has_change. TS: ArpBuilderOpts
 * {fundingUtxos?, changeAddress?}. */
typedef struct {
    const funding_utxos_t *funding;        /* borrowed funding UTXOs (or NULL)    */
    const uint8_t         *change_hash160; /* 20-byte change addr (or NULL)       */
    bool                   has_change;
} arp_builder_opts_t;

/* ---- PublisherTea builders ---------------------------------------------- */

/* announceRelease into `b` (init'd): state output (next state = pending set to
 * (bundleHash,fileSetRoot,now)) + ANNOUNCE receipt (domain ARP1_ANNOUNCE_V1
 * committing bundleHash and fileSetRoot) + change. Sets nLockTime = now.
 * `bundle_hash`/`file_set_root` are 32 raw bytes. TS: bindAnnounceBuilder.
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int build_arp_announce(const publisher_tea_t *c, const arp_utxo_t *utxo,
                       const uint8_t bundle_hash[32],
                       const uint8_t file_set_root[32],
                       int64_t now, const arp_builder_opts_t *opts,
                       tx_builder_t *b);

/* activateRelease into `b`: state output (pending cleared, releaseCount++) +
 * ACTIVATE receipt (domain ARP1_ACTRCPT_V1 committing activateDigest at the
 * PRE-increment releaseCount) + change. `activate_digest` is 32 raw bytes; `c`
 * holds PRE-increment state. TS: bindActivateBuilder. BNS_OK/BNS_EINVAL/BNS_ENOMEM. */
int build_arp_activate(const publisher_tea_t *c, const arp_utxo_t *utxo,
                       const uint8_t activate_digest[32],
                       int64_t now, const arp_builder_opts_t *opts,
                       tx_builder_t *b);

/* cancelPending into `b`: state output (pending cleared) + CANCEL receipt
 * (domain ARP1_CANCEL_V1 committing current pendingBundleHash BEFORE clear) +
 * change. TS: bindCancelBuilder. BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int build_arp_cancel(const publisher_tea_t *c, const arp_utxo_t *utxo,
                     int64_t now, const arp_builder_opts_t *opts,
                     tx_builder_t *b);

/* invalidateRelease into `b`: state output (unchanged pending) + INVALIDATE
 * receipt (domain ARP1_INVALIDATE_V1 committing activateDigest) + change.
 * `activate_digest` is 32 raw bytes. TS: bindInvalidateBuilder.
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int build_arp_invalidate(const publisher_tea_t *c, const arp_utxo_t *utxo,
                         const uint8_t activate_digest[32],
                         int64_t now, const arp_builder_opts_t *opts,
                         tx_builder_t *b);

/* retire into `b`: single P2PKH payout of full balance to hash160(publisherKey);
 * no state output; change. TS: bindRetireBuilder. BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int build_arp_retire(const publisher_tea_t *c, const arp_utxo_t *utxo,
                     const arp_builder_opts_t *opts, tx_builder_t *b);

/* ---- AttestorTea builders ----------------------------------------------- */

/* slashEquivocation into `b`: output[0] = P2PKH bounty = total/2 (floor) to
 * hash160(reporter); output[1] = OP_RETURN 'SLASHED\0' burn = total - bounty
 * (odd satoshi goes to burn); no state output; change(reporterAddress).
 * `reporter` is 33 raw bytes; `total` is utxo->value. TS: bindAttestorSlashBuilder.
 * BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int build_arp_attestor_slash(const attestor_tea_t *c, const arp_utxo_t *utxo,
                             const uint8_t reporter[33],
                             const arp_builder_opts_t *opts, tx_builder_t *b);

/* AttestorTea stake into `b`: output[0] = recreated stateless contract at
 * newBalance = utxo->value + add_amount; change. TS: bindAttestorStakeBuilder.
 * BNS_OK / BNS_EINVAL / BNS_ERANGE / BNS_ENOMEM. */
int build_arp_attestor_stake(const attestor_tea_t *c, const arp_utxo_t *utxo,
                             const bn_t *add_amount,
                             const arp_builder_opts_t *opts, tx_builder_t *b);

/* AttestorTea withdraw into `b`: single P2PKH payout of full balance to
 * hash160(operator); no state output; change. Sets nLockTime = lock_time (the
 * unbond gate, a SIGNED 4-byte CScriptNum) and input[0].sequence < 0xffffffff.
 * TS: bindWithdrawBuilder. BNS_OK / BNS_EINVAL / BNS_ENOMEM. */
int build_arp_attestor_withdraw(const attestor_tea_t *c, const arp_utxo_t *utxo,
                                int64_t lock_time,
                                const arp_builder_opts_t *opts, tx_builder_t *b);

#endif /* BONSAI_TXBUILDERS_ARP_TX_BUILDER_H */
