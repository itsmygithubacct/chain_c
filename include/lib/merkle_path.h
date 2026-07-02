/*
 * merkle_path.h — MerklePath.calcMerkleRoot: fold a leaf up a 32-deep merkle
 * proof to the block merkle root, used by Blockchain.txInBlock for the slash()
 * SPV check.
 *
 * TS origin: scrypt-ts-lib merklePath.ts (Node {hash, pos}, MerkleProof =
 * FixedArray<Node,32>, MerklePath.{INVALID_NODE, LEFT_NODE, RIGHT_NODE,
 * calcMerkleRoot}).
 *
 * BYTE-EXACTNESS (contracts ricardianTea slash): for each proof node, skip when
 * pos == INVALID_NODE; else
 *   root = (pos == LEFT_NODE)  ? Sha256(hash256(node.hash || root))
 *                              : Sha256(hash256(root || node.hash))
 * i.e. double-SHA256 with concat order set by pos. depth bounds the iteration.
 */
#ifndef BONSAI_LIB_MERKLE_PATH_H
#define BONSAI_LIB_MERKLE_PATH_H

#include <stddef.h>
#include <stdint.h>
#include "common/error.h"
#include "crypto/hash.h"   /* BONSAI_SHA256_LEN */

/* Fixed merkle proof depth. TS: MerkleProof = FixedArray<Node, 32>. */
#define BONSAI_MERKLE_PROOF_DEPTH 32

/* Node position sentinels. TS: MerklePath.INVALID_NODE / LEFT_NODE / RIGHT_NODE. */
typedef enum {
    MERKLE_INVALID_NODE = 0, /* skip this level (padding above the actual depth)  */
    MERKLE_LEFT_NODE    = 1, /* sibling on the LEFT  -> hash(node.hash || root)   */
    MERKLE_RIGHT_NODE   = 2  /* sibling on the RIGHT -> hash(root || node.hash)   */
} merkle_pos_t;

/* One proof node: a sibling hash plus its position. TS: Node {hash, pos}. */
typedef struct {
    uint8_t      hash[BONSAI_SHA256_LEN]; /* sibling hash (raw 32 bytes)          */
    merkle_pos_t pos;
} merkle_node_t;

/* calcMerkleRoot(leaf, proof[32], depth): fold `leaf` (raw 32 bytes) up the
 * proof for `depth` levels (depth <= 32) using double-SHA256 with pos-ordered
 * concatenation, writing the resulting root (raw 32 bytes) to out_root.
 * TS: MerklePath.calcMerkleRoot. BNS_OK / BNS_EINVAL (depth > 32). */
int calc_merkle_root(const uint8_t leaf[BONSAI_SHA256_LEN],
                     const merkle_node_t proof[BONSAI_MERKLE_PROOF_DEPTH],
                     size_t depth,
                     uint8_t out_root[BONSAI_SHA256_LEN]);

#endif /* BONSAI_LIB_MERKLE_PATH_H */
