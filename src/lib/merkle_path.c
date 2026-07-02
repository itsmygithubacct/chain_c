/*
 * merkle_path.c — MerklePath.calcMerkleRoot port.
 *
 * TS origin: scrypt-ts-lib merklePath.ts MerklePath.calcMerkleRoot:
 *   let root = leaf;
 *   for (i = 0; i < depth; i++) {
 *       node = merkleProof[i];
 *       if (node.pos != INVALID_NODE)
 *           root = node.pos == LEFT_NODE
 *               ? Sha256(hash256(node.hash + root))   // sibling on the LEFT
 *               : Sha256(hash256(root + node.hash));   // sibling on the RIGHT
 *   }
 *   return root;
 *
 * In scrypt-ts `hash256()` is the real double-SHA256 and `Sha256()` is only a
 * branding cast (no extra hashing). So each non-INVALID level is exactly one
 * sha256d over the pos-ordered 64-byte concatenation.
 */
#include "lib/merkle_path.h"

#include <string.h>

#include "crypto/hash.h"   /* sha256d, BONSAI_SHA256_LEN */

int calc_merkle_root(const uint8_t leaf[BONSAI_SHA256_LEN],
                     const merkle_node_t proof[BONSAI_MERKLE_PROOF_DEPTH],
                     size_t depth,
                     uint8_t out_root[BONSAI_SHA256_LEN])
{
    if (depth > BONSAI_MERKLE_PROOF_DEPTH) {
        return BNS_EINVAL;
    }

    uint8_t root[BONSAI_SHA256_LEN];
    memcpy(root, leaf, BONSAI_SHA256_LEN);

    for (size_t i = 0; i < depth; i++) {
        const merkle_node_t *node = &proof[i];
        if (node->pos == MERKLE_INVALID_NODE) {
            continue; /* padding level above the actual proof depth */
        }

        /* Concatenate 64 bytes in pos order, then sha256d. */
        uint8_t concat[2 * BONSAI_SHA256_LEN];
        if (node->pos == MERKLE_LEFT_NODE) {
            /* sibling on the LEFT: hash256(node.hash || root) */
            memcpy(concat, node->hash, BONSAI_SHA256_LEN);
            memcpy(concat + BONSAI_SHA256_LEN, root, BONSAI_SHA256_LEN);
        } else {
            /* RIGHT_NODE (or any other non-INVALID sentinel, matching the TS
             * ternary which treats != LEFT_NODE as the right branch):
             * hash256(root || node.hash) */
            memcpy(concat, root, BONSAI_SHA256_LEN);
            memcpy(concat + BONSAI_SHA256_LEN, node->hash, BONSAI_SHA256_LEN);
        }
        sha256d(concat, sizeof(concat), root);
    }

    memcpy(out_root, root, BONSAI_SHA256_LEN);
    return BNS_OK;
}
