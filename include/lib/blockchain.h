/*
 * blockchain.h — Blockchain SPV helpers for slash(): block-header serialize /
 * hash, bits->target, header validity, and tx-in-block via a merkle proof.
 *
 * TS origin: scrypt-ts-lib blockchain.ts (BlockHeader, Blockchain.{serialize,
 * blockHeaderHash, blockHeaderHashAsInt, bits2Target, isValidBlockHeader,
 * verifyBlockHeader, txInBlock}). The ricardianTea slash() path uses these.
 *
 * BYTE-EXACTNESS (contracts ricardianTea slash):
 *  - serialize(header) = version(4 bytes, as-is ByteString) || prevBlockHash(32)
 *    || merkleRoot(32) || toLEUnsigned(time,4) || bits(4 bytes ByteString) ||
 *    toLEUnsigned(nonce,4)  (80 bytes total).
 *  - blockHeaderHash = hash256(serialize(header)); blockHeaderHashAsInt
 *    interprets that digest LITTLE-ENDIAN as a bigint.
 *  - isValidBlockHeader(header, target): blockHeaderHashAsInt <= bits2Target(bits)
 *    AND bits2Target(bits) <= target (the maxSlashingTarget cap).
 *  - txInBlock(txid, header, proof, depth): calcMerkleRoot(txid, proof, depth)
 *    == header.merkleRoot.
 */
#ifndef BONSAI_LIB_BLOCKCHAIN_H
#define BONSAI_LIB_BLOCKCHAIN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/hash.h"        /* BONSAI_SHA256_LEN          */
#include "crypto/bignum.h"      /* bn_t (target / hash-as-int) */
#include "lib/merkle_path.h"    /* merkle_node_t, depth        */

/* Serialized block-header length in bytes. TS: 80-byte header. */
#define BONSAI_BLOCK_HEADER_LEN 80

/* A block header. `version` and `bits` are raw 4-byte ByteStrings (stored as-is,
 * NOT re-encoded); prev_block_hash / merkle_root are raw 32-byte hashes; time /
 * nonce are unsigned ints serialized as 4-byte LE. TS: BlockHeader {version,
 * prevBlockHash, merkleRoot, time, bits, nonce}. */
typedef struct {
    uint8_t  version[4];                        /* ByteString, as-is              */
    uint8_t  prev_block_hash[BONSAI_SHA256_LEN];/* 32 bytes                       */
    uint8_t  merkle_root[BONSAI_SHA256_LEN];    /* 32 bytes                       */
    uint64_t time;                              /* serialized toLEUnsigned(time,4)*/
    uint8_t  bits[4];                           /* ByteString, as-is              */
    uint64_t nonce;                             /* serialized toLEUnsigned(nonce,4)*/
} block_header_t;

/* Serialize `header` to its 80-byte wire form appended to `out` (init'd).
 * TS: Blockchain.serialize. BNS_OK / BNS_ENOMEM. */
int block_header_serialize(const block_header_t *header, byte_buf_t *out);

/* blockHeaderHash = hash256(serialize(header)); writes the raw 32-byte digest to
 * out_hash. TS: Blockchain.blockHeaderHash. BNS_OK / BNS_ENOMEM. */
int block_header_hash(const block_header_t *header,
                      uint8_t out_hash[BONSAI_SHA256_LEN]);

/* blockHeaderHashAsInt: the blockHeaderHash digest read LITTLE-ENDIAN as a
 * bigint via *out (fresh bn_t, caller frees). TS: Blockchain.blockHeaderHashAsInt.
 * BNS_OK / BNS_ENOMEM. */
int block_header_hash_as_int(const block_header_t *header, bn_t **out);

/* bits2Target(bits): decode the 4-byte compact `bits` ByteString into the full
 * 256-bit target via *out (fresh bn_t, caller frees). TS: Blockchain.bits2Target.
 * BNS_OK / BNS_ENOMEM. */
int bits2target(const uint8_t bits[4], bn_t **out);

/* isValidBlockHeader(header, blockchain_target): blockHeaderHashAsInt <=
 * bits2Target(bits) AND bits2Target(bits) <= blockchain_target. Pure predicate;
 * fail-closed on internal error. TS: Blockchain.isValidBlockHeader. */
bool is_valid_block_header(const block_header_t *header,
                           const bn_t *blockchain_target);

/* txInBlock(txid, header, proof, depth): calcMerkleRoot(txid, proof, depth)
 * equals header.merkleRoot. `txid` is the raw 32-byte leaf. Pure predicate.
 * TS: Blockchain.txInBlock. */
bool tx_in_block(const uint8_t txid[BONSAI_SHA256_LEN],
                 const block_header_t *header,
                 const merkle_node_t proof[BONSAI_MERKLE_PROOF_DEPTH],
                 size_t depth);

#endif /* BONSAI_LIB_BLOCKCHAIN_H */
