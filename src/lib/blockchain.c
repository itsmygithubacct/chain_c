/*
 * blockchain.c — Blockchain SPV helpers (port of scrypt-ts-lib blockchain.ts).
 *
 * serialize(bh) = version(4, as-is) || prevBlockHash(32) || merkleRoot(32) ||
 *                 toLEUnsigned(time,4) || bits(4, as-is) || toLEUnsigned(nonce,4)
 *               (80 bytes).
 * blockHeaderHash      = hash256(serialize(bh)) (raw 32-byte digest, sha256d).
 * blockHeaderHashAsInt = fromLEUnsigned(blockHeaderHash) — the digest read
 *                        little-endian as a (non-negative) bigint.
 * bits2Target(bits):
 *     exponent    = fromLEUnsigned(bits[3..])         (1 byte)
 *     coefficient = fromLEUnsigned(bits[0..3])        (3 bytes, LE)
 *     n           = 8 * (exponent - 3)
 *     return lshift(coefficient, n)                   (coefficient << n)
 * isValidBlockHeader(bh, blockchainTarget):
 *     blockHeaderHashAsInt(bh) <= bits2Target(bh.bits)
 *     AND bits2Target(bh.bits) <= blockchainTarget.
 * txInBlock(txid, bh, proof, depth):
 *     calcMerkleRoot(txid, proof, depth) == bh.merkleRoot.
 */
#include "lib/blockchain.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/hash.h"        /* sha256d */
#include "crypto/bignum.h"
#include "lib/merkle_path.h"

/* ---- internal: append a uint as 4-byte little-endian -------------------- */
static int append_le4(byte_buf_t *out, uint64_t v)
{
    uint8_t b[4];
    b[0] = (uint8_t)(v & 0xff);
    b[1] = (uint8_t)((v >> 8) & 0xff);
    b[2] = (uint8_t)((v >> 16) & 0xff);
    b[3] = (uint8_t)((v >> 24) & 0xff);
    return byte_buf_append(out, b, sizeof(b));
}

int block_header_serialize(const block_header_t *header, byte_buf_t *out)
{
    int rc;

    /* version (4 bytes, as-is ByteString) */
    rc = byte_buf_append(out, header->version, sizeof(header->version));
    if (rc != BNS_OK) return rc;

    /* prevBlockHash (32) */
    rc = byte_buf_append(out, header->prev_block_hash, BONSAI_SHA256_LEN);
    if (rc != BNS_OK) return rc;

    /* merkleRoot (32) */
    rc = byte_buf_append(out, header->merkle_root, BONSAI_SHA256_LEN);
    if (rc != BNS_OK) return rc;

    /* toLEUnsigned(time, 4) */
    rc = append_le4(out, header->time);
    if (rc != BNS_OK) return rc;

    /* bits (4 bytes, as-is ByteString) */
    rc = byte_buf_append(out, header->bits, sizeof(header->bits));
    if (rc != BNS_OK) return rc;

    /* toLEUnsigned(nonce, 4) */
    rc = append_le4(out, header->nonce);
    if (rc != BNS_OK) return rc;

    return BNS_OK;
}

int block_header_hash(const block_header_t *header,
                      uint8_t out_hash[BONSAI_SHA256_LEN])
{
    byte_buf_t ser;
    byte_buf_init(&ser);

    int rc = block_header_serialize(header, &ser);
    if (rc != BNS_OK) {
        byte_buf_free(&ser);
        return rc;
    }

    sha256d(ser.data, ser.len, out_hash);
    byte_buf_free(&ser);
    return BNS_OK;
}

int block_header_hash_as_int(const block_header_t *header, bn_t **out)
{
    uint8_t digest[BONSAI_SHA256_LEN];
    int rc = block_header_hash(header, digest);
    if (rc != BNS_OK) return rc;

    /* fromLEUnsigned: read the 32-byte digest little-endian as a bigint. */
    return bn_parse_le(digest, sizeof(digest), out);
}

int bits2target(const uint8_t bits[4], bn_t **out)
{
    /* exponent = fromLEUnsigned(bits[3..]) — the single high byte. */
    int exponent = (int)bits[3];

    /* coefficient = fromLEUnsigned(bits[0..3]) — 3 low bytes, little-endian. */
    uint32_t coefficient =
        (uint32_t)bits[0] |
        ((uint32_t)bits[1] << 8) |
        ((uint32_t)bits[2] << 16);

    /* n = 8 * (exponent - 3); target = coefficient << n. */
    int n = 8 * (exponent - 3);

    if (n >= 0) {
        /* target = coefficient * 2^n. Build 2^n as a big-endian byte buffer
         * (a single 1-bit at position n) and multiply. */
        bn_t *coef = NULL;
        bn_t *pow2 = NULL;
        int rc;

        {
            /* coefficient as a bn (decimal-free path via BE bytes). */
            uint8_t cbe[4];
            cbe[0] = (uint8_t)((coefficient >> 24) & 0xff);
            cbe[1] = (uint8_t)((coefficient >> 16) & 0xff);
            cbe[2] = (uint8_t)((coefficient >> 8) & 0xff);
            cbe[3] = (uint8_t)(coefficient & 0xff);
            rc = bn_parse_be(cbe, sizeof(cbe), &coef);
            if (rc != BNS_OK) return rc;
        }

        {
            /* 2^n big-endian: total_bytes = n/8 + 1; the top bit of the high
             * byte holds bit (n). bit n lives at byte index (n/8) from the LSB,
             * i.e. big-endian byte index (total_bytes-1 - n/8). */
            size_t total_bytes = (size_t)(n / 8) + 1;
            uint8_t *pbuf = (uint8_t *)calloc(total_bytes, 1);
            if (!pbuf) {
                bn_free(coef);
                return BNS_ENOMEM;
            }
            int byte_from_lsb = n / 8;            /* which byte holds the bit  */
            int bit_in_byte = n % 8;              /* which bit within that byte */
            size_t be_index = total_bytes - 1 - (size_t)byte_from_lsb;
            pbuf[be_index] = (uint8_t)(1u << bit_in_byte);
            rc = bn_parse_be(pbuf, total_bytes, &pow2);
            free(pbuf);
            if (rc != BNS_OK) {
                bn_free(coef);
                return rc;
            }
        }

        rc = bn_mul(coef, pow2, out);
        bn_free(coef);
        bn_free(pow2);
        return rc;
    }

    /* n < 0 (degenerate: exponent < 3): target = coefficient >> (-n). The
     * coefficient fits in 24 bits, so do the right shift in plain C. */
    {
        int shift = -n;
        uint32_t v = (shift >= 32) ? 0u : (coefficient >> shift);
        uint8_t vbe[4];
        vbe[0] = (uint8_t)((v >> 24) & 0xff);
        vbe[1] = (uint8_t)((v >> 16) & 0xff);
        vbe[2] = (uint8_t)((v >> 8) & 0xff);
        vbe[3] = (uint8_t)(v & 0xff);
        return bn_parse_be(vbe, sizeof(vbe), out);
    }
}

bool is_valid_block_header(const block_header_t *header,
                           const bn_t *blockchain_target)
{
    bn_t *bh_hash = NULL;
    bn_t *target = NULL;
    bool ok = false;

    if (block_header_hash_as_int(header, &bh_hash) != BNS_OK) {
        goto done; /* fail-closed on internal error */
    }
    if (bits2target(header->bits, &target) != BNS_OK) {
        goto done;
    }

    /* blockHeaderHashAsInt <= target  AND  target <= blockchainTarget */
    ok = (bn_cmp(bh_hash, target) <= 0) &&
         (bn_cmp(target, blockchain_target) <= 0);

done:
    bn_free(bh_hash);
    bn_free(target);
    return ok;
}

bool tx_in_block(const uint8_t txid[BONSAI_SHA256_LEN],
                 const block_header_t *header,
                 const merkle_node_t proof[BONSAI_MERKLE_PROOF_DEPTH],
                 size_t depth)
{
    uint8_t root[BONSAI_SHA256_LEN];
    if (calc_merkle_root(txid, proof, depth, root) != BNS_OK) {
        return false; /* fail-closed */
    }
    return memcmp(root, header->merkle_root, BONSAI_SHA256_LEN) == 0;
}
