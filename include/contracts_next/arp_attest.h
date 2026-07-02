/*
 * contracts_next/arp_attest.h — the single canonical ARP-1 sequenced-attestation
 * message builder. THE linchpin of cross-contract byte-identity: the SAME 54-byte
 * buffer must come out of this function, of PublisherTea.activateRelease's inline
 * RabinVerifier call, of AttestorTea.slashEquivocation, and of attestationMsgHex()
 * in src/verifier/rabinAttestor.ts. Any divergence silently breaks every quorum
 * check and every slash.
 *
 * TS origin: src/contracts-next/arpAttest.ts (ArpAttest.attestationMsg).
 *
 * EXACT 54-BYTE LAYOUT (arpAttest.ts notes):
 *   tag(14) || int2ByteString(seq, 8) || activateDigest(32)
 *   - tag      = 0x415250315f4154544553545f5631  ('ARP1_ATTEST_V1', 14 bytes)
 *   - seq      = int2ByteString(seq, 8n): the TWO-ARG fixed 8-byte LITTLE-ENDIAN
 *                encoder (num2bin.h int2bytestring_sized) — NOT the one-arg
 *                minimal encoder. Big-endian or minimal seq = wrong message.
 *   - digest   = 32 raw bytes, in the digest's byte order (do NOT reverse).
 * Total = 14 + 8 + 32 = 54 bytes. Pin with a golden vector for a known (seq,digest).
 */
#ifndef BONSAI_CONTRACTS_NEXT_ARP_ATTEST_H
#define BONSAI_CONTRACTS_NEXT_ARP_ATTEST_H

#include <stddef.h>
#include <stdint.h>
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/bignum.h"

/* The ARP-1 attestation domain tag as exact preimage bytes ('ARP1_ATTEST_V1',
 * 14 bytes). TS: arpAttest.ts toByteString('415250315f4154544553545f5631'). */
#define BONSAI_ARP_ATTEST_TAG_HEX "415250315f4154544553545f5631"

/* The fixed total length of the attestation message (14 + 8 + 32). */
#define BONSAI_ARP_ATTEST_MSG_LEN 54

/* Append the canonical attestation message to `out` (init'd):
 *   tag(14) || int2ByteString(seq,8 LE) || activate_digest(32).
 * `seq` is the sequence number (signed CScriptNum widened to fixed 8-byte LE);
 * `activate_digest` is 32 raw bytes. TS: ArpAttest.attestationMsg(seq, digest).
 * BNS_OK / BNS_ERANGE (seq exceeds 8 bytes) / BNS_ENOMEM. */
int arp_attestation_msg(const bn_t *seq, const uint8_t activate_digest[32],
                        byte_buf_t *out);

#endif /* BONSAI_CONTRACTS_NEXT_ARP_ATTEST_H */
