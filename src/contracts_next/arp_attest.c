/*
 * contracts_next/arp_attest.c — ArpAttest.attestationMsg port.
 *
 * Builds the canonical 54-byte ARP-1 sequenced-attestation message:
 *   tag(14) || int2ByteString(seq, 8 LE) || activate_digest(32)
 *
 * TS origin: src/contracts-next/arpAttest.ts (ArpAttest.attestationMsg):
 *   toByteString('415250315f4154544553545f5631')  // "ARP1_ATTEST_V1"
 *   + int2ByteString(seq, 8n)                      // fixed 8-byte LE
 *   + activateDigest                               // 32 raw bytes
 *
 * The tag and digest are appended raw (no reversal); seq uses the TWO-ARG
 * fixed-width little-endian encoder (num2bin int2bytestring_sized), NOT the
 * one-arg minimal encoder.
 */
#include "contracts_next/arp_attest.h"
#include "bsv/num2bin.h"

/* "ARP1_ATTEST_V1" as raw preimage bytes (14 bytes). Mirrors the TS
 * toByteString('415250315f4154544553545f5631'). */
static const uint8_t ARP_ATTEST_TAG[14] = {
    0x41, 0x52, 0x50, 0x31, 0x5f, 0x41, 0x54, 0x54,
    0x45, 0x53, 0x54, 0x5f, 0x56, 0x31,
};

int arp_attestation_msg(const bn_t *seq, const uint8_t activate_digest[32],
                        byte_buf_t *out)
{
    int rc;

    /* tag(14) */
    rc = byte_buf_append(out, ARP_ATTEST_TAG, sizeof(ARP_ATTEST_TAG));
    if (rc != BNS_OK)
        return rc;

    /* int2ByteString(seq, 8n): fixed 8-byte little-endian, sign in top byte.
     * Returns BNS_ERANGE if seq does not fit 8 bytes. */
    rc = int2bytestring_sized(seq, 8, out);
    if (rc != BNS_OK)
        return rc;

    /* activateDigest(32): raw bytes, original byte order. */
    rc = byte_buf_append(out, activate_digest, 32);
    if (rc != BNS_OK)
        return rc;

    return BNS_OK;
}
