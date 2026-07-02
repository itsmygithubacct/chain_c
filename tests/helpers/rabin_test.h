/*
 * rabin_test.h — test Rabin keygen/sign wrappers over crypto/rabin.h, mirroring
 * chain/tests/utils/rabin.ts (genRabinKey / rabinPubKey / rabinSign).
 *
 * The TS helper uses a RANDOM genRabinKey(); for byte-exact C tests we ALSO
 * expose a FIXED deterministic keypair (two pinned Blum primes p≡q≡3 mod 4) so
 * a signature/pubkey can be reproduced across runs. Use rabin_test_fixed_key()
 * where the TS would use one fixed key; rabin_test_genkey() for the random path.
 *
 * rabin_test_sign() takes a HEX message string (the ByteString .toString() form
 * the TS rabinSign receives) — it decodes the hex then calls rabin_sign over the
 * raw bytes, matching `rabin.sign(msgHex, key)`.
 */
#ifndef BONSAI_TEST_RABIN_TEST_H
#define BONSAI_TEST_RABIN_TEST_H

#include "common/error.h"
#include "crypto/rabin.h"   /* rabin_key_t, rabin_sig_t, bn_t */

/* Fill *out with the pinned deterministic test keypair {p,q} (two fixed Blum
 * primes). Owns fresh bn_t's; release via rabin_key_free. Use this where a test
 * needs a reproducible key (the C analogue of "the TS uses one fixed key").
 * TS: a fixed genRabinKey() substitute. BNS_OK / BNS_EPARSE / BNS_ENOMEM. */
int rabin_test_fixed_key(rabin_key_t *out);

/* Generate a fresh random keypair (passthrough to rabin_keygen). Release via
 * rabin_key_free. TS: genRabinKey(). BNS_OK / BNS_ECRYPTO / BNS_ENOMEM. */
int rabin_test_genkey(rabin_key_t *out);

/* Derive the public modulus n = p*q as a fresh bn_t (*out; caller bn_free's).
 * Its DECIMAL string (bn_to_dec) is the on-wire RabinPubKey. TS: rabinPubKey(key).
 * BNS_OK / BNS_ENOMEM. */
int rabin_test_pubkey(const rabin_key_t *key, bn_t **out);

/* Convenience: the pinned fixed key's public modulus as a freshly malloc'd
 * DECIMAL string (caller frees). Lets a test pin the exact RabinPubKey literal.
 * BNS_OK / BNS_EPARSE / BNS_ENOMEM. */
int rabin_test_fixed_pubkey_dec(char **out_dec);

/* Sign a HEX message (no 0x; a ByteString .toString()) with `key`. Decodes the
 * hex to raw bytes then rabin_sign's them; fills *out_sig (caller frees via
 * rabin_sig_free). TS: rabinSign(msgHex, key) -> { s, padding }.
 * BNS_OK / BNS_EPARSE (bad hex) / BNS_ECRYPTO / BNS_ENOMEM. */
int rabin_test_sign(const char *msg_hex, const rabin_key_t *key,
                    rabin_sig_t *out_sig);

#endif /* BONSAI_TEST_RABIN_TEST_H */
