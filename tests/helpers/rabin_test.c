/* rabin_test.c — see rabin_test.h. */
#include "rabin_test.h"

#include <stddef.h>

#include "common/hex.h"
#include "crypto/bignum.h"

/* Two pinned ~1600-bit Blum primes (p ≡ q ≡ 3 mod 4), so n = p*q is 3200 bits —
 * comfortably above the 384-byte (3072-bit) rabin_hash output, which is what
 * lets signing's QR/CRT-sqrt search terminate. Fixed so the public key + every
 * signature reproduce byte-for-byte across runs. Verified prime via
 * `openssl prime`; n.bit_length() == 3200. */
#define RABIN_TEST_P \
    "22231208238547022310008407032758682157909617256068919659709111546" \
    "87684153488457611949239128808698470874297676057052469187255352822" \
    "76419896581925083508064050597812925393102079883653528491725435195" \
    "17965380637541913632702798032709086826342517894449056995813521164" \
    "623425157014938580811243705938889789446048514845230766000957655683" \
    "431234471074446102998941914132860645148110124601337370334907352909" \
    "282382504980150194820921660968004208236887572255964623394123279769" \
    "485478648080313182335347"
#define RABIN_TEST_Q \
    "44462416477094044620016814065517364315819234512137839319418223093" \
    "75368306976915223898478257617396941748595352114104938374510705645" \
    "52839793163850167016128101195625850786204159767307056983450870390" \
    "35930761275083827265405596065418173652685035788898113991627042329" \
    "246850314029877161622487411877779578892097029690461532001915311366" \
    "862468942148892205997883828265721290296220249202674740669814705818" \
    "564765009960300389641843321936008416473775144511929246788246559538" \
    "970957296160626364721343"

int rabin_test_fixed_key(rabin_key_t *out)
{
    if (!out) return BNS_EINVAL;
    out->p = NULL;
    out->q = NULL;
    int rc = bn_parse_dec(RABIN_TEST_P, &out->p);
    if (rc != BNS_OK) return rc;
    rc = bn_parse_dec(RABIN_TEST_Q, &out->q);
    if (rc != BNS_OK) { rabin_key_free(out); return rc; }
    return BNS_OK;
}

int rabin_test_genkey(rabin_key_t *out)
{
    if (!out) return BNS_EINVAL;
    return rabin_keygen(out);
}

int rabin_test_pubkey(const rabin_key_t *key, bn_t **out)
{
    if (!key || !out) return BNS_EINVAL;
    return rabin_pubkey(key, out);
}

int rabin_test_fixed_pubkey_dec(char **out_dec)
{
    if (!out_dec) return BNS_EINVAL;
    *out_dec = NULL;
    rabin_key_t key;
    int rc = rabin_test_fixed_key(&key);
    if (rc != BNS_OK) return rc;
    bn_t *n = NULL;
    rc = rabin_pubkey(&key, &n);
    rabin_key_free(&key);
    if (rc != BNS_OK) return rc;
    rc = bn_to_dec(n, out_dec);
    bn_free(n);
    return rc;
}

int rabin_test_sign(const char *msg_hex, const rabin_key_t *key,
                    rabin_sig_t *out_sig)
{
    if (!msg_hex || !key || !out_sig) return BNS_EINVAL;
    byte_buf_t msg;
    byte_buf_init(&msg);
    int rc = hex_decode(msg_hex, &msg);
    if (rc != BNS_OK) { byte_buf_free(&msg); return rc; }
    rc = rabin_sign(msg.data, msg.len, key, out_sig);
    byte_buf_free(&msg);
    return rc;
}
