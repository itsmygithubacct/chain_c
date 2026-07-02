/*
 * script_support.c — shared CLI helpers (see script_support.h).
 */
#include "scripts/script_support.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h> /* OPENSSL_cleanse */

#include "cJSON.h"
#include "crypto/ecdsa.h"

const char *bonsai_home(void) {
    static char buf[1024];
    const char *h = getenv("BONSAI_NOTARY_HOME");
    if (h && h[0]) {
        snprintf(buf, sizeof(buf), "%s", h);
        return buf;
    }
    const char *home = getenv("HOME");
    snprintf(buf, sizeof(buf), "%s/.local/trinote", (home && home[0]) ? home : ".");
    return buf;
}

const char *env_get(const char *name) {
    return getenv(name);
}

const char *env_or(const char *name, const char *dflt) {
    const char *v = getenv(name);
    return (v && v[0]) ? v : dflt;
}

int env_require(const char *name, const char **out, bonsai_err_ctx *err) {
    const char *v = getenv(name);
    if (!v || !v[0]) {
        return bns_fail(err, BNS_EINVAL, "Set %s", name);
    }
    *out = v;
    return BNS_OK;
}

bool confirm_mainnet_broadcast(void) {
    const char *v = getenv("CONFIRM_MAINNET_BROADCAST");
    return v && strcmp(v, "yes") == 0;
}

void key_file_free(key_file_t *kf) {
    if (!kf) return;
    /* The WIF is secret key material; scrub it before returning the heap. */
    if (kf->wif) OPENSSL_cleanse(kf->wif, strlen(kf->wif));
    free(kf->wif);
    free(kf->address);
    kf->wif = NULL;
    kf->address = NULL;
}

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[rd] = '\0';
    return buf;
}

int key_file_load(const char *path, key_file_t *kf, bonsai_err_ctx *err) {
    if (!kf) return bns_fail(err, BNS_EINVAL, "key_file_load: NULL out");
    kf->wif = NULL;
    kf->address = NULL;

    char *text = slurp(path);
    if (!text) return bns_fail(err, BNS_EPERSIST, "cannot read key file %s", path);

    cJSON *root = cJSON_Parse(text);
    /* `text` holds the raw key JSON incl. the WIF — scrub it before free. Note:
     * cJSON keeps a transient internal copy of the WIF string until cJSON_Delete
     * below; that residual is best-effort and out of scope here. */
    OPENSSL_cleanse(text, strlen(text));
    free(text);
    if (!root) return bns_fail(err, BNS_EPARSE, "key file %s is not valid JSON", path);

    const cJSON *wif = cJSON_GetObjectItemCaseSensitive(root, "wif");
    const cJSON *addr = cJSON_GetObjectItemCaseSensitive(root, "address");
    if (!cJSON_IsString(wif) || !wif->valuestring ||
        !cJSON_IsString(addr) || !addr->valuestring) {
        cJSON_Delete(root);
        return bns_fail(err, BNS_EPARSE, "key file %s missing wif/address", path);
    }
    kf->wif = strdup(wif->valuestring);
    kf->address = strdup(addr->valuestring);
    cJSON_Delete(root);
    if (!kf->wif || !kf->address) {
        key_file_free(kf);
        return bns_fail(err, BNS_ENOMEM, "out of memory");
    }
    return BNS_OK;
}

int key_file_verify(const key_file_t *kf, bsv_network_t net, bonsai_err_ctx *err) {
    if (!kf || !kf->wif || !kf->address)
        return bns_fail(err, BNS_EINVAL, "key_file_verify: empty key file");

    ecdsa_key_t *key = NULL;
    ecdsa_pubkey_t *pub = NULL;
    char *derived = NULL;
    bool compressed = false;
    int rc;

    rc = ecdsa_key_from_wif(kf->wif, &key, &compressed);
    if (rc != BNS_OK) { bns_fail(err, rc, "bad WIF in key file"); goto done; }
    rc = ecdsa_key_derive_pubkey(key, &pub);
    if (rc != BNS_OK) { bns_fail(err, rc, "cannot derive pubkey from WIF"); goto done; }
    rc = address_from_pubkey(pub, net, &derived);
    if (rc != BNS_OK) { bns_fail(err, rc, "cannot derive address from WIF"); goto done; }

    if (strcmp(derived, kf->address) != 0) {
        rc = bns_fail(err, BNS_EBINDING, "WIF/address mismatch");
        goto done;
    }
    rc = BNS_OK;

done:
    free(derived);
    ecdsa_pubkey_free(pub);
    ecdsa_key_free(key);
    return rc;
}
