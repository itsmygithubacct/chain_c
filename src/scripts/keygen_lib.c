/*
 * keygen_lib.c — logic for the `keygen` CLI (see include/scripts/keygen.h).
 *
 * Generates a fresh random mainnet P2PKH key via wallet_generate_key and either
 * writes a {"wif","address"} key file (0600, no overwrite) or prints it.
 */
#include "scripts/keygen.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h> /* OPENSSL_cleanse — scrub the cleartext WIF secret */

#include "wallet/keygen.h"
#include "scripts/script_support.h"

/* Atomically write {"wif","address"} JSON to `path` (0600, never overwriting an
 * existing file). The JSON is built in a local buffer that is OPENSSL_cleanse'd
 * afterwards — the WIF never passes through an unscrubbed stdio buffer — then
 * written to a sibling temp file, fsync'd, and link()'d into place. link() is
 * atomic and fails closed (EEXIST) if `path` already exists, so a crash never
 * leaves a partial or clobbered key file at `path`. */
static int write_key_file(const char *path, const char *wif, const char *address)
{
    char json[512];
    int n = snprintf(json, sizeof json,
                     "{\n  \"wif\": \"%s\",\n  \"address\": \"%s\"\n}\n", wif, address);
    if (n < 0 || (size_t)n >= sizeof json)
        { OPENSSL_cleanse(json, sizeof json); return BNS_EPERSIST; }

    char tmpl[PATH_MAX];
    if (snprintf(tmpl, sizeof tmpl, "%s.tmpXXXXXX", path) >= (int)sizeof tmpl)
        { OPENSSL_cleanse(json, sizeof json); return BNS_EPERSIST; }

    int fd = mkstemp(tmpl);                 /* random name, O_EXCL, 0600 */
    if (fd < 0) { OPENSSL_cleanse(json, sizeof json); return BNS_EPERSIST; }

    int rc = BNS_OK;
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) rc = BNS_EPERSIST;
    for (size_t off = 0; rc == BNS_OK && off < (size_t)n; ) {
        ssize_t w = write(fd, json + off, (size_t)n - off);
        if (w < 0) { if (errno == EINTR) continue; rc = BNS_EPERSIST; break; }
        off += (size_t)w;
    }
    if (rc == BNS_OK && fsync(fd) != 0) rc = BNS_EPERSIST;
    if (close(fd) != 0) rc = BNS_EPERSIST;
    OPENSSL_cleanse(json, sizeof json);

    if (rc == BNS_OK && link(tmpl, path) != 0) rc = BNS_EPERSIST;  /* fails if `path` exists */
    unlink(tmpl);                            /* drop the temp on every path */
    return rc;
}

int keygen_run(int argc, char **argv, int *out_exit_code)
{
    int dummy = 0;
    if (!out_exit_code) out_exit_code = &dummy;
    *out_exit_code = 0;

    const char *path = (argc > 1 && argv[1] && argv[1][0]) ? argv[1]
                                                           : env_get("KEY_FILE");

    char *wif = NULL;
    char *addr = NULL;
    int rc = wallet_generate_key(BSV_MAINNET, &wif, &addr);
    if (rc != BNS_OK) {
        fprintf(stderr, "keygen: key generation failed: %s\n", bns_err_name((bonsai_err_t)rc));
        *out_exit_code = 1;
        return BNS_OK;
    }

    if (path && path[0]) {
        /* Refuse to clobber an existing key file (never destroy key material). */
        FILE *exists = fopen(path, "r");
        if (exists) {
            fclose(exists);
            fprintf(stderr, "keygen: refusing to overwrite existing key file %s\n", path);
            if (wif) OPENSSL_cleanse(wif, strlen(wif));
            free(wif);
            free(addr);
            *out_exit_code = 1;
            return BNS_OK;
        }
        rc = write_key_file(path, wif, addr);
        if (rc != BNS_OK) {
            fprintf(stderr, "keygen: cannot write %s: %s\n", path,
                    bns_err_name((bonsai_err_t)rc));  /* errno is unreliable across the write */
            if (wif) OPENSSL_cleanse(wif, strlen(wif));
            free(wif);
            free(addr);
            *out_exit_code = 1;
            return BNS_OK;
        }
        printf("%s\n", addr); /* address only; the WIF is now on disk (0600) */
        fprintf(stderr, "keygen: wrote key file %s (0600)\n", path);
    } else {
        printf("{\"wif\":\"%s\",\"address\":\"%s\"}\n", wif, addr);
    }

    if (wif) OPENSSL_cleanse(wif, strlen(wif));
    free(wif);
    free(addr);
    return BNS_OK;
}
