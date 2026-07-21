/* Crash-durable state and accepted-broadcast persistence for agentd. */
#include "scripts/agentd_persistence.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int write_all(int fd, const char *data, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t written = write(fd, data + off, len - off);
        if (written < 0) {
            if (errno == EINTR) continue;
            return BNS_EPERSIST;
        }
        if (written == 0) return BNS_EPERSIST;
        off += (size_t)written;
    }
    return BNS_OK;
}

static int fsync_parent_dir(const char *path)
{
    if (path == NULL || path[0] == '\0') return BNS_EINVAL;
    char *copy = strdup(path);
    if (copy == NULL) return BNS_ENOMEM;

    char *slash = strrchr(copy, '/');
    const char *dir = ".";
    if (slash != NULL) {
        if (slash == copy) slash[1] = '\0';
        else *slash = '\0';
        dir = copy;
    }

    int flags = O_RDONLY;
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
    int fd = open(dir, flags);
    free(copy);
    if (fd < 0) return BNS_EPERSIST;
    int rc = fsync(fd) == 0 ? BNS_OK : BNS_EPERSIST;
    if (close(fd) != 0 && rc == BNS_OK) rc = BNS_EPERSIST;
    return rc;
}

int agentd_write_file_atomic(const char *path, const char *text)
{
    if (path == NULL || path[0] == '\0' || text == NULL) return BNS_EINVAL;
    size_t path_len = strlen(path);
    char *tmp = malloc(path_len + sizeof ".tmp.XXXXXX");
    if (tmp == NULL) return BNS_ENOMEM;
    snprintf(tmp, path_len + sizeof ".tmp.XXXXXX", "%s.tmp.XXXXXX", path);

    int fd = mkstemp(tmp); /* O_CREAT|O_EXCL and mode 0600 */
    if (fd < 0) { free(tmp); return BNS_EPERSIST; }
    int rc = BNS_OK;
    if (fchmod(fd, 0600) != 0) rc = BNS_EPERSIST;
    if (rc == BNS_OK) rc = write_all(fd, text, strlen(text));
    if (rc == BNS_OK && fsync(fd) != 0) rc = BNS_EPERSIST;
    if (close(fd) != 0 && rc == BNS_OK) rc = BNS_EPERSIST;
    if (rc != BNS_OK) {
        unlink(tmp);
        free(tmp);
        return rc;
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        free(tmp);
        return BNS_EPERSIST;
    }
    free(tmp);
    return fsync_parent_dir(path);
}

int agentd_journal_broadcast(const char *state_file, const char *tag,
                             const char *txid)
{
    if (state_file == NULL || state_file[0] == '\0' || tag == NULL || tag[0] == '\0' ||
        txid == NULL || txid[0] == '\0') return BNS_EINVAL;

    const char *override = getenv("AGENTD_BROADCAST_JOURNAL");
    char *path = NULL;
    if (override != NULL && override[0] != '\0') {
        path = strdup(override);
    } else {
        size_t n = strlen(state_file) + sizeof ".broadcasts";
        path = malloc(n);
        if (path != NULL) snprintf(path, n, "%s.broadcasts", state_file);
    }
    if (path == NULL) return BNS_ENOMEM;

    int line_len = snprintf(NULL, 0, "%s %s\n", tag, txid);
    if (line_len < 0) { free(path); return BNS_EPERSIST; }
    char *line = malloc((size_t)line_len + 1);
    if (line == NULL) { free(path); return BNS_ENOMEM; }
    snprintf(line, (size_t)line_len + 1, "%s %s\n", tag, txid);

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    int rc = BNS_OK;
    if (fd < 0) rc = BNS_EPERSIST;
    else {
        if (fchmod(fd, 0600) != 0) rc = BNS_EPERSIST;
        if (rc == BNS_OK) rc = write_all(fd, line, (size_t)line_len);
        if (rc == BNS_OK && fsync(fd) != 0) rc = BNS_EPERSIST;
        if (close(fd) != 0 && rc == BNS_OK) rc = BNS_EPERSIST;
    }
    if (rc == BNS_OK) rc = fsync_parent_dir(path);
    free(line);
    free(path);
    return rc;
}
