/* Durable local persistence for the resumable AgentTea lifecycle. */
#ifndef BONSAI_SCRIPTS_AGENTD_PERSISTENCE_H
#define BONSAI_SCRIPTS_AGENTD_PERSISTENCE_H

#include "common/error.h"

/* Atomically replace path with text using a 0600 same-directory temporary
 * file. The file and containing directory are fsync'd before success. */
int agentd_write_file_atomic(const char *path, const char *text);

/* Append "<tag> <txid>\n" to the state-file broadcast journal. The append and
 * directory entry are fsync'd before success; files are forced to mode 0600. */
int agentd_journal_broadcast(const char *state_file, const char *tag,
                             const char *txid);

#endif /* BONSAI_SCRIPTS_AGENTD_PERSISTENCE_H */
