/* mock_chain_source.c — see mock_chain_source.h. */
#include "mock_chain_source.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "fixtures.h"   /* fix_raw_tx_* convenience builders */

/* ---- tiny dynamic-array tables ------------------------------------------ */

typedef struct { char *txid; char *raw; } raw_entry_t;
typedef struct { char *txid; int64_t time; } time_entry_t;
typedef struct { char *txid; uint32_t vout; char *spender; bool present; } spend_entry_t;

struct mock_chain_source_s {
    raw_entry_t   *raw;    size_t raw_n,   raw_cap;
    time_entry_t  *times;  size_t time_n,  time_cap;
    spend_entry_t *spends; size_t spend_n, spend_cap;
    int64_t        default_time;
    bool           fail_next;
    size_t         calls_get_raw_tx;
    size_t         calls_get_spending_txid;
    size_t         calls_get_time;
};

static char *dup_str(const char *s)
{
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *d = malloc(n);
    if (d) memcpy(d, s, n);
    return d;
}

mock_chain_source_t *mock_chain_source_new(int64_t default_time)
{
    mock_chain_source_t *m = calloc(1, sizeof(*m));
    if (m) m->default_time = default_time;
    return m;
}

void mock_chain_source_free(mock_chain_source_t *m)
{
    if (!m) return;
    for (size_t i = 0; i < m->raw_n; i++)   { free(m->raw[i].txid); free(m->raw[i].raw); }
    for (size_t i = 0; i < m->time_n; i++)  { free(m->times[i].txid); }
    for (size_t i = 0; i < m->spend_n; i++) { free(m->spends[i].txid); free(m->spends[i].spender); }
    free(m->raw); free(m->times); free(m->spends);
    free(m);
}

/* ---- builder API -------------------------------------------------------- */

int mock_chain_source_add_raw(mock_chain_source_t *m, const char *txid,
                              const char *raw_hex)
{
    if (!m || !txid || !raw_hex) return BNS_EINVAL;
    for (size_t i = 0; i < m->raw_n; i++) {
        if (strcmp(m->raw[i].txid, txid) == 0) {
            char *nr = dup_str(raw_hex);
            if (!nr) return BNS_ENOMEM;
            free(m->raw[i].raw);
            m->raw[i].raw = nr;
            return BNS_OK;
        }
    }
    if (m->raw_n == m->raw_cap) {
        size_t nc = m->raw_cap ? m->raw_cap * 2 : 8;
        raw_entry_t *p = realloc(m->raw, nc * sizeof(*p));
        if (!p) return BNS_ENOMEM;
        m->raw = p; m->raw_cap = nc;
    }
    char *tx = dup_str(txid), *rw = dup_str(raw_hex);
    if (!tx || !rw) { free(tx); free(rw); return BNS_ENOMEM; }
    m->raw[m->raw_n].txid = tx;
    m->raw[m->raw_n].raw = rw;
    m->raw_n++;
    return BNS_OK;
}

int mock_chain_source_set_time(mock_chain_source_t *m, const char *txid,
                               int64_t time)
{
    if (!m || !txid) return BNS_EINVAL;
    for (size_t i = 0; i < m->time_n; i++) {
        if (strcmp(m->times[i].txid, txid) == 0) { m->times[i].time = time; return BNS_OK; }
    }
    if (m->time_n == m->time_cap) {
        size_t nc = m->time_cap ? m->time_cap * 2 : 8;
        time_entry_t *p = realloc(m->times, nc * sizeof(*p));
        if (!p) return BNS_ENOMEM;
        m->times = p; m->time_cap = nc;
    }
    char *tx = dup_str(txid);
    if (!tx) return BNS_ENOMEM;
    m->times[m->time_n].txid = tx;
    m->times[m->time_n].time = time;
    m->time_n++;
    return BNS_OK;
}

int mock_chain_source_link(mock_chain_source_t *m, const char *txid,
                           uint32_t vout, const char *spender)
{
    if (!m || !txid) return BNS_EINVAL;
    for (size_t i = 0; i < m->spend_n; i++) {
        if (m->spends[i].vout == vout && strcmp(m->spends[i].txid, txid) == 0) {
            char *ns = dup_str(spender);
            if (spender && !ns) return BNS_ENOMEM;
            free(m->spends[i].spender);
            m->spends[i].spender = ns;
            m->spends[i].present = true;
            return BNS_OK;
        }
    }
    if (m->spend_n == m->spend_cap) {
        size_t nc = m->spend_cap ? m->spend_cap * 2 : 8;
        spend_entry_t *p = realloc(m->spends, nc * sizeof(*p));
        if (!p) return BNS_ENOMEM;
        m->spends = p; m->spend_cap = nc;
    }
    char *tx = dup_str(txid);
    if (!tx) return BNS_ENOMEM;
    char *sp = dup_str(spender);
    if (spender && !sp) { free(tx); return BNS_ENOMEM; }
    m->spends[m->spend_n].txid = tx;
    m->spends[m->spend_n].vout = vout;
    m->spends[m->spend_n].spender = sp;
    m->spends[m->spend_n].present = true;
    m->spend_n++;
    return BNS_OK;
}

int mock_chain_source_add_state_tx(mock_chain_source_t *m, const char *txid,
                                   const char *receipt_hash_hex)
{
    if (!m || !txid) return BNS_EINVAL;
    char *raw = NULL;
    int rc = fix_raw_tx_recreated(receipt_hash_hex, &raw);
    if (rc != BNS_OK) return rc;
    rc = mock_chain_source_add_raw(m, txid, raw);
    free(raw);
    return rc;
}

int mock_chain_source_add_terminal_tx(mock_chain_source_t *m, const char *txid)
{
    if (!m || !txid) return BNS_EINVAL;
    char *raw = NULL;
    int rc = fix_raw_tx_p2pkh_terminal(&raw);
    if (rc != BNS_OK) return rc;
    rc = mock_chain_source_add_raw(m, txid, raw);
    free(raw);
    return rc;
}

int mock_chain_source_add_no_output_tx(mock_chain_source_t *m, const char *txid)
{
    if (!m || !txid) return BNS_EINVAL;
    char *raw = NULL;
    int rc = fix_raw_tx_no_outputs(&raw);
    if (rc != BNS_OK) return rc;
    rc = mock_chain_source_add_raw(m, txid, raw);
    free(raw);
    return rc;
}

void mock_chain_source_fail_next(mock_chain_source_t *m, bool fail)
{
    if (m) m->fail_next = fail;
}

void mock_chain_source_calls(const mock_chain_source_t *m,
                             size_t *out_get_raw_tx,
                             size_t *out_get_spending_txid,
                             size_t *out_get_time)
{
    if (!m) return;
    if (out_get_raw_tx)        *out_get_raw_tx        = m->calls_get_raw_tx;
    if (out_get_spending_txid) *out_get_spending_txid = m->calls_get_spending_txid;
    if (out_get_time)          *out_get_time          = m->calls_get_time;
}

/* ---- chain_source_t vtable impls ---------------------------------------- */

static int mcs_get_raw_tx(void *ctx, const char *txid, char **out_hex)
{
    mock_chain_source_t *m = ctx;
    m->calls_get_raw_tx++;
    if (m->fail_next) { m->fail_next = false; return BNS_ENET; }
    if (!txid || !out_hex) return BNS_EINVAL;
    for (size_t i = 0; i < m->raw_n; i++) {
        if (strcmp(m->raw[i].txid, txid) == 0) {
            char *r = dup_str(m->raw[i].raw);
            if (!r) return BNS_ENOMEM;
            *out_hex = r;
            return BNS_OK;
        }
    }
    return BNS_ENOTFOUND;   /* TS FakeChain throws `no raw for ${txid}` */
}

static int mcs_get_time(void *ctx, const char *txid, int64_t *out_time)
{
    mock_chain_source_t *m = ctx;
    m->calls_get_time++;
    if (!out_time) return BNS_EINVAL;
    for (size_t i = 0; i < m->time_n; i++) {
        if (txid && strcmp(m->times[i].txid, txid) == 0) {
            *out_time = m->times[i].time;
            return BNS_OK;
        }
    }
    *out_time = m->default_time;
    return BNS_OK;
}

static int mcs_get_spending_txid(void *ctx, const char *txid, uint32_t vout,
                                 char **out_spender)
{
    mock_chain_source_t *m = ctx;
    m->calls_get_spending_txid++;
    if (m->fail_next) { m->fail_next = false; return BNS_ENET; }
    if (!txid || !out_spender) return BNS_EINVAL;
    for (size_t i = 0; i < m->spend_n; i++) {
        if (m->spends[i].vout == vout && strcmp(m->spends[i].txid, txid) == 0) {
            if (!m->spends[i].spender) { *out_spender = NULL; return BNS_OK; }
            char *s = dup_str(m->spends[i].spender);
            if (!s) return BNS_ENOMEM;
            *out_spender = s;
            return BNS_OK;
        }
    }
    *out_spender = NULL;   /* unrecorded => unspent (TS: ?? null) */
    return BNS_OK;
}

int mock_chain_source_as_source(mock_chain_source_t *m, chain_source_t *out)
{
    if (!m || !out) return BNS_EINVAL;
    out->ctx = m;
    out->get_raw_tx = mcs_get_raw_tx;
    out->get_time = mcs_get_time;
    out->get_spending_txid = mcs_get_spending_txid;
    return BNS_OK;
}

void mock_chain_source_disable_spend_index(chain_source_t *out)
{
    if (out) out->get_spending_txid = NULL;
}
