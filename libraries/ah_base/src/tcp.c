// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"
#include "ah/sock.h"

static ah_err_t s_trans_conn_init(void* ctx, ah_tcp_conn_t* conn, ah_loop_t* loop, ah_tcp_trans_t trans, ah_tcp_conn_obs_t obs);
ah_err_t ah_i_tcp_trans_conn_open(void* ctx, ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr);
ah_err_t ah_i_tcp_trans_conn_connect(void* ctx, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr);
ah_err_t ah_i_tcp_trans_conn_read_start(void* ctx, ah_tcp_conn_t* conn);
ah_err_t ah_i_tcp_trans_conn_read_stop(void* ctx, ah_tcp_conn_t* conn);
ah_err_t ah_i_tcp_trans_conn_write(void* ctx, ah_tcp_conn_t* conn, ah_tcp_out_t* out);
ah_err_t ah_i_tcp_trans_conn_shutdown(void* ctx, ah_tcp_conn_t* conn, uint8_t flags);
ah_err_t ah_i_tcp_trans_conn_close(void* ctx, ah_tcp_conn_t* conn);
static ah_err_t s_trans_conn_term(void* ctx, ah_tcp_conn_t* conn);

static ah_err_t s_trans_listener_init(void* ctx, ah_tcp_listener_t* ln, ah_loop_t* loop, ah_tcp_trans_t trans, ah_tcp_listener_obs_t obs);
ah_err_t ah_i_tcp_trans_listener_open(void* ctx, ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr);
ah_err_t ah_i_tcp_trans_listener_listen(void* ctx, ah_tcp_listener_t* ln, unsigned backlog);
ah_err_t ah_i_tcp_trans_listener_close(void* ctx, ah_tcp_listener_t* ln);
static ah_err_t s_trans_listener_term(void* ctx, ah_tcp_listener_t* ln);

ah_extern ah_err_t ah_tcp_conn_init(ah_tcp_conn_t* conn, ah_loop_t* loop, ah_tcp_trans_t trans, ah_tcp_conn_obs_t obs)
{
    if (conn == NULL || trans.vtab == NULL || trans.vtab->conn_init == NULL) {
        return AH_EINVAL;
    }

    (void) memset(conn, 0, sizeof(*conn));

    return trans.vtab->conn_init(trans.ctx, conn, loop, trans, obs);
}

static ah_err_t s_trans_conn_init(void* ctx, ah_tcp_conn_t* conn, ah_loop_t* loop, ah_tcp_trans_t trans, ah_tcp_conn_obs_t obs)
{
    (void) ctx;

    if (conn == NULL || loop == NULL || !ah_tcp_trans_vtab_is_valid(trans.vtab) || !ah_tcp_conn_cbs_is_valid_for_connection(obs.cbs)) {
        return AH_EINVAL;
    }

    conn->_loop = loop;
    conn->_trans = trans;
    conn->_obs = obs;
    conn->_state = AH_I_TCP_CONN_STATE_INITIALIZED;

    return AH_ENONE;
}

ah_extern ah_err_t ah_tcp_conn_open(ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_INITIALIZED) {
        return AH_ESTATE;
    }

    ah_assert_if_debug(conn->_trans.vtab != NULL && conn->_trans.vtab->conn_open != NULL);

    return conn->_trans.vtab->conn_open(conn->_trans.ctx, conn, laddr);
}

ah_extern ah_err_t ah_tcp_conn_connect(ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_OPEN) {
        return AH_ESTATE;
    }

    ah_assert_if_debug(conn->_trans.vtab != NULL && conn->_trans.vtab->conn_connect != NULL);

    return conn->_trans.vtab->conn_connect(conn->_trans.ctx, conn, raddr);
}

ah_extern ah_err_t ah_tcp_conn_read_start(ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_CONNECTED) {
        return AH_ESTATE;
    }

    ah_assert_if_debug(conn->_trans.vtab != NULL && conn->_trans.vtab->conn_read_start != NULL);

    return conn->_trans.vtab->conn_read_start(conn->_trans.ctx, conn);
}

ah_extern ah_err_t ah_tcp_conn_read_stop(ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_READING) {
        return AH_ESTATE;
    }

    ah_assert_if_debug(conn->_trans.vtab != NULL && conn->_trans.vtab->conn_read_stop != NULL);

    return conn->_trans.vtab->conn_read_stop(conn->_trans.ctx, conn);
}

ah_extern ah_err_t ah_tcp_conn_write(ah_tcp_conn_t* conn, ah_tcp_out_t* out)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state < AH_I_TCP_CONN_STATE_CONNECTED) {
        return AH_ESTATE;
    }

    ah_assert_if_debug(conn->_trans.vtab != NULL && conn->_trans.vtab->conn_write != NULL);

    return conn->_trans.vtab->conn_write(conn->_trans.ctx, conn, out);
}

ah_extern ah_err_t ah_tcp_conn_shutdown(ah_tcp_conn_t* conn, uint8_t flags)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state < AH_I_TCP_CONN_STATE_CONNECTED) {
        return AH_ESTATE;
    }

    ah_assert_if_debug(conn->_trans.vtab != NULL && conn->_trans.vtab->conn_shutdown != NULL);

    return conn->_trans.vtab->conn_shutdown(conn->_trans.ctx, conn, flags);
}

ah_extern ah_err_t ah_tcp_conn_close(ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state <= AH_I_TCP_CONN_STATE_CLOSED) {
        return AH_ESTATE;
    }

    ah_assert_if_debug(conn->_trans.vtab != NULL && conn->_trans.vtab->conn_close != NULL);

    return conn->_trans.vtab->conn_close(conn->_trans.ctx, conn);
}

ah_extern ah_err_t ah_tcp_conn_term(ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_CLOSED) {
        return AH_ESTATE;
    }

    ah_assert_if_debug(conn->_trans.vtab != NULL && conn->_trans.vtab->conn_term != NULL);

    return conn->_trans.vtab->conn_term(conn->_trans.ctx, conn);
}

static ah_err_t s_trans_conn_term(void* ctx, ah_tcp_conn_t* conn)
{
    (void) ctx;

    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_CLOSED) {
        return AH_ESTATE;
    }
    conn->_state = AH_I_TCP_CONN_STATE_TERMINATED;

    if (conn->_owning_slab != NULL) {
        ah_i_slab_free(conn->_owning_slab, conn);
    }

    return AH_ENONE;
}

ah_extern int ah_tcp_conn_get_family(const ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return -1;
    }
    return conn->_is_ipv6 ? AH_SOCKFAMILY_IPV6 : AH_SOCKFAMILY_IPV4;
}

ah_extern ah_loop_t* ah_tcp_conn_get_loop(const ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return NULL;
    }
    return conn->_loop;
}

ah_extern uint8_t ah_tcp_conn_get_shutdown_flags(const ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return AH_TCP_SHUTDOWN_RDWR;
    }
    return conn->_shutdown_flags;
}

ah_extern void* ah_tcp_conn_get_obs_ctx(const ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return NULL;
    }
    return conn->_obs.ctx;
}

ah_extern bool ah_tcp_conn_is_closed(const ah_tcp_conn_t* conn)
{
    return conn == NULL || conn->_state <= AH_I_TCP_CONN_STATE_CLOSED;
}

ah_extern bool ah_tcp_conn_is_readable(const ah_tcp_conn_t* conn)
{
    return conn != NULL && conn->_state >= AH_I_TCP_CONN_STATE_CONNECTED
        && (conn->_shutdown_flags & AH_TCP_SHUTDOWN_RD) == 0u;
}

ah_extern bool ah_tcp_conn_is_readable_and_writable(const ah_tcp_conn_t* conn)
{
    return conn != NULL && conn->_state >= AH_I_TCP_CONN_STATE_CONNECTED
        && (conn->_shutdown_flags & AH_TCP_SHUTDOWN_RDWR) == 0u;
}

ah_extern bool ah_tcp_conn_is_reading(const ah_tcp_conn_t* conn)
{
    return conn != NULL && conn->_state == AH_I_TCP_CONN_STATE_READING;
}

ah_extern bool ah_tcp_conn_is_writable(const ah_tcp_conn_t* conn)
{
    return conn != NULL && conn->_state >= AH_I_TCP_CONN_STATE_CONNECTED
        && (conn->_shutdown_flags & AH_TCP_SHUTDOWN_WR) == 0u;
}

ah_extern bool ah_tcp_conn_cbs_is_valid_for_acceptance(const ah_tcp_conn_cbs_t* cbs)
{
    return cbs != NULL
        && cbs->on_read != NULL
        && cbs->on_write != NULL
        && cbs->on_close != NULL;
}

ah_extern bool ah_tcp_conn_cbs_is_valid_for_connection(const ah_tcp_conn_cbs_t* cbs)
{
    return cbs != NULL
        && cbs->on_open != NULL
        && cbs->on_connect != NULL
        && ah_tcp_conn_cbs_is_valid_for_acceptance(cbs);
}

ah_extern ah_err_t ah_tcp_in_alloc_for(ah_tcp_in_t** owner_ptr)
{
    if (owner_ptr == NULL) {
        return AH_EINVAL;
    }

    uint8_t* page = ah_palloc();
    if (page == NULL) {
        return AH_ENOMEM;
    }

    ah_tcp_in_t* in = (void*) page;

    uint8_t* base = &page[sizeof(ah_tcp_in_t)];
    uint8_t* end = &page[AH_PSIZE];

    if (base >= end) {
        return AH_EOVERFLOW;
    }

    *in = (ah_tcp_in_t) {
        .rw.r = base,
        .rw.w = base,
        .rw.e = end,
        ._owner_ptr = owner_ptr,
    };

    *owner_ptr = in;

    return AH_ENONE;
}

ah_extern ah_err_t ah_tcp_in_detach(ah_tcp_in_t* in)
{
    if (in == NULL) {
        return AH_EINVAL;
    }
    if (in->_owner_ptr == NULL) {
        return AH_ESTATE;
    }

    ah_err_t err = ah_tcp_in_alloc_for(in->_owner_ptr);
    if (err != AH_ENONE) {
        return err;
    }

    in->_owner_ptr = NULL;

    return AH_ENONE;
}

ah_extern void ah_tcp_in_free(ah_tcp_in_t* in)
{
    if (in != NULL) {
#ifndef NDEBUG
        memset(in, 0, AH_PSIZE);
#endif
        ah_pfree(in);
    }
}

ah_extern ah_err_t ah_tcp_in_repackage(ah_tcp_in_t* in)
{
    if (in == NULL) {
        return AH_EINVAL;
    }

    uint8_t* r_off = in->rw.r;
    size_t r_size = ah_rw_get_readable_size(&in->rw);

    ah_tcp_in_reset(in);

    if (in->rw.r == r_off) {
        if (ah_unlikely(in->rw.w == in->rw.e)) {
            return AH_EOVERFLOW;
        }
        return AH_ENONE;
    }

    memmove(in->rw.r, r_off, r_size);

    in->rw.w = &in->rw.r[r_size];

    return AH_ENONE;
}

ah_extern void ah_tcp_in_reset(ah_tcp_in_t* in)
{
    if (in == NULL) {
        return;
    }

    uint8_t* page = (uint8_t*) in;

    uint8_t* base = &page[sizeof(ah_tcp_in_t)];
    in->rw.r = base;
    in->rw.w = base;
}

ah_extern ah_err_t ah_tcp_listener_init(ah_tcp_listener_t* ln, ah_loop_t* loop, ah_tcp_trans_t trans, ah_tcp_listener_obs_t obs)
{
    if (ln == NULL || trans.vtab == NULL || trans.vtab->listener_init == NULL) {
        return AH_EINVAL;
    }

    (void) memset(ln, 0, sizeof(*ln));

    return trans.vtab->listener_init(trans.ctx, ln, loop, trans, obs);
}

static ah_err_t s_trans_listener_init(void* ctx, ah_tcp_listener_t* ln, ah_loop_t* loop, ah_tcp_trans_t trans, ah_tcp_listener_obs_t obs)
{
    (void) ctx;

    if (ln == NULL || loop == NULL || !ah_tcp_trans_vtab_is_valid(trans.vtab) || !ah_tcp_listener_cbs_is_valid(obs.cbs)) {
        return AH_EINVAL;
    }

    ln->_loop = loop;
    ln->_trans = trans;
    ln->_obs = obs;

    ah_err_t err = ah_i_slab_init(&ln->_conn_slab, 1u, sizeof(ah_tcp_conn_t));
    if (err != AH_ENONE) {
        return err;
    }

    ln->_state = AH_I_TCP_LISTENER_STATE_INITIALIZED;

    return AH_ENONE;
}

ah_extern ah_err_t ah_tcp_listener_open(ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr)
{
    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state != AH_I_TCP_LISTENER_STATE_INITIALIZED) {
        return AH_ESTATE;
    }

    ah_assert_if_debug(ln->_trans.vtab != NULL && ln->_trans.vtab->listener_open != NULL);

    return ln->_trans.vtab->listener_open(ln->_trans.ctx, ln, laddr);
}

ah_extern ah_err_t ah_tcp_listener_listen(ah_tcp_listener_t* ln, unsigned backlog)
{
    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state != AH_I_TCP_LISTENER_STATE_OPEN) {
        return AH_ESTATE;
    }

    ah_assert_if_debug(ln->_trans.vtab != NULL && ln->_trans.vtab->listener_listen != NULL);

    return ln->_trans.vtab->listener_listen(ln->_trans.ctx, ln, backlog);
}

ah_extern ah_err_t ah_tcp_listener_close(ah_tcp_listener_t* ln)
{
    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state <= AH_I_TCP_LISTENER_STATE_CLOSED) {
        return AH_ESTATE;
    }

    ah_assert_if_debug(ln->_trans.vtab != NULL && ln->_trans.vtab->listener_close != NULL);

    return ln->_trans.vtab->listener_close(ln->_trans.ctx, ln);
}

ah_extern ah_err_t ah_tcp_listener_term(ah_tcp_listener_t* ln)
{
    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state != AH_I_TCP_LISTENER_STATE_CLOSED) {
        return AH_ESTATE;
    }

    ah_assert_if_debug(ln->_trans.vtab != NULL && ln->_trans.vtab->listener_term != NULL);

    return ln->_trans.vtab->listener_term(ln->_trans.ctx, ln);
}

static ah_err_t s_trans_listener_term(void* ctx, ah_tcp_listener_t* ln)
{
    (void) ctx;

    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state != AH_I_TCP_LISTENER_STATE_CLOSED) {
        return AH_ESTATE;
    }
    ln->_state = AH_I_TCP_LISTENER_STATE_TERMINATED;

    ah_i_slab_term(&ln->_conn_slab, NULL);

    return AH_ENONE;
}

ah_extern int ah_tcp_listener_get_family(const ah_tcp_listener_t* ln)
{
    if (ln == NULL) {
        return -1;
    }
    return ln->_is_ipv6 ? AH_SOCKFAMILY_IPV6 : AH_SOCKFAMILY_IPV4;
}

ah_extern ah_loop_t* ah_tcp_listener_get_loop(const ah_tcp_listener_t* ln)
{
    if (ln == NULL) {
        return NULL;
    }
    return ln->_loop;
}

ah_extern void* ah_tcp_listener_get_obs_ctx(const ah_tcp_listener_t* ln)
{
    if (ln == NULL) {
        return NULL;
    }
    return ln->_obs.ctx;
}

ah_extern bool ah_tcp_listener_is_closed(ah_tcp_listener_t* ln)
{
    return ln == NULL || ln->_state <= AH_I_TCP_LISTENER_STATE_CLOSED;
}

ah_extern bool ah_tcp_listener_cbs_is_valid(const ah_tcp_listener_cbs_t* cbs)
{
    return cbs != NULL
        && cbs->on_open != NULL
        && cbs->on_listen != NULL
        && cbs->on_accept != NULL
        && cbs->on_close != NULL;
}

ah_extern ah_tcp_out_t* ah_tcp_out_alloc(void)
{
    uint8_t* page = ah_palloc();
    if (page == NULL) {
        return NULL;
    }

    ah_tcp_out_t* out = (void*) page;

    *out = (ah_tcp_out_t) {
        .buf = ah_buf_from(&page[sizeof(ah_tcp_out_t)], AH_TCP_OUT_BUF_SIZE),
    };

    if (out->buf.size > AH_PSIZE) {
        ah_pfree(page);
        return NULL;
    }

    return out;
}

ah_extern void ah_tcp_out_free(ah_tcp_out_t* out)
{
    if (out != NULL) {
        ah_pfree(out);
    }
}

ah_extern ah_tcp_trans_t ah_tcp_trans_get_root(void)
{
    static const ah_tcp_trans_vtab_t s_vtab = {
        .conn_init = s_trans_conn_init,
        .conn_open = ah_i_tcp_trans_conn_open,
        .conn_connect = ah_i_tcp_trans_conn_connect,
        .conn_read_start = ah_i_tcp_trans_conn_read_start,
        .conn_read_stop = ah_i_tcp_trans_conn_read_stop,
        .conn_write = ah_i_tcp_trans_conn_write,
        .conn_shutdown = ah_i_tcp_trans_conn_shutdown,
        .conn_close = ah_i_tcp_trans_conn_close,
        .conn_term = s_trans_conn_term,

        .listener_init = s_trans_listener_init,
        .listener_open = ah_i_tcp_trans_listener_open,
        .listener_listen = ah_i_tcp_trans_listener_listen,
        .listener_close = ah_i_tcp_trans_listener_close,
        .listener_term = s_trans_listener_term,
    };

    return (ah_tcp_trans_t) {
        .vtab = &s_vtab,
        .ctx = NULL,
    };
}

ah_extern bool ah_tcp_trans_vtab_is_valid(const ah_tcp_trans_vtab_t* vtab)
{
    return vtab != NULL
        && vtab->conn_init != NULL
        && vtab->conn_open != NULL
        && vtab->conn_connect != NULL
        && vtab->conn_read_start != NULL
        && vtab->conn_read_stop != NULL
        && vtab->conn_write != NULL
        && vtab->conn_shutdown != NULL
        && vtab->conn_close != NULL
        && vtab->listener_init != NULL
        && vtab->listener_open != NULL
        && vtab->listener_listen != NULL
        && vtab->listener_close != NULL;
}
