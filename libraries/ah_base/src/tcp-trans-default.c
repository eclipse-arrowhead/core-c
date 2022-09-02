// SPDX-License-Identifier: EPL-2.0

#include "tcp-trans-default.h"

#include "ah/err.h"
#include "ah/intrin.h"
#include "ah/tcp.h"

ah_err_t ah_i_tcp_trans_default_conn_init(void* ctx, ah_tcp_conn_t* conn, ah_loop_t* loop, ah_tcp_trans_t trans, ah_tcp_conn_obs_t obs)
{
    (void) ctx;

    if (ah_unlikely(conn == NULL || loop == NULL || !ah_tcp_trans_vtab_is_valid(trans.vtab) || !ah_tcp_conn_cbs_is_valid_for_connection(obs.cbs))) {
        return AH_EINVAL;
    }

    conn->_loop = loop;
    conn->_trans = trans;
    conn->_obs = obs;
    conn->_state = AH_I_TCP_CONN_STATE_INITIALIZED;

    return AH_ENONE;
}

ah_err_t ah_i_tcp_trans_default_conn_term(void* ctx, ah_tcp_conn_t* conn)
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

int ah_i_tcp_trans_default_conn_get_family(void* ctx, const ah_tcp_conn_t* conn)
{
    (void) ctx;

    if (conn == NULL) {
        return -1;
    }
    return conn->_sock_family;
}

ah_loop_t* ah_i_tcp_trans_default_conn_get_loop(void* ctx, const ah_tcp_conn_t* conn)
{
    (void) ctx;

    if (conn == NULL) {
        return NULL;
    }
    return conn->_loop;
}

void* ah_i_tcp_trans_default_conn_get_obs_ctx(void* ctx, const ah_tcp_conn_t* conn)
{
    (void) ctx;

    if (conn == NULL) {
        return NULL;
    }
    return conn->_obs.ctx;
}

bool ah_i_tcp_trans_default_conn_is_closed(void* ctx, const ah_tcp_conn_t* conn)
{
    (void) ctx;

    return conn == NULL || conn->_state <= AH_I_TCP_CONN_STATE_CLOSING;
}

bool ah_i_tcp_trans_default_conn_is_readable(void* ctx, const ah_tcp_conn_t* conn)
{
    (void) ctx;

    return conn != NULL && conn->_state >= AH_I_TCP_CONN_STATE_CONNECTED
        && (conn->_shutdown_flags & AH_TCP_SHUTDOWN_RD) == 0u;
}

bool ah_i_tcp_trans_default_conn_is_reading(void* ctx, const ah_tcp_conn_t* conn)
{
    (void) ctx;

    return conn != NULL && conn->_state == AH_I_TCP_CONN_STATE_READING;
}

bool ah_i_tcp_trans_default_conn_is_writable(void* ctx, const ah_tcp_conn_t* conn)
{
    (void) ctx;

    return conn != NULL && conn->_state >= AH_I_TCP_CONN_STATE_CONNECTED
        && (conn->_shutdown_flags & AH_TCP_SHUTDOWN_WR) == 0u;
}

ah_err_t ah_i_tcp_trans_default_listener_init(void* ctx, ah_tcp_listener_t* ln, ah_loop_t* loop, ah_tcp_trans_t trans, ah_tcp_listener_obs_t obs)
{
    (void) ctx;

    if (ah_unlikely(ln == NULL || loop == NULL || !ah_tcp_trans_vtab_is_valid(trans.vtab) || !ah_tcp_listener_cbs_is_valid(obs.cbs))) {
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

ah_err_t ah_i_tcp_trans_default_listener_term(void* ctx, ah_tcp_listener_t* ln)
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

int ah_i_tcp_trans_default_listener_get_family(void* ctx, const ah_tcp_listener_t* ln)
{
    (void) ctx;

    if (ln == NULL) {
        return -1;
    }
    return ln->_sock_family;
}

ah_loop_t* ah_i_tcp_trans_default_listener_get_loop(void* ctx, const ah_tcp_listener_t* ln)
{
    (void) ctx;

    if (ln == NULL) {
        return NULL;
    }
    return ln->_loop;
}

void* ah_i_tcp_trans_default_listener_get_obs_ctx(void* ctx, const ah_tcp_listener_t* ln)
{
    (void) ctx;

    if (ln == NULL) {
        return NULL;
    }
    return ln->_obs.ctx;
}

bool ah_i_tcp_trans_default_listener_is_closed(void* ctx, ah_tcp_listener_t* ln)
{
    (void) ctx;

    return ln == NULL || ln->_state <= AH_I_TCP_LISTENER_STATE_CLOSING;
}

ah_err_t ah_i_tcp_trans_default_trans_init(void* ctx, ah_tcp_trans_t* trans)
{
    (void) ctx;

    if (trans == NULL) {
        return AH_EINVAL;
    }

    *trans = ah_tcp_trans_get_default();

    return AH_ENONE;
}

ah_err_t ah_i_tcp_trans_default_trans_term(void* ctx, ah_tcp_trans_t trans)
{
    (void) ctx;
    (void) trans;

    return AH_ENONE;
}
