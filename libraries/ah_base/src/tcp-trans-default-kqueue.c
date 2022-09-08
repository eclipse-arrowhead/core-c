// SPDX-License-Identifier: EPL-2.0

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/internal/collections/list.h"
#include "ah/loop.h"
#include "ah/sock.h"
#include "ah/tcp.h"

#include <sys/uio.h>

static void s_conn_on_connect(ah_i_loop_evt_t* evt, struct kevent* kev);
static void s_conn_on_read(ah_i_loop_evt_t* evt, struct kevent* kev);
static void s_conn_on_write(ah_i_loop_evt_t* evt, struct kevent* kev);

static void s_listener_on_accept(ah_i_loop_evt_t* evt, struct kevent* kev);

static void s_conn_read_stop(ah_tcp_conn_t* conn);
static ah_err_t s_conn_ref(ah_tcp_conn_t* conn);
static void s_conn_unref(ah_tcp_conn_t* conn);
static ah_err_t s_conn_write_prep(ah_tcp_conn_t* conn);
static void s_conn_write_stop(ah_tcp_conn_t* conn);

static ah_err_t s_listener_ref(ah_tcp_listener_t* ln);
static void s_listener_unref(ah_tcp_listener_t* ln);

ah_err_t ah_i_tcp_trans_default_conn_connect(void* ctx, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr)
{
    (void) ctx;

    if (conn == NULL || raddr == NULL) {
        return AH_EINVAL;
    }
    if (!ah_sockaddr_is_ip(raddr)) {
        return AH_EAFNOSUPPORT;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_OPEN) {
        return AH_ESTATE;
    }

    ah_i_loop_evt_t* evt;
    struct kevent* kev;

    ah_err_t err = ah_i_loop_evt_alloc_with_kev(conn->_loop, &evt, &kev);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_conn_on_connect;
    evt->_subject = conn;

    conn->_state = AH_I_TCP_CONN_STATE_CONNECTING;

    EV_SET(kev, conn->_fd, EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0u, 0u, evt);

    if (connect(conn->_fd, ah_i_sockaddr_const_into_bsd(raddr), ah_i_sockaddr_get_size(raddr)) != 0) {
        if (errno == EINPROGRESS) {
            return AH_ENONE;
        }
        kev->flags |= EV_ERROR;
        kev->data = errno;
    }

    s_conn_on_connect(evt, kev);

    return AH_ENONE;
}

static void s_conn_on_connect(ah_i_loop_evt_t* evt, struct kevent* kev)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(kev != NULL);

    ah_tcp_conn_t* conn = evt->_subject;
    ah_assert_if_debug(conn != NULL);

    ah_err_t err;

    if (ah_unlikely((kev->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) kev->data;
        conn->_state = AH_I_TCP_CONN_STATE_OPEN;
    }
    else if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        conn->_state = AH_I_TCP_CONN_STATE_OPEN;
        err = kev->fflags != 0 ? (ah_err_t) kev->fflags : AH_EEOF;
    }
    else {
        conn->_state = AH_I_TCP_CONN_STATE_CONNECTED;
        err = AH_ENONE;
    }

    conn->_obs.cbs->on_connect(conn->_obs.ctx, conn, err);
}

ah_err_t ah_i_tcp_trans_default_conn_read_start(void* ctx, ah_tcp_conn_t* conn)
{
    (void) ctx;

    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_CONNECTED || (conn->_shutdown_flags & AH_TCP_SHUTDOWN_RD) != 0) {
        return AH_ESTATE;
    }

    ah_err_t err;

    err = ah_tcp_in_alloc_for(&conn->_in);
    if (err != AH_ENONE) {
        return err;
    }

    ah_i_loop_evt_t* evt;
    struct kevent* kev;

    err = ah_i_loop_evt_alloc_with_kev(conn->_loop, &evt, &kev);
    if (err != AH_ENONE) {
        ah_tcp_in_free(conn->_in);
        return err;
    }

    evt->_cb = s_conn_on_read;
    evt->_subject = conn;

    EV_SET(kev, conn->_fd, EVFILT_READ, EV_ADD, 0u, 0, evt);
    conn->_read_evt = evt;

    conn->_state = AH_I_TCP_CONN_STATE_READING;

    return AH_ENONE;
}

static void s_conn_on_read(ah_i_loop_evt_t* evt, struct kevent* kev)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(kev != NULL);

    ah_tcp_conn_t* conn = evt->_subject;
    ah_assert_if_debug(conn != NULL);

    if (conn->_state != AH_I_TCP_CONN_STATE_READING) {
        return;
    }

    ah_err_t err;

    if (ah_unlikely((kev->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) kev->data;
        goto report_err;
    }

    size_t n_bytes_left = kev->data;

    while (n_bytes_left != 0u) {
        ah_buf_t dst = ah_rw_get_writable_as_buf(&conn->_in->rw);
        if (ah_buf_is_empty(&dst)) {
            err = AH_EOVERFLOW;
            goto report_err;
        }

        if (dst.size > n_bytes_left) {
            dst.size = n_bytes_left;
        }

        ssize_t nread = recv(conn->_fd, dst.base, dst.size, 0u);
        if (nread < 0) {
            err = errno;
            goto report_err;
        }
        if (nread == 0) {
            break;
        }

        if (ah_unlikely(dst.size < (size_t) nread)) {
            err = AH_EDOM;
            goto report_err;
        }

        conn->_in->rw.w = &conn->_in->rw.w[(size_t) nread];
        ah_assert_if_debug(conn->_in->rw.w <= conn->_in->rw.e);

        err = s_conn_ref(conn);
        if (err != AH_ENONE) {
            goto report_err;
        }

        conn->_obs.cbs->on_read(conn->_obs.ctx, conn, conn->_in, AH_ENONE);

        uint8_t state = conn->_state;

        s_conn_unref(conn);

        if (state != AH_I_TCP_CONN_STATE_READING) {
            return;
        }

        if (!ah_rw_is_readable(&conn->_in->rw)) {
            ah_tcp_in_reset(conn->_in);
        }

        n_bytes_left -= (size_t) nread;
    }

    if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        err = kev->fflags != 0u ? (ah_err_t) kev->fflags : AH_EEOF;
        conn->_shutdown_flags |= AH_TCP_SHUTDOWN_RD;
        goto report_err;
    }

    return;

report_err:
    conn->_obs.cbs->on_read(conn->_obs.ctx, conn, NULL, err);
}

static ah_err_t s_conn_ref(ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return AH_EINTERN;
    }
    return ah_add_uint32(conn->_ref_count, 1u, &conn->_ref_count);
}

static void s_conn_unref(ah_tcp_conn_t* conn)
{
    if (conn->_ref_count != 0u) {
        conn->_ref_count -= 1u;
        return;
    }

    ah_assert_if_debug(conn->_state == AH_I_TCP_CONN_STATE_CLOSING);

    ah_err_t err = ah_i_sock_close(conn->_fd);
    if (err == AH_EINTR) {
        if (ah_i_loop_try_set_pending_err(conn->_loop, AH_EINTR)) {
            err = AH_ENONE;
        }
    }

    conn->_shutdown_flags = AH_TCP_SHUTDOWN_RDWR;
    conn->_fd = 0;

    s_conn_read_stop(conn);
    s_conn_write_stop(conn);

    conn->_state = AH_I_TCP_CONN_STATE_CLOSED;

    conn->_obs.cbs->on_close(conn->_obs.ctx, conn, err);
}

static void s_conn_read_stop(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);
    ah_assert_if_debug(conn->_state < AH_I_TCP_CONN_STATE_READING);

    if (conn->_in != NULL) {
        ah_tcp_in_free(conn->_in);
        conn->_in = NULL;
    }

    if (conn->_read_evt != NULL) {
        ah_i_loop_evt_dealloc(conn->_loop, conn->_read_evt);
        conn->_read_evt = NULL;

        struct kevent* kev;
        if (ah_i_loop_alloc_kev(conn->_loop, &kev) == AH_ENONE) {
            EV_SET(kev, conn->_fd, EVFILT_READ, EV_DELETE, 0, 0u, NULL);
        }
    }
}

static void s_conn_write_stop(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);
    ah_assert_if_debug(conn->_state < AH_I_TCP_CONN_STATE_CONNECTED);

    for (;;) {
        ah_tcp_out_t* out = ah_i_list_pop(&conn->_out_queue, offsetof(ah_tcp_out_t, _list_entry));
        if (out == NULL) {
            break;
        }
        conn->_obs.cbs->on_write(conn->_obs.ctx, conn, out, AH_ECANCELED);
    }

    if (conn->_write_evt != NULL) {
        ah_i_loop_evt_dealloc(conn->_loop, conn->_write_evt);
        conn->_write_evt = NULL;

        struct kevent* kev;
        if (ah_i_loop_alloc_kev(conn->_loop, &kev) == AH_ENONE) {
            EV_SET(kev, conn->_fd, EVFILT_WRITE, EV_DELETE, 0, 0u, NULL);
        }
    }
}

ah_err_t ah_i_tcp_trans_default_conn_read_stop(void* ctx, ah_tcp_conn_t* conn)
{
    (void) ctx;

    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_READING) {
        return AH_ESTATE;
    }
    conn->_state = AH_I_TCP_CONN_STATE_CONNECTED;

    s_conn_read_stop(conn);

    return AH_ENONE;
}

ah_err_t ah_i_tcp_trans_default_conn_write(void* ctx, ah_tcp_conn_t* conn, ah_tcp_out_t* out)
{
    (void) ctx;

    if (conn == NULL || out == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state < AH_I_TCP_CONN_STATE_CONNECTED || (conn->_shutdown_flags & AH_TCP_SHUTDOWN_WR) != 0) {
        return AH_ESTATE;
    }

    out->_buf_offset = 0u;

    ah_i_list_push(&conn->_out_queue, out, offsetof(ah_tcp_out_t, _list_entry));

    return s_conn_write_prep(conn);
}

static ah_err_t s_conn_write_prep(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);

    if (conn->_write_evt != NULL) {
        return AH_ENONE; // Pending write already exists.
    }

    ah_i_loop_evt_t* evt;
    struct kevent* kev;

    ah_err_t err = ah_i_loop_evt_alloc_with_kev(conn->_loop, &evt, &kev);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_conn_on_write;
    evt->_subject = conn;

    EV_SET(kev, conn->_fd, EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0u, 0, evt);
    ah_assert_if_debug(conn->_write_evt == NULL);
    conn->_write_evt = evt;

    return AH_ENONE;
}

static void s_conn_on_write(ah_i_loop_evt_t* evt, struct kevent* kev)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(kev != NULL);

    ah_tcp_conn_t* conn = evt->_subject;
    ah_assert_if_debug(conn != NULL);
    ah_assert_if_debug(conn->_write_evt == evt);

    conn->_write_evt = NULL;

    if (conn->_state < AH_I_TCP_CONN_STATE_CONNECTED) {
        return;
    }

    ah_err_t err;

    ah_tcp_out_t* out = ah_i_list_peek(&conn->_out_queue, offsetof(ah_tcp_out_t, _list_entry));

    if (ah_unlikely(out == NULL)) {
        err = AH_EINTERN;
        goto report_err;
    }

    if (ah_unlikely((kev->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) kev->data;
        goto report_err;
    }

    if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        err = kev->fflags != 0 ? (ah_err_t) kev->fflags : AH_EEOF;
        conn->_shutdown_flags |= AH_TCP_SHUTDOWN_WR;
        goto report_err;
    }

    if (out->_buf_offset > out->buf.size) {
        err = AH_EINTERN;
        goto report_err;
    }

    void* buffer = &out->buf.base[out->_buf_offset];
    size_t length = out->buf.size - out->_buf_offset;

    ssize_t res = send(conn->_fd, buffer, length, 0);
    if (ah_unlikely(res < 0)) {
        err = errno;
        goto report_err;
    }

    if (((size_t) res) < out->buf.size) {
        out->_buf_offset = (size_t) res;
        goto prep_next;
    }

report_and_prep_next:
    ah_i_list_skip(&conn->_out_queue);

    err = s_conn_ref(conn);
    if (err != AH_ENONE) {
        goto report_err;
    }

    conn->_obs.cbs->on_write(conn->_obs.ctx, conn, out, AH_ENONE);

    uint8_t state = conn->_state;

    s_conn_unref(conn);

    if (state < AH_I_TCP_CONN_STATE_CONNECTED) {
        return;
    }
    if (ah_i_list_is_empty(&conn->_out_queue)) {
        return;
    }

prep_next:
    err = s_conn_write_prep(conn);
    if (err != AH_ENONE) {
        goto report_and_prep_next;
    }

    return;

report_err:
    conn->_obs.cbs->on_write(conn->_obs.ctx, conn, out, err);
}

ah_err_t ah_i_tcp_trans_default_conn_close(void* ctx, ah_tcp_conn_t* conn)
{
    (void) ctx;

    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state <= AH_I_TCP_CONN_STATE_CLOSING) {
        return AH_ESTATE;
    }
    if (conn->_fd == 0) {
        return AH_EINTERN;
    }
    conn->_state = AH_I_TCP_CONN_STATE_CLOSING;

    s_conn_unref(conn);

    return AH_ENONE;
}

ah_err_t ah_i_tcp_trans_default_listener_listen(void* ctx, ah_tcp_listener_t* ln, unsigned backlog)
{
    (void) ctx;

    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state != AH_I_TCP_LISTENER_STATE_OPEN) {
        return AH_ESTATE;
    }

    ah_err_t err;

    int backlog_int = (backlog == 0u ? 16 : backlog <= SOMAXCONN ? (int) backlog
                                                                 : SOMAXCONN);
    if (listen(ln->_fd, backlog_int) != 0) {
        err = errno;
        ln->_obs.cbs->on_listen(ln->_obs.ctx, ln, err);
        return AH_ENONE;
    }

    ah_i_loop_evt_t* evt;
    struct kevent* kev;

    err = ah_i_loop_evt_alloc_with_kev(ln->_loop, &evt, &kev);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_listener_on_accept;
    evt->_subject = ln;

    EV_SET(kev, ln->_fd, EVFILT_READ, EV_ADD, 0u, 0, evt);

    ln->_state = AH_I_TCP_LISTENER_STATE_LISTENING;
    ln->_listen_evt = evt;

    ln->_obs.cbs->on_listen(ln->_obs.ctx, ln, AH_ENONE);

    return AH_ENONE;
}

static void s_listener_on_accept(ah_i_loop_evt_t* evt, struct kevent* kev)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(kev != NULL);

    ah_tcp_listener_t* ln = evt->_subject;
    ah_assert_if_debug(ln != NULL);

    ah_err_t err, err0;

    if (ah_unlikely((kev->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) kev->data;
        goto handle_major_err;
    }

    for (intptr_t i = 0; i < kev->data; i += 1) {
        ah_tcp_accept_t* accept_ptr = NULL;

        ah_tcp_conn_t* conn = ah_i_slab_alloc(&ln->_conn_slab);
        if (conn == NULL) {
            err = AH_ENOMEM;
            goto handle_minor_err;
        }

        ah_sockaddr_t sockaddr;
        socklen_t socklen = sizeof(ah_sockaddr_t);

        const int fd = accept(ln->_fd, ah_i_sockaddr_into_bsd(&sockaddr), &socklen);
        if (fd == -1) {
            err = errno;
            goto handle_major_err;
        }

#if AH_I_SOCKADDR_HAS_SIZE
        ah_assert_if_debug(socklen <= UINT8_MAX);
        sockaddr.as_any.size = socklen;
#endif

        (void) memset(conn, 0, sizeof(*conn));

        err = ln->_trans.vtab->listener_prepare(ln->_trans.ctx, ln, &conn->_trans);
        if (err != AH_ENONE) {
            ah_i_slab_free(&ln->_conn_slab, conn);
            goto handle_minor_err;
        }

        if (!ah_tcp_trans_vtab_is_valid(conn->_trans.vtab)) {
            err = AH_ESTATE;
            goto handle_minor_err;
        }

        conn->_loop = ln->_loop;
        conn->_owning_slab = &ln->_conn_slab;
        conn-> _sockfamily = ln-> _sockfamily;
        conn->_state = AH_I_TCP_CONN_STATE_CONNECTED;
        conn->_fd = fd;

        ah_tcp_accept_t accept = {
            .ctx = conn->_trans.ctx,
            .conn = conn,
            .obs = &conn->_obs,
            .raddr = &sockaddr,
        };

        accept_ptr = &accept;

    handle_minor_err:
        err0 = s_listener_ref(ln);
        if (err0 != AH_ENONE) {
            err = err0;
            goto handle_major_err;
        }

        ln->_obs.cbs->on_accept(ln->_obs.ctx, ln, accept_ptr, err);

        uint8_t state = ln->_state;

        s_listener_unref(ln);

        if (state != AH_I_TCP_LISTENER_STATE_LISTENING) {
            return;
        }
    }

    if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        err = (ah_err_t) kev->fflags != 0 ? (ah_err_t) kev->fflags : AH_EEOF;
        goto handle_major_err;
    }

    return;

handle_major_err:
    ln->_obs.cbs->on_accept(ln->_obs.ctx, ln, NULL, err);
}

static ah_err_t s_listener_ref(ah_tcp_listener_t* ln)
{
    if (ln == NULL) {
        return AH_EINTERN;
    }
    return ah_add_uint32(ln->_ref_count, 1u, &ln->_ref_count);
}

static void s_listener_unref(ah_tcp_listener_t* ln)
{
    if (ln->_ref_count != 0u) {
        ln->_ref_count -= 1u;
        return;
    }

    ah_assert_if_debug(ln->_state == AH_I_TCP_LISTENER_STATE_CLOSING);

    ah_err_t err = ah_i_sock_close(ln->_fd);
    if (err == AH_EINTR) {
        if (ah_i_loop_try_set_pending_err(ln->_loop, AH_EINTR)) {
            err = AH_ENONE;
        }
    }

    ln->_state = AH_I_TCP_LISTENER_STATE_CLOSED;
    ln->_fd = 0;

    if (ln->_listen_evt != NULL) {
        ah_i_loop_evt_dealloc(ln->_loop, ln->_listen_evt);
        ln->_listen_evt = NULL;
    }

    ln->_obs.cbs->on_close(ln->_obs.ctx, ln, err);
}

ah_err_t ah_i_tcp_trans_default_listener_close(void* ctx, ah_tcp_listener_t* ln)
{
    (void) ctx;

    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state <= AH_I_TCP_LISTENER_STATE_CLOSING) {
        return AH_ESTATE;
    }
    if (ln->_fd == 0) {
        return AH_EINTERN;
    }
    ln->_state = AH_I_TCP_LISTENER_STATE_CLOSING;

    s_listener_unref(ln);

    return AH_ENONE;
}
