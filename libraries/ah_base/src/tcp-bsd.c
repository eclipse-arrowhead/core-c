// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

#include <stddef.h>

#if AH_HAS_POSIX
#    include <netinet/tcp.h>
#    include <sys/socket.h>
#elif AH_IS_WIN32
#    include <winsock2.h>
#endif

#if AH_IS_WIN32
#    define SHUT_RD   SD_RECEIVE
#    define SHUT_WR   SD_SEND
#    define SHUT_RDWR SD_BOTH
#endif

ah_err_t ah_tcp_conn_open(ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_CLOSED) {
        return AH_ESTATE;
    }

    ah_err_t err = ah_i_sock_open_bind(conn->_loop, laddr, SOCK_STREAM, &conn->_fd);

    if (err == AH_ENONE) {
        conn->_state = AH_I_TCP_CONN_STATE_OPEN;
    }

    conn->_vtab->on_open(conn, err);

    return AH_ENONE;
}

ah_err_t ah_tcp_conn_get_laddr(const ah_tcp_conn_t* conn, ah_sockaddr_t* laddr)
{
    if (conn == NULL || laddr == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state == AH_I_TCP_CONN_STATE_CLOSED) {
        return AH_ESTATE;
    }
    return ah_i_sock_getsockname(conn->_fd, laddr);
}

ah_err_t ah_tcp_conn_get_raddr(const ah_tcp_conn_t* conn, ah_sockaddr_t* raddr)
{
    if (conn == NULL || raddr == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state == AH_I_TCP_CONN_STATE_CLOSED) {
        return AH_ESTATE;
    }
    return ah_i_sock_getpeername(conn->_fd, raddr);
}

ah_err_t ah_tcp_conn_set_keepalive(ah_tcp_conn_t* conn, bool is_enabled)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state == AH_I_TCP_CONN_STATE_CLOSED) {
        return AH_ESTATE;
    }
    int value = is_enabled ? 1 : 0;
    if (setsockopt(conn->_fd, SOL_SOCKET, SO_KEEPALIVE, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }
    return AH_ENONE;
}

ah_err_t ah_tcp_conn_set_nodelay(ah_tcp_conn_t* conn, bool is_enabled)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state == AH_I_TCP_CONN_STATE_CLOSED) {
        return AH_ESTATE;
    }
    int value = is_enabled ? 1 : 0;
    if (setsockopt(conn->_fd, IPPROTO_TCP, TCP_NODELAY, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }
    return AH_ENONE;
}

ah_err_t ah_tcp_conn_set_reuseaddr(ah_tcp_conn_t* conn, bool is_enabled)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state == AH_I_TCP_CONN_STATE_CLOSED) {
        return AH_ESTATE;
    }
    int value = is_enabled ? 1 : 0;
    if (setsockopt(conn->_fd, SOL_SOCKET, SO_REUSEADDR, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }
    return AH_ENONE;
}

ah_err_t ah_tcp_conn_shutdown(ah_tcp_conn_t* conn, ah_tcp_shutdown_t flags)
{
    if (conn == NULL || (flags & ~AH_TCP_SHUTDOWN_RDWR) != 0u) {
        return AH_EINVAL;
    }
    if ((flags & AH_TCP_SHUTDOWN_RDWR) == 0u) {
        return AH_ENONE;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_CONNECTED) {
        return AH_ESTATE;
    }

#if SHUT_RD == (AH_TCP_SHUTDOWN_RD - 1) && SHUT_WR == (AH_TCP_SHUTDOWN_WR - 1)                                         \
    && SHUT_RDWR == (AH_TCP_SHUTDOWN_RDWR - 1)

    const int how = ((int) flags) - 1;

#else

    int how;
    switch (flags) {
    case AH_TCP_SHUTDOWN_RD:
        how = SHUT_RD;
        break;

    case AH_TCP_SHUTDOWN_WR:
        how = SHUT_WR;
        break;

    case AH_TCP_SHUTDOWN_RDWR:
        how = SHUT_RDWR;
        break;

    default:
        ah_unreachable();
    }

#endif

    ah_err_t err;

    if (shutdown(conn->_fd, how) != 0) {
#if AH_IS_WIN32
        err = WSAGetLastError();
#else
        err = errno;
#endif
    }
    else {
        err = AH_ENONE;
        conn->_shutdown_flags = flags;
    }

    return err;
}

ah_err_t ah_tcp_listener_open(ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr)
{
    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state != AH_I_TCP_LISTENER_STATE_CLOSED) {
        return AH_ESTATE;
    }

    ah_err_t err = ah_i_sock_open_bind(ln->_loop, laddr, SOCK_STREAM, &ln->_fd);

#if AH_USE_IOCP
    ln->_sockfamily = laddr != NULL ? laddr->as_ip.family : AH_SOCKFAMILY_DEFAULT;
#endif

    if (err == AH_ENONE) {
        ln->_state = AH_I_TCP_LISTENER_STATE_OPEN;
    }

    ln->_vtab->on_open(ln, err);

    return AH_ENONE;
}

ah_err_t ah_tcp_listener_get_laddr(const ah_tcp_listener_t* ln, ah_sockaddr_t* laddr)
{
    if (ln == NULL || laddr == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state == AH_I_TCP_LISTENER_STATE_CLOSED) {
        return AH_ESTATE;
    }
    return ah_i_sock_getsockname(ln->_fd, laddr);
}

ah_err_t ah_tcp_listener_set_keepalive(ah_tcp_listener_t* ln, bool is_enabled)
{
    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state == AH_I_TCP_LISTENER_STATE_CLOSED) {
        return AH_ESTATE;
    }
    int value = is_enabled ? 1 : 0;
    if (setsockopt(ln->_fd, SOL_SOCKET, SO_KEEPALIVE, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }
    return AH_ENONE;
}

ah_err_t ah_tcp_listener_set_nodelay(ah_tcp_listener_t* ln, bool is_enabled)
{
    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state == AH_I_TCP_LISTENER_STATE_CLOSED) {
        return AH_ESTATE;
    }
    int value = is_enabled ? 1 : 0;
    if (setsockopt(ln->_fd, IPPROTO_TCP, TCP_NODELAY, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }
    return AH_ENONE;
}

ah_err_t ah_tcp_listener_set_reuseaddr(ah_tcp_listener_t* ln, bool is_enabled)
{
    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state == AH_I_TCP_LISTENER_STATE_CLOSED) {
        return AH_ESTATE;
    }
    int value = is_enabled ? 1 : 0;
    if (setsockopt(ln->_fd, SOL_SOCKET, SO_REUSEADDR, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }
    return AH_ENONE;
}

void ah_i_tcp_listener_force_close_with_err(ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_assert_if_debug(ln != NULL);
    ah_assert_if_debug(ln->_state != AH_I_TCP_LISTENER_STATE_CLOSED);
    ah_assert_if_debug(ln->_fd != 0);

    ln->_state = AH_I_TCP_LISTENER_STATE_CLOSED;

    ah_err_t err0 = ah_i_sock_close(ln->_fd);
    if (err0 == AH_EINTR) {
        (void) ah_i_loop_try_set_pending_err(ln->_loop, AH_EINTR);
    }

#ifndef NDEBUG
    ln->_fd = 0;
#endif

    ln->_vtab->on_close(ln, err);
}
