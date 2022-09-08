// SPDX-License-Identifier: EPL-2.0

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"
#include "ah/sock.h"
#include "ah/tcp.h"

#include <stddef.h>

#if AH_HAS_POSIX
# include <netinet/tcp.h>
# include <sys/socket.h>
#elif AH_IS_WIN32
# include <winsock2.h>
#endif

#if AH_IS_WIN32
# define SHUT_RD   SD_RECEIVE
# define SHUT_WR   SD_SEND
# define SHUT_RDWR SD_BOTH
#endif

ah_err_t ah_i_tcp_trans_default_conn_open(void* ctx, ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr)
{
    (void) ctx;

    if (conn == NULL || laddr == NULL) {
        return AH_EINVAL;
    }
    if (!ah_sockaddr_is_ip(laddr)) {
        return AH_EAFNOSUPPORT;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_INITIALIZED) {
        return AH_ESTATE;
    }

    ah_err_t err = ah_i_sock_open_bind(conn->_loop, laddr, SOCK_STREAM, &conn->_fd);

    if (err == AH_ENONE) {
        conn-> _sockfamily = laddr->as_any.family;
        conn->_state = AH_I_TCP_CONN_STATE_OPEN;
    }

    conn->_obs.cbs->on_open(conn->_obs.ctx, conn, err);

    return AH_ENONE;
}

ah_extern ah_err_t ah_i_tcp_trans_default_conn_shutdown(void* ctx, ah_tcp_conn_t* conn, uint8_t flags)
{
    (void) ctx;

    if (conn == NULL || (flags & ~AH_TCP_SHUTDOWN_RDWR) != 0u) {
        return AH_EINVAL;
    }
    if (conn->_state < AH_I_TCP_CONN_STATE_CONNECTED) {
        return AH_ESTATE;
    }

    if (((flags & ~conn->_shutdown_flags) & AH_TCP_SHUTDOWN_RDWR) == 0u) {
        return AH_ENONE;
    }

#if SHUT_RD == (AH_TCP_SHUTDOWN_RD - 1) && SHUT_WR == (AH_TCP_SHUTDOWN_WR - 1) && SHUT_RDWR == (AH_TCP_SHUTDOWN_RDWR - 1)

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

    ah_err_t err = ah_i_sock_shutdown(conn->_fd, how);
    if (err != AH_ENONE) {
        return err;
    }

    conn->_shutdown_flags = flags;

    if ((flags & AH_TCP_SHUTDOWN_RD) != 0u && conn->_state == AH_I_TCP_CONN_STATE_READING) {
        conn->_state = AH_I_TCP_CONN_STATE_CONNECTED;
    }

    return AH_ENONE;
}

ah_extern ah_err_t ah_i_tcp_trans_default_conn_get_laddr(void* ctx, const ah_tcp_conn_t* conn, ah_sockaddr_t* laddr)
{
    (void) ctx;

    if (conn == NULL || laddr == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state <= AH_I_TCP_CONN_STATE_CLOSED) {
        return AH_ESTATE;
    }
    return ah_i_sock_getsockname(conn->_fd, laddr);
}

ah_extern ah_err_t ah_i_tcp_trans_default_conn_get_raddr(void* ctx, const ah_tcp_conn_t* conn, ah_sockaddr_t* raddr)
{
    (void) ctx;

    if (conn == NULL || raddr == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state < AH_I_TCP_CONN_STATE_CONNECTED) {
        return AH_ESTATE;
    }
    return ah_i_sock_getpeername(conn->_fd, raddr);
}

ah_extern ah_err_t ah_i_tcp_trans_default_conn_set_keepalive(void* ctx, ah_tcp_conn_t* conn, bool is_enabled)
{
    (void) ctx;

    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state <= AH_I_TCP_CONN_STATE_CLOSING) {
        return AH_ESTATE;
    }
    int value = is_enabled ? 1 : 0;
    return ah_i_sock_setsockopt(conn->_fd, SOL_SOCKET, SO_KEEPALIVE, &value, sizeof(value));
}

ah_extern ah_err_t ah_i_tcp_trans_default_conn_set_nodelay(void* ctx, ah_tcp_conn_t* conn, bool is_enabled)
{
    (void) ctx;

    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state <= AH_I_TCP_CONN_STATE_CLOSING) {
        return AH_ESTATE;
    }
    int value = is_enabled ? 1 : 0;
    return ah_i_sock_setsockopt(conn->_fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));
}

ah_extern ah_err_t ah_i_tcp_trans_default_conn_set_reuseaddr(void* ctx, ah_tcp_conn_t* conn, bool is_enabled)
{
    (void) ctx;

    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state <= AH_I_TCP_CONN_STATE_CLOSING) {
        return AH_ESTATE;
    }
    int value = is_enabled ? 1 : 0;
    return ah_i_sock_setsockopt(conn->_fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));
}

ah_err_t ah_i_tcp_trans_default_listener_open(void* ctx, ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr)
{
    (void) ctx;

    if (ln == NULL || laddr == NULL) {
        return AH_EINVAL;
    }
    if (!ah_sockaddr_is_ip(laddr)) {
        return AH_EAFNOSUPPORT;
    }
    if (ln->_state != AH_I_TCP_LISTENER_STATE_INITIALIZED) {
        return AH_ESTATE;
    }

    ah_err_t err = ah_i_sock_open_bind(ln->_loop, laddr, SOCK_STREAM, &ln->_fd);

    if (err == AH_ENONE) {
        ln-> _sockfamily = laddr->as_any.family;
        ln->_state = AH_I_TCP_LISTENER_STATE_OPEN;
    }

    ln->_obs.cbs->on_open(ln->_obs.ctx, ln, err);

    return AH_ENONE;
}

ah_extern ah_err_t ah_i_tcp_trans_default_listener_get_laddr(void* ctx, const ah_tcp_listener_t* ln, ah_sockaddr_t* laddr)
{
    (void) ctx;

    if (ln == NULL || laddr == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state <= AH_I_TCP_LISTENER_STATE_CLOSED) {
        return AH_ESTATE;
    }
    return ah_i_sock_getsockname(ln->_fd, laddr);
}

ah_extern ah_err_t ah_i_tcp_trans_default_listener_set_keepalive(void* ctx, ah_tcp_listener_t* ln, bool is_enabled)
{
    (void) ctx;

    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state <= AH_I_TCP_LISTENER_STATE_CLOSING) {
        return AH_ESTATE;
    }
    int value = is_enabled ? 1 : 0;
    return ah_i_sock_setsockopt(ln->_fd, SOL_SOCKET, SO_KEEPALIVE, &value, sizeof(value));
}

ah_extern ah_err_t ah_i_tcp_trans_default_listener_set_nodelay(void* ctx, ah_tcp_listener_t* ln, bool is_enabled)
{
    (void) ctx;

    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state <= AH_I_TCP_LISTENER_STATE_CLOSING) {
        return AH_ESTATE;
    }
    int value = is_enabled ? 1 : 0;
    return ah_i_sock_setsockopt(ln->_fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));
}

ah_extern ah_err_t ah_i_tcp_trans_default_listener_set_reuseaddr(void* ctx, ah_tcp_listener_t* ln, bool is_enabled)
{
    (void) ctx;

    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state <= AH_I_TCP_LISTENER_STATE_CLOSING) {
        return AH_ESTATE;
    }
    int value = is_enabled ? 1 : 0;
    return ah_i_sock_setsockopt(ln->_fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));
}
