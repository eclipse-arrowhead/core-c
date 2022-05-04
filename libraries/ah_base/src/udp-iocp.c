// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"
#include "winapi.h"

#include <ws2ipdef.h>

static void s_on_sock_recv(ah_i_loop_evt_t* evt);
static void s_on_sock_send(ah_i_loop_evt_t* evt);

static ah_err_t s_prep_sock_recv(ah_udp_sock_t* sock);
static ah_err_t s_prep_sock_send(ah_udp_sock_t* sock);

ah_extern ah_err_t ah_udp_omsg_init(ah_udp_omsg_t* omsg, ah_bufs_t bufs, ah_sockaddr_t* raddr)
{
    if (omsg == NULL || (bufs.items == NULL && bufs.length != 0u) || raddr == NULL) {
        return AH_EINVAL;
    }

    WSABUF* buffers;
    ULONG buffer_count;

    ah_err_t err = ah_i_bufs_into_wsabufs(&bufs, &buffers, &buffer_count);
    if (err != AH_ENONE) {
        return err;
    }

    *omsg = (ah_udp_omsg_t) {
        ._next = NULL,
        ._wsamsg.name = ah_i_sockaddr_into_bsd(raddr),
        ._wsamsg.namelen = ah_i_sockaddr_get_size(raddr),
        ._wsamsg.lpBuffers = buffers,
        ._wsamsg.dwBufferCount = buffer_count,
    };

    return AH_ENONE;
}

ah_extern ah_sockaddr_t* ah_udp_omsg_get_raddr(ah_udp_omsg_t* omsg)
{
    ah_assert_if_debug(omsg != NULL);
    return ah_i_sockaddr_from_bsd(omsg->_wsamsg.name);
}

ah_extern ah_bufs_t ah_udp_omsg_get_bufs(ah_udp_omsg_t* omsg)
{
    ah_assert_if_debug(omsg != NULL);

    ah_bufs_t bufs;
    ah_i_bufs_from_wsabufs(&bufs, omsg->_wsamsg.lpBuffers, omsg->_wsamsg.dwBufferCount);

    return bufs;
}

ah_extern ah_err_t ah_udp_sock_recv_start(ah_udp_sock_t* sock)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open || sock->_is_receiving) {
        return AH_ESTATE;
    }

    ah_err_t err;

    if (sock->_WSARecvMsg == NULL) {
        err = ah_i_winapi_get_wsa_fn(sock->_fd, &(GUID) WSAID_WSARECVMSG, (void**) &sock->_WSARecvMsg);
        if (err != AH_ENONE) {
            return err;
        }
    }

    err = s_prep_sock_recv(sock);
    if (err != AH_ENONE) {
        return err;
    }

    sock->_is_receiving = true;

    return AH_ENONE;
}

static ah_err_t s_prep_sock_recv(ah_udp_sock_t* sock)
{
    ah_assert_if_debug(sock != NULL);

    ah_i_loop_evt_t* evt;

    ah_err_t err = ah_i_loop_evt_alloc(sock->_loop, &evt);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_sock_recv;
    evt->_subject = sock;

    ah_bufs_t bufs = { .items = NULL, .length = 0u };
    sock->_vtab->on_recv_alloc(sock, &bufs);
    if (bufs.items == NULL || bufs.length == 0u) {
        return AH_ENOBUFS;
    }

    WSABUF* buffers;
    ULONG buffer_count;
    err = ah_i_bufs_into_wsabufs(&bufs, &buffers, &buffer_count);
    if (ah_unlikely(err != AH_ENONE)) {
        return err;
    }

    sock->_recv_wsamsg = (WSAMSG) {
        .name = ah_i_sockaddr_into_bsd(&sock->_recv_addr),
        .namelen = sizeof(ah_sockaddr_t),
        .lpBuffers = buffers,
        .dwBufferCount = buffer_count,
    };

    int res = sock->_WSARecvMsg(sock->_fd, &sock->_recv_wsamsg, NULL, &evt->_overlapped, NULL);
    if (res == SOCKET_ERROR) {
        err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            return err;
        }
    }

    return AH_ENONE;
}

static void s_on_sock_recv(ah_i_loop_evt_t* evt)
{
    ah_assert_if_debug(evt != NULL);

    ah_udp_sock_t* sock = evt->_subject;
    ah_assert_if_debug(sock != NULL);

    if (!sock->_is_open || !sock->_is_receiving) {
        return;
    }

    ah_err_t err;
    ah_sockaddr_t* raddr;

    DWORD n_bytes_transferred;
    DWORD flags;
    if (!WSAGetOverlappedResult(sock->_fd, &evt->_overlapped, &n_bytes_transferred, false, &flags)) {
        err = WSAGetLastError();
        raddr = NULL;
        goto report_err;
    }
    else {
        raddr = ah_i_sockaddr_from_bsd(sock->_recv_wsamsg.name);
    }

    ah_bufs_t bufs;
    ah_i_bufs_from_wsabufs(&bufs, sock->_recv_wsamsg.lpBuffers, sock->_recv_wsamsg.dwBufferCount);

    sock->_vtab->on_recv_data(sock, bufs, n_bytes_transferred, raddr);

    if (!sock->_is_open) {
        return;
    }

    err = s_prep_sock_recv(sock);
    if (err != AH_ENONE) {
        goto report_err;
    }

    return;

report_err:
    sock->_vtab->on_recv_err(sock, raddr, err);
}

ah_extern ah_err_t ah_udp_sock_recv_stop(ah_udp_sock_t* sock)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_receiving) {
        return AH_ESTATE;
    }
    sock->_is_receiving = false;

    return AH_ENONE;
}

ah_extern ah_err_t ah_udp_sock_send(ah_udp_sock_t* sock, ah_udp_omsg_t* omsg)
{
    if (sock == NULL || omsg == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open || sock->_vtab->on_send_done == NULL) {
        return AH_ESTATE;
    }

    if (sock->_send_queue_head != NULL) {
        sock->_send_queue_end->_next = omsg;
        sock->_send_queue_end = omsg;
        return AH_ENONE;
    }

    sock->_send_queue_head = omsg;
    sock->_send_queue_end = omsg;

    return s_prep_sock_send(sock);
}

static ah_err_t s_prep_sock_send(ah_udp_sock_t* sock)
{
    ah_i_loop_evt_t* evt;

    ah_err_t err = ah_i_loop_evt_alloc(sock->_loop, &evt);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_sock_send;
    evt->_subject = sock;

    ah_udp_omsg_t* omsg = sock->_send_queue_head;

    int res = WSASendMsg(sock->_fd, &omsg->_wsamsg, 0u, NULL, &evt->_overlapped, NULL);
    if (res == SOCKET_ERROR) {
        err = WSAGetLastError();
        if (err == WSA_IO_PENDING) {
            err = AH_ENONE;
        }
    }

    return err;
}

static void s_on_sock_send(ah_i_loop_evt_t* evt)
{
    ah_assert_if_debug(evt != NULL);

    ah_udp_sock_t* sock = evt->_subject;
    ah_assert_if_debug(sock != NULL);

    ah_err_t err;

    DWORD n_bytes_sent;
    DWORD flags;
    if (WSAGetOverlappedResult(sock->_fd, &evt->_overlapped, &n_bytes_sent, false, &flags)) {
        err = AH_ENONE;
    }
    else {
        err = WSAGetLastError();
        n_bytes_sent = 0u;
    }

    ah_udp_omsg_t* omsg = sock->_send_queue_head;
    sock->_send_queue_head = omsg->_next;

report_err_and_prep_next:
    sock->_vtab->on_send_done(sock, n_bytes_sent, ah_i_sockaddr_from_bsd(omsg->_wsamsg.name), err);

    if (sock->_send_queue_head == NULL) {
        return;
    }

    err = s_prep_sock_send(sock);
    if (err != AH_ENONE) {
        omsg = sock->_send_queue_head;
        sock->_send_queue_head = omsg->_next;
        goto report_err_and_prep_next;
    }
}

ah_extern ah_err_t ah_udp_sock_close(ah_udp_sock_t* sock)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }
#ifndef NDEBUG
    if (sock->_fd == 0) {
        return AH_ESTATE;
    }
#endif
    sock->_is_open = false;

    ah_err_t err = ah_i_sock_close(sock->_fd);
    if (err == AH_EINTR) {
        if (ah_i_loop_try_set_pending_err(sock->_loop, AH_EINTR)) {
            err = AH_ENONE;
        }
    }

#ifndef NDEBUG
    sock->_fd = 0;
#endif

    sock->_vtab->on_close(sock, err);

    return err;
}
