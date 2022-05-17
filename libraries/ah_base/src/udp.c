// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

ah_extern ah_err_t ah_udp_sock_init(ah_udp_sock_t* sock, ah_loop_t* loop, const ah_udp_sock_vtab_t* vtab)
{
    if (sock == NULL || loop == NULL || vtab == NULL) {
        return AH_EINVAL;
    }

    ah_assert_if_debug(vtab->on_open != NULL);
    ah_assert_if_debug(vtab->on_close != NULL);
    ah_assert_if_debug(((vtab->on_recv_alloc == NULL) == (vtab->on_recv_data == NULL)) == (vtab->on_recv_err == NULL));

    if (ah_loop_is_term(loop)) {
        return AH_ESTATE;
    }

    *sock = (ah_udp_sock_t) {
        ._loop = loop,
        ._vtab = vtab,
    };

    return AH_ENONE;
}

ah_extern ah_loop_t* ah_udp_sock_get_loop(const ah_udp_sock_t* sock)
{
    ah_assert_if_debug(sock != NULL);

    return sock->_loop;
}

ah_extern void* ah_udp_sock_get_user_data(const ah_udp_sock_t* sock)
{
    ah_assert_if_debug(sock != NULL);

    return sock->_user_data;
}

ah_extern void ah_udp_sock_set_user_data(ah_udp_sock_t* sock, void* user_data)
{
    ah_assert_if_debug(sock != NULL);

    sock->_user_data = user_data;
}

ah_extern void ah_udp_trans_init(ah_udp_trans_t* trans, ah_loop_t* loop)
{
    ah_assert_if_debug(loop != NULL);

    static const ah_udp_trans_vtab_t s_vtab = {
        .sock_init = ah_udp_sock_init,
        .sock_open = ah_udp_sock_open,
        .sock_recv_start = ah_udp_sock_recv_start,
        .sock_recv_stop = ah_udp_sock_recv_stop,
        .sock_send = ah_udp_sock_send,
        .sock_close = ah_udp_sock_close,
    };

    *trans = (ah_udp_trans_t) {
        ._vtab = &s_vtab,
        ._loop = loop,
        ._trans_data = NULL,
    };
}


bool ah_i_udp_msg_queue_is_empty(struct ah_i_udp_msg_queue* queue)
{
    ah_assert_if_debug(queue != NULL);
    return queue->_head == NULL;
}

bool ah_i_udp_msg_queue_is_empty_then_add(struct ah_i_udp_msg_queue* queue, ah_udp_msg_t* msg)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(msg != NULL);

    msg->_next = NULL;

    if (queue->_head == NULL) {
        queue->_head = msg;
        queue->_end = msg;
        return true;
    }

    queue->_end->_next = msg;
    queue->_end = msg;

    return false;
}

ah_udp_msg_t* ah_i_udp_msg_queue_get_head(struct ah_i_udp_msg_queue* queue)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(queue->_head != NULL);

    return queue->_head;
}

void ah_i_udp_msg_queue_remove_unsafe(struct ah_i_udp_msg_queue* queue)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(queue->_head != NULL);
    ah_assert_if_debug(queue->_end != NULL);

    ah_udp_msg_t* msg = queue->_head;
    queue->_head = msg->_next;

#ifndef NDEBUG

    msg->_next = NULL;

    if (queue->_head == NULL) {
        queue->_end = NULL;
    }

#endif
}
