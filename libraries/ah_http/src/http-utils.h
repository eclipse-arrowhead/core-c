// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_UTILS_H_
#define SRC_HTTP_UTILS_H_

#include "ah/http.h"

#include <ah/assert.h>

static inline ah_http_client_t* ah_i_http_conn_to_client(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);

    // This is only safe if `conn` is a member of an ah_http_client_t value.
    const size_t conn_member_offset = offsetof(ah_http_client_t, _conn);
    ah_assert_if_debug(conn_member_offset <= PTRDIFF_MAX);
    ah_http_client_t* cln = (ah_http_client_t*) &((uint8_t*) conn)[-((ptrdiff_t) conn_member_offset)];

    return cln;
}

static inline ah_http_server_t* ah_i_http_conn_to_server(ah_tcp_listener_t* ln)
{
    ah_assert_if_debug(ln != NULL);

    // This is only safe if `ln` is a member of an ah_http_server_t value.
    const size_t ln_member_offset = offsetof(ah_http_server_t, _ln);
    ah_assert_if_debug(ln_member_offset <= PTRDIFF_MAX);
    ah_http_server_t* srv = (ah_http_server_t*) &((uint8_t*) ln)[-((ptrdiff_t) ln_member_offset)];

    return srv;
}

static inline void ah_i_http_msg_queue_add(struct ah_i_http_msg_queue* queue, ah_http_msg_t* msg)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(msg != NULL);

    msg->_next = NULL;

    if (queue->_head == NULL) {
        queue->_head = msg;
        queue->_end = msg;
    }
    else {
        queue->_end->_next = msg;
        queue->_end = msg;
    }
}

static inline void ah_i_http_msg_queue_discard_unsafe(struct ah_i_http_msg_queue* queue)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(queue->_head != NULL);
    ah_assert_if_debug(queue->_end != NULL);

    ah_http_msg_t* msg = queue->_head;
    queue->_head = msg->_next;

#ifndef NDEBUG

    msg->_next = NULL;

    if (queue->_head == NULL) {
        queue->_end = NULL;
    }

#endif
}

static inline bool ah_i_http_msg_queue_is_empty(struct ah_i_http_msg_queue* queue)
{
    ah_assert_if_debug(queue != NULL);
    return queue->_head == NULL;
}

static inline bool ah_i_http_msg_queue_is_empty_then_add(struct ah_i_http_msg_queue* queue, ah_http_msg_t* msg)
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

static inline ah_http_msg_t* ah_i_http_msg_queue_peek(struct ah_i_http_msg_queue* queue)
{
    ah_assert_if_debug(queue != NULL);

    return queue->_head;
}

static inline ah_http_msg_t* ah_i_http_msg_queue_peek_unsafe(struct ah_i_http_msg_queue* queue)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(queue->_head != NULL);

    return queue->_head;
}

static inline ah_http_msg_t* ah_i_http_msg_queue_remove_unsafe(struct ah_i_http_msg_queue* queue)
{
    ah_assert_if_debug(queue != NULL);

    ah_http_msg_t* req = queue->_head;
    ah_i_http_msg_queue_discard_unsafe(queue);
    return req;
}

static inline ah_http_msg_t* ah_i_http_msg_queue_remove(struct ah_i_http_msg_queue* queue)
{
    ah_assert_if_debug(queue != NULL);

    if (queue->_head == NULL) {
        return NULL;
    }

    return ah_i_http_msg_queue_remove_unsafe(queue);
}

#endif
