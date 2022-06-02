// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_MSG_QUEUE_H_
#define SRC_HTTP_MSG_QUEUE_H_

#include "ah/http.h"

#include <ah/assert.h>

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

    ah_http_msg_t* msg = queue->_head;
    queue->_head = msg->_next;

#ifndef NDEBUG

    msg->_next = NULL;

    if (queue->_head == NULL) {
        queue->_end = NULL;
    }

#endif

    return msg;
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
