// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_MSG_QUEUE_H_
#define SRC_HTTP_MSG_QUEUE_H_

#include "ah/http.h"

#include <ah/assert.h>

static inline bool ah_i_http_out_queue_is_empty(struct ah_i_http_out_queue* queue)
{
    ah_assert_if_debug(queue != NULL);

    return queue->_head == NULL;
}

static inline bool ah_i_http_out_queue_is_empty_then_add(struct ah_i_http_out_queue* queue, ah_http_out_t* out)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(out != NULL);

    out->_next = NULL;

    if (queue->_head == NULL) {
        queue->_head = out;
        queue->_end = out;
        return true;
    }

    queue->_end->_next = out;
    queue->_end = out;

    return false;
}

static inline ah_http_out_t* ah_i_http_out_queue_peek(struct ah_i_http_out_queue* queue)
{
    ah_assert_if_debug(queue != NULL);

    return queue->_head;
}

static inline ah_http_out_t* ah_i_http_out_queue_peek_unsafe(struct ah_i_http_out_queue* queue)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(queue->_head != NULL);

    return queue->_head;
}

static inline ah_http_out_t* ah_i_http_out_queue_remove_unsafe(struct ah_i_http_out_queue* queue)
{
    ah_assert_if_debug(queue != NULL);

    ah_http_out_t* out = queue->_head;
    queue->_head = out->_next;

#ifndef NDEBUG

    out->_next = NULL;

    if (queue->_head == NULL) {
        queue->_end = NULL;
    }

#endif

    return out;
}

static inline ah_http_out_t* ah_i_http_out_queue_remove(struct ah_i_http_out_queue* queue)
{
    ah_assert_if_debug(queue != NULL);

    if (queue->_head == NULL) {
        return NULL;
    }

    return ah_i_http_out_queue_remove_unsafe(queue);
}

#endif
