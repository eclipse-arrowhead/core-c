// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "http-utils.h"

#include <ah/assert.h>

ah_http_lclient_t* ah_i_http_upcast_to_lclient(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);

    // This is only safe if `conn` is a member of an ah_http_client_t value.
    const size_t conn_member_offset = offsetof(ah_http_lclient_t, _conn);
    ah_assert_if_debug(conn_member_offset <= PTRDIFF_MAX);
    ah_http_lclient_t* cln = (ah_http_lclient_t*) &((uint8_t*) conn)[-((ptrdiff_t) conn_member_offset)];

    ah_assert_if_debug(cln->_vtab != NULL);
    ah_assert_if_debug(cln->_trans_vtab != NULL);

    return cln;
}

ah_http_rclient_t* ah_i_http_upcast_to_rclient(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);

    // This is only safe if `conn` is a member of an ah_http_client_t value.
    const size_t conn_member_offset = offsetof(ah_http_rclient_t, _conn);
    ah_assert_if_debug(conn_member_offset <= PTRDIFF_MAX);
    ah_http_rclient_t* cln = (ah_http_rclient_t*) &((uint8_t*) conn)[-((ptrdiff_t) conn_member_offset)];

    ah_assert_if_debug(cln->_vtab != NULL);
    ah_assert_if_debug(cln->_trans_vtab != NULL);

    return cln;
}

ah_http_server_t* ah_i_http_upcast_to_server(ah_tcp_listener_t* ln)
{
    ah_assert_if_debug(ln != NULL);

    // This is only safe if `ln` is a member of an ah_http_server_t value.
    const size_t ln_member_offset = offsetof(ah_http_server_t, _ln);
    ah_assert_if_debug(ln_member_offset <= PTRDIFF_MAX);
    ah_http_server_t* srv = (ah_http_server_t*) &((uint8_t*) ln)[-((ptrdiff_t) ln_member_offset)];

    ah_assert_if_debug(srv->_vtab != NULL);
    ah_assert_if_debug(srv->_trans_vtab != NULL);

    return srv;
}

void ah_i_http_req_queue_add(struct ah_i_http_req_queue* queue, ah_http_req_t* req)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(req != NULL);

    req->_next = NULL;

    if (queue->_head == NULL) {
        queue->_head = req;
        queue->_end = req;
    }
    else {
        queue->_end->_next = req;
        queue->_end = req;
    }
}

void ah_i_http_req_queue_discard_unsafe(struct ah_i_http_req_queue* queue)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(queue->_head != NULL);
    ah_assert_if_debug(queue->_end != NULL);

    ah_http_req_t* req = queue->_head;
    queue->_head = req->_next;

#ifndef NDEBUG

    req->_next = NULL;

    if (queue->_head == NULL) {
        queue->_end = NULL;
    }

#endif
}

bool ah_i_http_req_queue_is_empty(struct ah_i_http_req_queue* queue)
{
    ah_assert_if_debug(queue != NULL);
    return queue->_head == NULL;
}

bool ah_i_http_req_queue_is_empty_then_add(struct ah_i_http_req_queue* queue, ah_http_req_t* req)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(req != NULL);

    req->_next = NULL;

    if (queue->_head == NULL) {
        queue->_head = req;
        queue->_end = req;
        return true;
    }

    queue->_end->_next = req;
    queue->_end = req;

    return false;
}

ah_http_req_t* ah_i_http_req_queue_peek(struct ah_i_http_req_queue* queue)
{
    ah_assert_if_debug(queue != NULL);

    return queue->_head;
}

ah_http_req_t* ah_i_http_req_queue_peek_unsafe(struct ah_i_http_req_queue* queue)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(queue->_head != NULL);

    return queue->_head;
}

ah_http_req_t* ah_i_http_req_queue_remove(struct ah_i_http_req_queue* queue)
{
    ah_assert_if_debug(queue != NULL);

    if (queue->_head == NULL) {
        return NULL;
    }

    return ah_i_http_req_queue_remove_unsafe(queue);
}

ah_http_req_t* ah_i_http_req_queue_remove_unsafe(struct ah_i_http_req_queue* queue)
{
    ah_assert_if_debug(queue != NULL);

    ah_http_req_t* req = queue->_head;
    ah_i_http_req_queue_discard_unsafe(queue);
    return req;
}


void ah_i_http_res_queue_add(struct ah_i_http_res_queue* queue, ah_http_res_t* res)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(res != NULL);

    res->_next = NULL;

    if (queue->_head == NULL) {
        queue->_head = res;
        queue->_end = res;
    }
    else {
        queue->_end->_next = res;
        queue->_end = res;
    }
}

void ah_i_http_res_queue_discard_unsafe(struct ah_i_http_res_queue* queue)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(queue->_head != NULL);
    ah_assert_if_debug(queue->_end != NULL);

    ah_http_res_t* res = queue->_head;
    queue->_head = res->_next;

#ifndef NDEBUG

    res->_next = NULL;

    if (queue->_head == NULL) {
        queue->_end = NULL;
    }

#endif
}

bool ah_i_http_res_queue_is_empty(struct ah_i_http_res_queue* queue)
{
    ah_assert_if_debug(queue != NULL);
    return queue->_head == NULL;
}

bool ah_i_http_res_queue_is_empty_then_add(struct ah_i_http_res_queue* queue, ah_http_res_t* res)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(res != NULL);

    res->_next = NULL;

    if (queue->_head == NULL) {
        queue->_head = res;
        queue->_end = res;
        return true;
    }

    queue->_end->_next = res;
    queue->_end = res;

    return false;
}

ah_http_res_t* ah_i_http_res_queue_peek(struct ah_i_http_res_queue* queue)
{
    ah_assert_if_debug(queue != NULL);

    return queue->_head;
}

ah_http_res_t* ah_i_http_res_queue_peek_unsafe(struct ah_i_http_res_queue* queue)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(queue->_head != NULL);

    return queue->_head;
}

ah_http_res_t* ah_i_http_res_queue_remove(struct ah_i_http_res_queue* queue)
{
    ah_assert_if_debug(queue != NULL);

    if (queue->_head == NULL) {
        return NULL;
    }

    return ah_i_http_res_queue_remove_unsafe(queue);
}

ah_http_res_t* ah_i_http_res_queue_remove_unsafe(struct ah_i_http_res_queue* queue)
{
    ah_assert_if_debug(queue != NULL);

    ah_http_res_t* res = queue->_head;
    ah_i_http_res_queue_discard_unsafe(queue);
    return res;
}
