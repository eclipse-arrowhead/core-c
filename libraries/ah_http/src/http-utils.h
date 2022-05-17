// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_UTILS_H_
#define SRC_HTTP_UTILS_H_

#include "ah/http.h"

ah_http_lclient_t* ah_i_http_upcast_to_lclient(ah_tcp_conn_t* conn);
ah_http_rclient_t* ah_i_http_upcast_to_rclient(ah_tcp_conn_t* conn);
ah_http_server_t* ah_i_http_upcast_to_server(ah_tcp_listener_t* ln);

void ah_i_http_req_queue_add(struct ah_i_http_req_queue* queue, ah_http_req_t* req);
void ah_i_http_req_queue_discard_unsafe(struct ah_i_http_req_queue* queue);
bool ah_i_http_req_queue_is_empty(struct ah_i_http_req_queue* queue);
bool ah_i_http_req_queue_is_empty_then_add(struct ah_i_http_req_queue* queue, ah_http_req_t* req);
ah_http_req_t* ah_i_http_req_queue_peek(struct ah_i_http_req_queue* queue);
ah_http_req_t* ah_i_http_req_queue_peek_unsafe(struct ah_i_http_req_queue* queue);
ah_http_req_t* ah_i_http_req_queue_remove(struct ah_i_http_req_queue* queue);
ah_http_req_t* ah_i_http_req_queue_remove_unsafe(struct ah_i_http_req_queue* queue);

void ah_i_http_res_queue_add(struct ah_i_http_res_queue* queue, ah_http_res_t* res);
void ah_i_http_res_queue_discard_unsafe(struct ah_i_http_res_queue* queue);
bool ah_i_http_res_queue_is_empty(struct ah_i_http_res_queue* queue);
bool ah_i_http_res_queue_is_empty_then_add(struct ah_i_http_res_queue* queue, ah_http_res_t* res);
ah_http_res_t* ah_i_http_res_queue_peek(struct ah_i_http_res_queue* queue);
ah_http_res_t* ah_i_http_res_queue_peek_unsafe(struct ah_i_http_res_queue* queue);
ah_http_res_t* ah_i_http_res_queue_remove(struct ah_i_http_res_queue* queue);
ah_http_res_t* ah_i_http_res_queue_remove_unsafe(struct ah_i_http_res_queue* queue);

#endif
