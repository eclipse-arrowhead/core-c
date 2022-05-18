// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_HTTP_H_
#define AH_HTTP_H_

#include "internal/_http.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

// Directly supported HTTP versions.
#define AH_HTTP_VER_1_0 ((ah_http_ver_t) { 1u, 0u })
#define AH_HTTP_VER_1_1 ((ah_http_ver_t) { 1u, 1u })

// HTTP response status codes. See https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml.
#define AH_HTTP_CODE_CONTINUE                        100u
#define AH_HTTP_CODE_SWITCHING_PROTOCOLS             101u
#define AH_HTTP_CODE_PROCESSING                      102u
#define AH_HTTP_CODE_EARLY_HINTS                     103u
#define AH_HTTP_CODE_OK                              200u
#define AH_HTTP_CODE_CREATED                         201u
#define AH_HTTP_CODE_ACCEPTED                        202u
#define AH_HTTP_CODE_NON_AUTHORITATIVE_INFORMATION   203u
#define AH_HTTP_CODE_NO_CONTENT                      204u
#define AH_HTTP_CODE_RESET_CONTENT                   205u
#define AH_HTTP_CODE_PARTIAL_CONTENT                 206u
#define AH_HTTP_CODE_MULTI_STATUS                    207u
#define AH_HTTP_CODE_ALREADY_REPORTED                208u
#define AH_HTTP_CODE_IM_USED                         226u
#define AH_HTTP_CODE_MULTIPLE_CHOICES                300u
#define AH_HTTP_CODE_MOVED_PERMANENTLY               301u
#define AH_HTTP_CODE_FOUND                           302u
#define AH_HTTP_CODE_SEE_OTHER                       303u
#define AH_HTTP_CODE_NOT_MODIFIED                    304u
#define AH_HTTP_CODE_USE_PROXY                       305u
#define AH_HTTP_CODE_TEMPORARY_REDIRECT              307u
#define AH_HTTP_CODE_PERMANENT_REDIRECT              308u
#define AH_HTTP_CODE_BAD_REQUEST                     400u
#define AH_HTTP_CODE_UNAUTHORIZED                    401u
#define AH_HTTP_CODE_PAYMENT_REQUIRED                402u
#define AH_HTTP_CODE_FORBIDDEN                       403u
#define AH_HTTP_CODE_NOT_FOUND                       404u
#define AH_HTTP_CODE_METHOD_NOT_ALLOWED              405u
#define AH_HTTP_CODE_NOT_ACCEPTABLE                  406u
#define AH_HTTP_CODE_PROXY_AUTHENTICATION_REQUIRED   407u
#define AH_HTTP_CODE_REQUEST_TIMEOUT                 408u
#define AH_HTTP_CODE_CONFLICT                        409u
#define AH_HTTP_CODE_GONE                            410u
#define AH_HTTP_CODE_LENGTH_REQUIRED                 411u
#define AH_HTTP_CODE_PRECONDITION_FAILED             412u
#define AH_HTTP_CODE_CONTENT_TOO_LARGE               413u
#define AH_HTTP_CODE_URI_TOO_LONG                    414u
#define AH_HTTP_CODE_UNSUPPORTED_MEDIA_TYPE          415u
#define AH_HTTP_CODE_RANGE_NOT_SATISFIABLE           416u
#define AH_HTTP_CODE_EXPECTATION_FAILED              417u
#define AH_HTTP_CODE_MISDIRECTED_REQUEST             421u
#define AH_HTTP_CODE_UNPROCESSABLE_CONTENT           422u
#define AH_HTTP_CODE_LOCKED                          423u
#define AH_HTTP_CODE_FAILED_DEPENDENCY               424u
#define AH_HTTP_CODE_TOO_EARLY                       425u
#define AH_HTTP_CODE_UPGRADE_REQUIRED                426u
#define AH_HTTP_CODE_PRECONDITION_REQUIRED           428u
#define AH_HTTP_CODE_TOO_MANY_REQUESTS               429u
#define AH_HTTP_CODE_REQUEST_HEADER_FIELDS_TOO_LARGE 431u
#define AH_HTTP_CODE_UNAVAILABLE_FOR_LEGAL_REASONS   451u
#define AH_HTTP_CODE_INTERNAL_SERVER_ERROR           500u
#define AH_HTTP_CODE_NOT_IMPLEMENTED                 501u
#define AH_HTTP_CODE_BAD_GATEWAY                     502u
#define AH_HTTP_CODE_SERVICE_UNAVAILABLE             503u
#define AH_HTTP_CODE_GATEWAY_TIMEOUT                 504u
#define AH_HTTP_CODE_HTTP_VERSION_NOT_SUPPORTED      505u
#define AH_HTTP_CODE_VARIANT_ALSO_NEGOTIATES         506u
#define AH_HTTP_CODE_INSUFFICIENT_STORAGE            507u
#define AH_HTTP_CODE_LOOP_DETECTED                   508u
#define AH_HTTP_CODE_NETWORK_AUTHENTICATION_REQUIRED 511u

typedef struct ah_http_chunk ah_http_chunk_t;
typedef struct ah_http_chunk_line ah_http_chunk_line_t;
typedef struct ah_http_header ah_http_header_t;
typedef struct ah_http_lclient ah_http_lclient_t;
typedef struct ah_http_lclient_vtab ah_http_lclient_vtab_t;
typedef struct ah_http_rclient ah_http_rclient_t;
typedef struct ah_http_rclient_vtab ah_http_rclient_vtab_t;
typedef struct ah_http_req ah_http_req_t;
typedef struct ah_http_req_line ah_http_req_line_t;
typedef struct ah_http_res ah_http_res_t;
typedef struct ah_http_server ah_http_server_t;
typedef struct ah_http_server_vtab ah_http_server_vtab_t;
typedef struct ah_http_stat_line ah_http_stat_line_t;
typedef struct ah_http_trailer ah_http_trailer_t;
typedef struct ah_http_ver ah_http_ver_t;

typedef union ah_http_body ah_http_body_t;

// A local HTTP client, potentially connected to a remote HTTP server.
struct ah_http_lclient {
    AH_I_HTTP_LCLIENT_FIELDS
};

// Virtual function table of a local HTTP client.
struct ah_http_lclient_vtab {
    void (*on_open)(ah_http_lclient_t* cln, ah_err_t err);
    void (*on_connect)(ah_http_lclient_t* cln, ah_err_t err);
    void (*on_close)(ah_http_lclient_t* cln, ah_err_t err);

    // If `reuse` is true, any block of memory previously provided via `buf` may
    // be used again without disrupting `cln`.
    void (*on_msg_alloc)(ah_http_lclient_t* cln, ah_buf_t* buf, bool reuse);

    void (*on_req_sent)(ah_http_lclient_t* cln, ah_http_req_t* req, ah_err_t err);

    void (*on_res_line)(ah_http_lclient_t* cln, ah_http_stat_line_t stat_line);
    void (*on_res_header)(ah_http_lclient_t* cln, ah_http_header_t header);
    void (*on_res_headers)(ah_http_lclient_t* cln);                                     // Optional.
    void (*on_res_chunk_line)(ah_http_lclient_t* cln, ah_http_chunk_line_t chunk_line); // Optional.
    void (*on_res_data)(ah_http_lclient_t* cln, const ah_buf_t* rbuf);
    void (*on_res_end)(ah_http_lclient_t* cln, ah_err_t err);
};

// A remote HTTP client, connected via a local HTTP server.
struct ah_http_rclient {
    AH_I_HTTP_RCLIENT_FIELDS
};

// Virtual function table of remote HTTP client.
struct ah_http_rclient_vtab {
    void (*on_close)(ah_http_rclient_t* cln, ah_err_t err);

    // If `reuse` is true, any block of memory previously provided via `buf` may
    // be used again without disrupting `srv`.
    void (*on_msg_alloc)(ah_http_rclient_t* cln, ah_buf_t* buf, bool reuse);

    void (*on_req_line)(ah_http_rclient_t* cln, ah_http_req_line_t req_line);
    void (*on_req_header)(ah_http_rclient_t* cln, ah_http_header_t header);
    void (*on_req_headers)(ah_http_rclient_t* cln);                                     // Optional.
    void (*on_req_chunk_line)(ah_http_rclient_t* cln, ah_http_chunk_line_t chunk_line); // Optional.
    void (*on_req_data)(ah_http_rclient_t* cln, const ah_buf_t* rbuf);
    void (*on_req_end)(ah_http_rclient_t* cln, ah_err_t err, uint16_t stat_code);

    void (*on_res_sent)(ah_http_rclient_t* cln, ah_http_res_t* res, ah_err_t err);
};

// A local HTTP server.
struct ah_http_server {
    AH_I_HTTP_SERVER_FIELDS
};

// Virtual function table of local HTTP server.
struct ah_http_server_vtab {
    void (*on_open)(ah_http_server_t* srv, ah_err_t err);
    void (*on_listen)(ah_http_server_t* srv, ah_err_t err);
    void (*on_close)(ah_http_server_t* srv, ah_err_t err);

    void (*on_client_alloc)(ah_http_server_t* srv, ah_http_rclient_t** client);
    void (*on_client_accept)(ah_http_server_t* srv, ah_http_rclient_t* client, ah_err_t err);
};

// An HTTP version indicator.
struct ah_http_ver {
    uint8_t major;
    uint8_t minor;
};

// An HTTP request line.
struct ah_http_req_line {
    const char* method;
    const char* target;
    ah_http_ver_t version;
};

// An HTTP status line.
struct ah_http_stat_line {
    ah_http_ver_t version;
    uint16_t code;
    const char* reason;
};

// The size and extension string part of an incoming HTTP chunk.
struct ah_http_chunk_line {
    size_t size;

    // Will be NULL or something that should adhere to the chunk-ext syntax, as
    // described in https://www.rfc-editor.org/rfc/rfc7230#section-4.1.1.
    const char* ext;
};

// An outgoing HTTP chunk.
struct ah_http_chunk {
    // Must be NULL, an empty string, or adhere to the chunk-ext syntax, as
    // described in https://www.rfc-editor.org/rfc/rfc7230#section-4.1.1.
    const char* ext;

    ah_tcp_msg_t data;

    AH_I_HTTP_CHUNK_FIELDS
};

// An HTTP header.
struct ah_http_header {
    const char* name;
    const char* value;
};

// The ending part of an outgoing chunked message transmission.
struct ah_http_trailer {
    // Must be NULL, an empty string, or adhere to the chunk-ext syntax, as
    // described in https://www.rfc-editor.org/rfc/rfc7230#section-4.1.1.
    const char* ext;

    ah_http_header_t* headers; // Array terminated by { NULL, * } pair.

    AH_I_HTTP_TRAILER_FIELDS
};

// The body of an outgoing HTTP request or response.
union ah_http_body {
    AH_I_HTTP_BODY_FIELDS
};

// An outgoing HTTP request.
struct ah_http_req {
    ah_http_req_line_t req_line;
    ah_http_header_t* headers; // Array terminated by { NULL, * } pair.
    ah_http_body_t body;
    void* user_data;

    AH_I_HTTP_REQ_FIELDS
};

// An outgoing HTTP response.
struct ah_http_res {
    ah_http_stat_line_t stat_line;
    ah_http_header_t* headers; // Array terminated by { NULL, * } pair.
    ah_http_body_t body;
    void* user_data;

    AH_I_HTTP_RES_FIELDS
};

ah_extern ah_err_t ah_http_lclient_init(ah_http_lclient_t* cln, ah_tcp_trans_t trans, const ah_http_lclient_vtab_t* vtab);
ah_extern ah_err_t ah_http_lclient_open(ah_http_lclient_t* cln, const ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_http_lclient_connect(ah_http_lclient_t* cln, const ah_sockaddr_t* raddr);
ah_extern ah_err_t ah_http_lclient_request(ah_http_lclient_t* cln, ah_http_req_t* req);
ah_extern ah_err_t ah_http_lclient_send_data(ah_http_lclient_t* cln, ah_tcp_msg_t* msg);
ah_extern ah_err_t ah_http_lclient_send_end(ah_http_lclient_t* cln);
ah_extern ah_err_t ah_http_lclient_send_chunk(ah_http_lclient_t* cln, ah_http_chunk_t* chunk);
ah_extern ah_err_t ah_http_lclient_send_trailer(ah_http_lclient_t* cln, ah_http_trailer_t* trailer);
ah_extern ah_err_t ah_http_lclient_close(ah_http_lclient_t* cln);
ah_extern ah_tcp_conn_t* ah_http_lclient_get_conn(ah_http_lclient_t* cln);
ah_extern void* ah_http_lclient_get_user_data(ah_http_lclient_t* cln);
ah_extern void ah_http_lclient_set_user_data(ah_http_lclient_t* cln, void* user_data);

ah_extern ah_err_t ah_http_server_init(ah_http_server_t* srv, ah_tcp_trans_t trans, const ah_http_server_vtab_t* vtab);
ah_extern ah_err_t ah_http_server_open(ah_http_server_t* srv, const ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_http_server_listen(ah_http_server_t* srv, unsigned backlog, const ah_http_rclient_vtab_t* vtab);
ah_extern ah_err_t ah_http_server_close(ah_http_server_t* srv);
ah_extern ah_tcp_listener_t* ah_http_server_get_listener(ah_http_server_t* srv);
ah_extern void* ah_http_server_get_user_data(ah_http_server_t* srv);
ah_extern void ah_http_server_set_user_data(ah_http_server_t* srv, void* user_data);

ah_extern ah_err_t ah_http_rclient_respond(ah_http_rclient_t* cln, ah_http_res_t* res);
ah_extern ah_err_t ah_http_rclient_send_data(ah_http_rclient_t* cln, ah_tcp_msg_t* msg);
ah_extern ah_err_t ah_http_rclient_send_end(ah_http_rclient_t* cln);
ah_extern ah_err_t ah_http_rclient_send_chunk(ah_http_rclient_t* cln, ah_http_chunk_t* chunk);
ah_extern ah_err_t ah_http_rclient_send_trailer(ah_http_rclient_t* cln, ah_http_trailer_t* trailer);
ah_extern ah_err_t ah_http_rclient_close(ah_http_rclient_t* cln);
ah_extern ah_tcp_conn_t* ah_http_rclient_get_conn(ah_http_rclient_t* cln);
ah_extern ah_http_server_t* ah_http_rclient_get_server(ah_http_rclient_t* cln);
ah_extern void* ah_http_rclient_get_user_data(ah_http_rclient_t* cln);
ah_extern void ah_http_rclient_set_user_data(ah_http_rclient_t* cln, void* user_data);

ah_extern ah_http_body_t ah_http_body_empty(void);
ah_extern ah_http_body_t ah_http_body_from_buf(ah_buf_t buf);
ah_extern ah_http_body_t ah_http_body_from_bufs(ah_bufs_t bufs);
ah_extern ah_http_body_t ah_http_body_from_cstr(char* cstr);
ah_extern ah_http_body_t ah_http_body_override(void); // Enables use of *_send_{chunk,data,end,trailer} functions.

#endif
