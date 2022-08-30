// SPDX-License-Identifier: EPL-2.0

#ifndef AH_MBEDTLS_H_
#define AH_MBEDTLS_H_

/**
 * @file
 * Transport Layer Security (TLS) via MbedTLS.
 *
 * Here, structures and functions are provided for associating TLS clients and
 * servers with ah_tcp_trans instances. These transport instances may be used to
 * make ah_tcp_conn and ah_tcp_listener instances communicate using the TLS
 * protocol.
 *
 * @see https://rfc-editor.org/rfc/rfc8446
 * @see https://rfc-editor.org/rfc/rfc5246
 * @see https://tls.mbed.org/
 */

#include "internal/_mbedtls.h"

#include <ah/tcp.h>
#include <stdbool.h>

typedef struct ah_mbedtls_client ah_mbedtls_client_t;
typedef struct ah_mbedtls_server ah_mbedtls_server_t;

/**
 * @a conn has been part of a completed TLS handshake.
 *
 * @param conn       Pointer to connection over which the TLS handshake was
 *                   performed.
 * @param peer_chain Pointer to the certificate chain of the remote host, if
 *                   @a err is @ref AH_ENONE and MbedTLS is compiled with
 *                   @c MBEDTLS_X509_CRT_PARSE_C enabled. @c NULL is returned in
 *                   any other case.
 * @param err        One of the following error codes may always be given: <ul>
 *   <li>@ref AH_ENONE   - Handshake concluded with a usable TLS session.
 *   <li>@ref AH_EDEP    - An MbedTLS error occurred that cannot be represented
 *                         with an Arrowhead Core C error code. Use the
 *                         ah_mbedtls_conn_get_last_err() function with @a conn
 *                         as argument to get a copy of the MbedTLS error.
 *   <li>@ref AH_ENOMEM  - Not enough heap memory available.
 * </ul>
 * What other error codes are possible depend on the underlying TCP transport
 * used by the handshaking TLS client. See ah_tcp_conn_cbs::on_read and
 * ah_tcp_conn_cbs::on_write for lists of error codes that may be provided if
 * the default TCP transport is used, directly or indirectly, by the TLS client.
 *
 * @note To access the TLS client associated with @a conn, use the
 *       ah_mbedtls_conn_get_client() function.
 */
typedef void (*ah_mbedtls_on_handshake_done_cb)(ah_tcp_conn_t* conn, const mbedtls_x509_crt* peer_chain, ah_err_t err);

/**
 * MbedTLS client context.
 *
 * Holds TLS data, such as certificates and sessions, associated with the
 * ah_tcp_trans of an ah_tcp_conn instance.
 *
 * @note All fields of this data structure are @e private in the sense that a
 *       user of this API should not access them directly.
 */
struct ah_mbedtls_client {
    AH_I_TLS_CLIENT_FIELDS
};

/**
 * MbedTLS server context.
 *
 * Holds TLS data, such as certificates and sessions, associated with the
 * ah_tcp_trans of an ah_tcp_listener instance.
 *
 * @note All fields of this data structure are @e private in the sense that a
 *       user of this API should not access them directly.
 */
struct ah_mbedtls_server {
    AH_I_TLS_SERVER_FIELDS
};

/**
 * @name TLS Client
 *
 * Operations on ah_mbedtls_client instances. All such instances must be
 * initialized using ah_mbedtls_client_init() before they are provided to any
 * other functions listed here. Any other requirements regarding the state of
 * clients are described in the documentation of each respective function,
 * sometimes only via the error codes it lists.
 *
 * @{
 */

/**
 * Initializes @a client for subsequent use.
 *
 * @param client               Pointer to client.
 * @param trans                Desired base transport, used to send and receive
 *                             TLS handshake messages and encrypted data.
 * @param ssl_conf             Pointer to initialized and prepared MbedTLS
 *                             SSL/TLS configuration. The configuration must be
 *                             set to <em>client mode</em> by being provided the
 *                             @c MBEDTLS_SSL_IS_CLIENT endpoint identifier.
 * @param on_handshake_done_cb Pointer to function called whenever a TCP
 *                             handshake is concluded.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - Initialization was successful.
 *   <li>@ref AH_EDEP   - An MbedTLS error occurred that cannot be represented with an Arrowhead
 *                        Core C error code. Use the ah_mbedtls_client_get_last_err() function with
 *                        @a client as argument to get a copy of the MbedTLS error.
 *   <li>@ref AH_EINVAL - @a client, @a ssl_conf or @a on_handshake_done_cb is @c NULL.
 *   <li>@ref AH_EINVAL - @a trans is invalid, as reported by ah_tcp_vtab_is_valid().
 *   <li>@ref AH_ENOMEM - Failed to allocate heap memory.
 * </ul>
 */
ah_extern ah_err_t ah_mbedtls_client_init(ah_mbedtls_client_t* client, ah_tcp_trans_t trans, mbedtls_ssl_config* ssl_conf, ah_mbedtls_on_handshake_done_cb on_handshake_done_cb);

ah_extern ah_tcp_trans_t ah_mbedtls_client_as_trans(ah_mbedtls_client_t* client);
ah_extern int ah_mbedtls_client_get_last_err(ah_mbedtls_client_t* client);
ah_extern mbedtls_ssl_context* ah_mbedtls_client_get_ssl_context(ah_mbedtls_client_t* client);
ah_extern void ah_mbedtls_client_term(ah_mbedtls_client_t* client);

/** @} */

/**
 * @name TLS Utilities for TCP Connections
 *
 * Operations on ah_tcp_conn instances relevant when they are directly provided
 * with ... TODO
 *
 * @{
 */

ah_extern ah_mbedtls_client_t* ah_mbedtls_conn_get_client(ah_tcp_conn_t* conn);
ah_extern int ah_mbedtls_conn_get_last_err(ah_tcp_conn_t* conn);
ah_extern mbedtls_ssl_context* ah_mbedtls_conn_get_ssl_context(ah_tcp_conn_t* conn);

/** @} */

/**
 * @name TLS Server
 *
 * Operations on ah_mbedtls_server instances. All such instances must be
 * initialized using ah_mbedtls_server_init() before they are provided to any
 * other functions listed here. Any other requirements regarding the state of
 * servers are described in the documentation of each respective function,
 * sometimes only via the error codes it lists.
 *
 * @{
 */

/**
 * Initializes @a server for subsequent use.
 *
 * @param server               Pointer to server.
 * @param trans                Desired base transport, used to send and receive
 *                             TLS handshake messages and encrypted data.
 * @param ssl_conf             Pointer to initialized and prepared MbedTLS
 *                             SSL/TLS configuration. The configuration must be
 *                             set to <em>server mode</em> by being provided the
 *                             @c MBEDTLS_SSL_IS_SERVER endpoint identifier.
 * @param on_handshake_done_cb Pointer to function called whenever a TCP
 *                             handshake is concluded.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE     - Initialization was successful.
 *   <li>@ref AH_EOVERFLOW - @c AH_PSIZE is too small for it to be possible to store both required
 *                           metadata @e and connected clients data in a single page provided by the
 *                           page allocator (see ah_palloc()).
 *   <li>@ref AH_EINVAL    - @a server, @a ssl_conf or @a on_handshake_done_cb is @c NULL.
 *   <li>@ref AH_EINVAL    - @a trans is invalid, as reported by ah_tcp_vtab_is_valid().
 *   <li>@ref AH_ENOMEM    - Failed to allocate heap memory.
 * </ul>
 */
ah_extern ah_err_t ah_mbedtls_server_init(ah_mbedtls_server_t* server, ah_tcp_trans_t trans, mbedtls_ssl_config* ssl_conf, ah_mbedtls_on_handshake_done_cb on_handshake_done_cb);

ah_extern int ah_mbedtls_server_get_last_err(ah_mbedtls_server_t* server);
ah_extern mbedtls_ssl_config* ah_mbedtls_server_get_ssl_config(ah_mbedtls_server_t* server);
ah_extern ah_tcp_trans_t ah_mbedtls_server_as_trans(ah_mbedtls_server_t* server);
ah_extern void ah_mbedtls_server_term(ah_mbedtls_server_t* server);

/** @} */

/**
 * @name TLS Utilities for TCP Listeners
 *
 * Operations on ah_tcp_listener instances relevant when they are directly
 * provided with ... TODO
 *
 * @{
 */

ah_extern ah_mbedtls_server_t* ah_mbedtls_listener_get_server(ah_tcp_listener_t* ln);
ah_extern int ah_mbedtls_listener_get_last_err(ah_tcp_listener_t* ln);
ah_extern mbedtls_ssl_config* ah_mbedtls_listener_get_ssl_config(ah_tcp_listener_t* ln);

/** @} */

#endif
