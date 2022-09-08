// SPDX-License-Identifier: EPL-2.0

#ifndef AH_MBEDTLS_H_
#define AH_MBEDTLS_H_

/**
 * @file
 * Transport Layer Security (TLS) via MbedTLS.
 *
 * Here, structures and functions are provided for associating TLS clients and
 * servers with ah_tcp_trans instances. These transport instances may then be
 * used to make ah_tcp_conn and ah_tcp_listener instances communicate using the
 * TLS protocol. TLS clients are used as transports when initializing local TCP
 * connections, while TLS servers are used as transports when initializing local
 * TCP listeners. Below, we provide brief instructions for initializing and
 * using clients and servers, respectively.
 *
 * <h3>Clients</h3>
 *
 * TLS clients are initialized using ah_mbedtls_client_init(). That function
 * takes an mbedtls_ssl_config instance as argument, which you must prepare by
 * setting its @e endpoint to <em>client mode</em> and by providing other
 * relevant configuration details. Setting the endpoint of the MbedTLS
 * configuration can be performed using the mbedtls_ssl_config_defaults()
 * function. For more details about how to set up an MbedTLS configuration
 * objects, please refer to the <a href="https://tls.mbed.org">MbedTLS</a>
 * documentation.
 *
 * Once you have a properly initialized ah_mbedtls_client instance, you can get
 * its associated TCP transport by calling ah_mbedtls_client_as_tcp_trans().
 * That transport can be used to initialize a TCP connection by calling
 * ah_tcp_conn_init().
 *
 * When using a TLS transport with a TCP connection, its callbacks may be
 * invoked with one additional error code: @ref AH_EDEP. That error code
 * indicates that you must use ah_mbedtls_client_get_last_err() to get the last
 * error code produced by MbedTLS. It is up to you to handle these errors as you
 * see fit.
 *
 * Every initialized ah_mbedtls_client instance must also be terminated once no
 * longer in use, which you can do by calling ah_mbedtls_client_term(). Note
 * that that function will not terminate the MbedTLS configuration. An
 * appropriate place to terminate both clients and configurations is likely
 * often going to be the ah_tcp_conn_cbs::on_close callback of the TCP
 * connection you provide the MbedTLS client transport to.
 *
 * <h3>Servers</h3>
 *
 * TLS servers are initialized, used and terminated in the same manner as TLS
 * clients. The names of the functions we provide here are the same as those for
 * TLS clients, with the difference that the server functions are prefixed with
 * @c ah_mbedtls_server_. You must, however, make sure that the MbedTLS
 * configurations you produce have their @e endpoints set to
 * <em>server mode</em>.
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
 * @a cln has been part of a completed TLS handshake.
 *
 * @param cln        Pointer to client associated with the connection through
 *                   which the TLS handshake was performed.
 * @param peer_chain Pointer to the certificate chain of the remote host, if
 *                   @a err is @ref AH_ENONE and MbedTLS is compiled with
 *                   @c MBEDTLS_X509_CRT_PARSE_C enabled. @c NULL is returned in
 *                   any other case.
 * @param err        One of the following error codes may always be given: <ul>
 *   <li>@ref AH_ENONE   - Handshake concluded with a usable TLS session.
 *   <li>@ref AH_EDEP    - An MbedTLS error occurred that cannot be represented
 *                         with an Arrowhead Core C error code. Use the
 *                         ah_mbedtls_client_get_last_err() function with @a cln
 *                         as argument to get a copy of the MbedTLS error.
 *   <li>@ref AH_ENOMEM  - Not enough heap memory available.
 * </ul>
 * What other error codes are possible depend on the underlying TCP transport
 * used by the handshaking TLS client. See ah_tcp_conn_cbs::on_read and
 * ah_tcp_conn_cbs::on_write for lists of error codes that may be provided if
 * the default TCP transport is used, directly or indirectly, by the TLS client.
 *
 * @note To access the TLS client associated with @a cln, use the
 *       ah_mbedtls_conn_get_client() function.
 */
typedef void (*ah_mbedtls_on_handshake_done_cb)(ah_mbedtls_client_t* cln, const mbedtls_x509_crt* peer_chain, ah_err_t err);

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
 * Initializes @a cln for subsequent use.
 *
 * @param cln                  Pointer to client.
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
 *                        @a cln as argument to get a copy of the MbedTLS error.
 *   <li>@ref AH_EINVAL - @a cln, @a ssl_conf or @a on_handshake_done_cb is @c NULL.
 *   <li>@ref AH_EINVAL - @a trans is invalid, as reported by ah_tcp_trans_vtab_is_valid().
 *   <li>@ref AH_ENOMEM - Failed to allocate heap memory.
 * </ul>
 *
 * @note You must initialize a separate MbedTLS client for each TCP connection
 *       you want to use with and MbedTLS transport.
 *
 * @note Every successfully initialized @a cln must eventually be provided to
 *       ah_mbedtls_client_term().
 */
ah_extern ah_err_t ah_mbedtls_client_init(ah_mbedtls_client_t* cln, ah_tcp_trans_t trans, mbedtls_ssl_config* ssl_conf, ah_mbedtls_on_handshake_done_cb on_handshake_done_cb);

/**
 * Gets copy of TCP transport associated with @a cln.
 *
 * The ah_tcp_trans::ctx field will contain a pointer to @a cln.
 *
 * @param cln Pointer to client.
 * @return TCP transport. If @a cln is @c NULL,
 *         <code>(ah_tcp_trans_t) { NULL, NULL }</code> will be returned.
 *
 * @warning Using the returned transport with more than a single TCP connection
 *          yields undefined behavior.
 */
ah_extern ah_tcp_trans_t ah_mbedtls_client_as_tcp_trans(ah_mbedtls_client_t* cln);

/**
 * Gets pointer to TCP connection associated with @a cln.
 *
 * @a cln becomes associated with a connection when it is provided as a TCP
 * transport to an initialized connection.
 *
 * @param cln Pointer to client.
 * @return Pointer to connection. If @a cln is @c NULL or has not yet been
 *         associated with a client, @c NULL is returned.
 */
ah_extern ah_tcp_conn_t* ah_mbedtls_client_get_tcp_conn(ah_mbedtls_client_t* cln);

/**
 * Gets last MbedTLS error code saved by @a cln.
 *
 * @param cln Pointer to client.
 * @return MbedTLS error code, or @c MBEDTLS_ERR_ERROR_GENERIC_ERROR if @a cln
 *         is @c NULL.
 */
ah_extern int ah_mbedtls_client_get_last_err(ah_mbedtls_client_t* cln);

/**
 * Gets TLS/SSL context associated with @a cln.
 *
 * @a cln becomes associated with a TLS/SSL context when successfully
 * initialized via a call to ah_mbedtls_client_init().
 *
 * @param cln Pointer to client.
 * @return Pointer to MbedTLS TLS/SSL context, or @c NULL if @a cln is @c NULL.
 */
ah_extern mbedtls_ssl_context* ah_mbedtls_client_get_ssl_context(ah_mbedtls_client_t* cln);

/**
 * Terminates @a cln, releasing any resources it may hold.
 *
 * @param cln Pointer to client.
 */
ah_extern void ah_mbedtls_client_term(ah_mbedtls_client_t* cln);

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
 * Initializes @a srv for subsequent use.
 *
 * @param srv                  Pointer to server.
 * @param trans                Desired base transport, used to send and receive
 *                             TLS handshake messages and encrypted data.
 * @param ssl_conf             Pointer to initialized and prepared MbedTLS
 *                             SSL/TLS configuration. The configuration must be
 *                             set to <em>server mode</em> by being provided the
 *                             @c MBEDTLS_SSL_IS_SERVER endpoint identifier.
 * @param on_handshake_done_cb Pointer to function called whenever a TCP
 *                             handshake is concluded.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - Initialization was successful.
 *   <li>@ref AH_EINVAL - @a srv, @a ssl_conf or @a on_handshake_done_cb is @c NULL.
 *   <li>@ref AH_EINVAL - @a trans is invalid, as reported by ah_tcp_trans_vtab_is_valid().
 *   <li>@ref AH_ENOMEM - Failed to allocate heap memory.
 * </ul>
 *
 * @note You must initialize a separate MbedTLS server for each TCP listener you
 *       want to use with an MbedTLS transport.
 *
 * @note Every successfully initialized @a srv must eventually be provided to
 *       ah_mbedtls_server_term().
 *
 * @note This call will not create any MbedTLS TLS/SSL contexts. Rather, one
 *       such will be created for each connection accepted by the TCP listener
 *       associated with @a srv.
 */
ah_extern ah_err_t ah_mbedtls_server_init(ah_mbedtls_server_t* srv, ah_tcp_trans_t trans, mbedtls_ssl_config* ssl_conf, ah_mbedtls_on_handshake_done_cb on_handshake_done_cb);

/**
 * Gets copy of TCP transport associated with @a srv.
 *
 * The ah_tcp_trans::ctx field will contain a pointer to @a srv.
 *
 * @param srv Pointer to client.
 * @return TCP transport. If @a srv is @c NULL,
 *         <code>(ah_tcp_trans_t) { NULL, NULL }</code> will be returned.
 *
 * @warning Using the returned transport with more than a single TCP listener
 *          yields undefined behavior.
 */
ah_extern ah_tcp_trans_t ah_mbedtls_server_as_tcp_trans(ah_mbedtls_server_t* srv);

/**
 * Terminates @a srv, releasing any resources it may hold.
 *
 * @param srv Pointer to server.
 */
ah_extern void ah_mbedtls_server_term(ah_mbedtls_server_t* srv);

/** @} */

#endif
