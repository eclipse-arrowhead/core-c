// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/mbedtls.h"

#include <ah/err.h>
#include <ah/loop.h>
#include <ah/tcp.h>
#include <ah/unit.h>
#include <mbedtls/certs.h>
#include <mbedtls/error.h>

struct s_tcp_conn_user_data {
    ah_buf_t* free_bufs[2];

    const ah_sockaddr_t* ln_addr;
    ah_tcp_listener_t* ln;

    ah_tcp_msg_t send_msg;

    size_t* close_call_counter;

    bool did_call_open_cb;
    bool did_call_connect_cb;
    bool did_call_handshake_done_cb;
    bool did_call_close_cb;
    bool did_call_read_alloc_cb;
    bool did_call_read_done_cb;
    bool did_call_write_done_cb;

    ah_unit_t* unit;
};

struct s_tcp_listener_user_data {
    ah_sockaddr_t addr;
    ah_tcp_conn_t* conn;

    ah_tcp_conn_t* free_conn;
    struct s_tcp_conn_user_data accept_user_data;

    bool did_call_open_cb;
    bool did_call_listen_cb;
    bool did_call_close_cb;
    bool did_call_conn_alloc_cb;
    bool did_call_conn_accept_cb;

    ah_unit_t* unit;
};

static void s_should_read_and_write_data(ah_unit_t* unit);

void test_mbedtls(ah_unit_t* unit)
{
    s_should_read_and_write_data(unit);
}

static void s_on_conn_open(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_conn_connect(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_conn_handshake_done(ah_tcp_conn_t* conn, const mbedtls_x509_crt* peer_chain, ah_err_t err);
static void s_on_conn_close(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_conn_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf);
static void s_on_conn_read_data(ah_tcp_conn_t* conn, ah_buf_t buf, size_t nread, ah_err_t err);
static void s_on_conn_write_done(ah_tcp_conn_t* conn, ah_err_t err);

static void s_on_listener_open(ah_tcp_listener_t* ln, ah_err_t err);
static void s_on_listener_listen(ah_tcp_listener_t* ln, ah_err_t err);
static void s_on_listener_close(ah_tcp_listener_t* ln, ah_err_t err);
static void s_on_listener_conn_alloc(ah_tcp_listener_t* ln, ah_tcp_conn_t** conn);
static void s_on_listener_conn_accept(ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr, ah_err_t err);

static const ah_tcp_conn_cbs_t s_conn_cbs = {
    .on_open = s_on_conn_open,
    .on_connect = s_on_conn_connect,
    .on_close = s_on_conn_close,
    .on_read_alloc = s_on_conn_read_alloc,
    .on_read_data = s_on_conn_read_data,
    .on_write_done = s_on_conn_write_done,
};

static const ah_tcp_listener_cbs_t s_listener_cbs = {
    .on_open = s_on_listener_open,
    .on_listen = s_on_listener_listen,
    .on_close = s_on_listener_close,
    .on_conn_alloc = s_on_listener_conn_alloc,
    .on_conn_accept = s_on_listener_conn_accept,
};

static void s_on_conn_open(ah_tcp_conn_t* conn, ah_err_t err)
{
    struct s_tcp_conn_user_data* user_data = ah_tcp_conn_get_user_data(conn);

    ah_unit_t* unit = user_data->unit;

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    err = ah_tcp_conn_set_keepalive(conn, false);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    err = ah_tcp_conn_set_nodelay(conn, true);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    err = ah_tcp_conn_set_reuseaddr(conn, false);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    err = ah_tcp_conn_connect(conn, user_data->ln_addr);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    user_data->did_call_open_cb = true;
}

static void s_on_conn_connect(ah_tcp_conn_t* conn, ah_err_t err)
{
    struct s_tcp_conn_user_data* user_data = ah_tcp_conn_get_user_data(conn);

    ah_unit_t* unit = user_data->unit;

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    err = ah_tcp_conn_read_start(conn);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    user_data->did_call_connect_cb = true;
}

static void s_on_conn_handshake_done(ah_tcp_conn_t* conn, const mbedtls_x509_crt* peer_chain, ah_err_t err)
{
    struct s_tcp_conn_user_data* user_data = ah_tcp_conn_get_user_data(conn);

    ah_unit_t* unit = user_data->unit;

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if (ah_buf_is_empty(&user_data->send_msg.buf)) {
        // Peer is connection/client.
        if (ah_unit_assert_unsigned_eq(unit, peer_chain->raw.len, mbedtls_test_srv_crt_len)) {
            (void) ah_unit_assert_mem_eq(unit, peer_chain->raw.p, mbedtls_test_srv_crt, peer_chain->raw.len);
        }
    }
    else {
        // Peer is listener/server.
        if (ah_unit_assert_unsigned_eq(unit, peer_chain->raw.len, mbedtls_test_cli_crt_len)) {
            (void) ah_unit_assert_mem_eq(unit, peer_chain->raw.p, mbedtls_test_cli_crt, peer_chain->raw.len);
        }
    }
#else
    (void) ah_unit_assert(unit, peer_chain == NULL, "peer_chain != NULL");
#endif

    err = ah_tcp_conn_read_start(conn);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    if (!ah_buf_is_empty(&user_data->send_msg.buf)) {
        err = ah_tcp_conn_write(conn, &user_data->send_msg);
        if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
            if (err == AH_EDEP) {
                char errbuf[256u];
                int res = ah_mbedtls_conn_get_last_err(conn);
                mbedtls_strerror(res, errbuf, sizeof(errbuf));
                ah_unit_printf(unit, "AH_EDEP caused by: %d; %s", res, errbuf);
            }
            return;
        }
    }

    user_data->did_call_handshake_done_cb = true;
}

static void s_on_conn_close(ah_tcp_conn_t* conn, ah_err_t err)
{
    struct s_tcp_conn_user_data* user_data = ah_tcp_conn_get_user_data(conn);

    ah_unit_t* unit = user_data->unit;

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    (*user_data->close_call_counter) += 1u;

    if (*user_data->close_call_counter == 2u) {
        ah_loop_t* loop = ah_tcp_conn_get_loop(conn);
        if (!ah_unit_assert(unit, loop != NULL, "loop == NULL")) {
            return;
        }

        err = ah_loop_term(loop);
        if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
            return;
        }
    }

    user_data->did_call_close_cb = true;
}

static void s_on_conn_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf)
{
    struct s_tcp_conn_user_data* user_data = ah_tcp_conn_get_user_data(conn);

    ah_unit_t* unit = user_data->unit;

    if (user_data->free_bufs[0u] != NULL) {
        *buf = *user_data->free_bufs[0u];
        user_data->free_bufs[0u] = NULL;
    }
    else if (user_data->free_bufs[1u] != NULL) {
        *buf = *user_data->free_bufs[1u];
        user_data->free_bufs[1u] = NULL;
    }
    else {
        ah_unit_fail(unit, "connection read buffer cannot be allocated");
        return;
    }

    user_data->did_call_read_alloc_cb = true;
}

static void s_on_conn_read_data(ah_tcp_conn_t* conn, ah_buf_t buf, size_t nread, ah_err_t err)
{
    struct s_tcp_conn_user_data* user_data = ah_tcp_conn_get_user_data(conn);

    ah_unit_t* unit = user_data->unit;

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    if (!ah_unit_assert(unit, ah_buf_get_base_const(&buf) != NULL, "ah_buf_get_base_const(buf) == NULL")) {
        return;
    }

    if (!ah_unit_assert_unsigned_eq(unit, 18u, nread)) {
        return;
    }

    if (!ah_unit_assert_unsigned_eq(unit, 24u, ah_buf_get_size(&buf))) {
        return;
    }
    if (!ah_unit_assert_cstr_eq(unit, "Hello, Arrowhead!", (char*) ah_buf_get_base_const(&buf))) {
        return;
    }

    ah_err_t err0 = ah_tcp_conn_close(conn);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err0)) {
        return;
    }

    user_data->did_call_read_done_cb = true;
}

static void s_on_conn_write_done(ah_tcp_conn_t* conn, ah_err_t err)
{
    struct s_tcp_conn_user_data* user_data = ah_tcp_conn_get_user_data(conn);

    ah_unit_t* unit = user_data->unit;

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    err = ah_tcp_conn_close(conn);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    ah_mbedtls_client_t* conn_client = ah_mbedtls_conn_get_client(conn);
    if (ah_unit_assert(unit, conn_client != NULL, "conn_client == NULL")) {
        ah_mbedtls_client_term(conn_client);
    }

    err = ah_tcp_listener_close(user_data->ln);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    ah_mbedtls_server_t* ln_server = ah_mbedtls_listener_get_server(user_data->ln);
    if (ah_unit_assert(unit, ln_server != NULL, "ln_server == NULL")) {
        ah_mbedtls_server_term(ln_server);
    }

    user_data->did_call_write_done_cb = true;
}

static void s_on_listener_open(ah_tcp_listener_t* ln, ah_err_t err)
{
    struct s_tcp_listener_user_data* user_data = ah_tcp_listener_get_user_data(ln);

    if (!ah_unit_assert_err_eq(user_data->unit, AH_ENONE, err)) {
        return;
    }

    err = ah_tcp_listener_set_nodelay(ln, false);
    if (!ah_unit_assert_err_eq(user_data->unit, AH_ENONE, err)) {
        return;
    }

    err = ah_tcp_listener_listen(ln, 1, &s_conn_cbs);
    if (!ah_unit_assert_err_eq(user_data->unit, AH_ENONE, err)) {
        return;
    }

    user_data->did_call_open_cb = true;
}

static void s_on_listener_listen(ah_tcp_listener_t* ln, ah_err_t err)
{
    struct s_tcp_listener_user_data* user_data = ah_tcp_listener_get_user_data(ln);
    ah_unit_t* unit = user_data->unit;

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Save the IP address the listener is bound to.
    err = ah_tcp_listener_get_laddr(ln, &user_data->addr);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Open connection that will connect to our listener.
    err = ah_tcp_conn_open(user_data->conn, NULL);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    user_data->did_call_listen_cb = true;
}

static void s_on_listener_close(ah_tcp_listener_t* ln, ah_err_t err)
{
    struct s_tcp_listener_user_data* user_data = ah_tcp_listener_get_user_data(ln);

    if (!ah_unit_assert_err_eq(user_data->unit, AH_ENONE, err)) {
        return;
    }

    user_data->did_call_close_cb = true;
}

static void s_on_listener_conn_alloc(ah_tcp_listener_t* ln, ah_tcp_conn_t** conn)
{
    struct s_tcp_listener_user_data* user_data = ah_tcp_listener_get_user_data(ln);

    if (!ah_unit_assert(user_data->unit, user_data->free_conn != NULL, "no free connection can be allocated")) {
        return;
    }

    *conn = user_data->free_conn;
    user_data->free_conn = NULL;

    user_data->did_call_conn_alloc_cb = true;
}

static void s_on_listener_conn_accept(ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr, ah_err_t err)
{
    struct s_tcp_listener_user_data* user_data = ah_tcp_listener_get_user_data(ln);

    ah_unit_t* unit = user_data->unit;

    if (err == AH_ECANCELED) {
        return;
    }

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    ah_unit_assert(unit, raddr != NULL, "ln_addr == NULL");

    ah_tcp_conn_set_user_data(conn, &user_data->accept_user_data);

    user_data->did_call_conn_accept_cb = true;
}

static void s_should_read_and_write_data(ah_unit_t* unit)
{
    char errbuf[256u];
    ah_err_t err;
    int res;

    // Setup user data.

    size_t close_call_counter = 0u;

    uint8_t free_buf0_base[256u] = { 0u };
    ah_buf_t free_buf0 = ah_buf_from(free_buf0_base, sizeof(free_buf0_base));

    uint8_t free_buf1_base[256u] = { 0u };
    ah_buf_t free_buf1 = ah_buf_from(free_buf1_base, sizeof(free_buf1_base));

    struct s_tcp_conn_user_data conn_user_data = {
        .free_bufs = {
            [0u] = &free_buf0,
            [1u] = &free_buf1,
        },
        .close_call_counter = &close_call_counter,
        .unit = unit,
    };

    uint8_t free_buf2_base[256u] = { 0u };
    ah_buf_t free_buf2 = ah_buf_from(free_buf2_base, sizeof(free_buf2_base));

    struct s_tcp_listener_user_data ln_user_data = {
        .free_conn = &(ah_tcp_conn_t) { 0u },
        .accept_user_data = (struct s_tcp_conn_user_data) {
            .free_bufs = {
                [0u] = &free_buf2,
            },
            .close_call_counter = &close_call_counter,
            .send_msg = (ah_tcp_msg_t) {
                .buf = ah_buf_from((uint8_t*) "Hello, Arrowhead!", 18u),
            },
            .unit = unit,
        },
        .unit = unit,
    };

    // Setup event loop.

    ah_loop_t loop;

    err = ah_loop_init(&loop, &(ah_loop_opts_t) { .capacity = 4u });
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Setup TLS server/listener.

    mbedtls_entropy_context ln_entropy;
    mbedtls_entropy_init(&ln_entropy);

    mbedtls_ctr_drbg_context ln_ctr_drbg;
    mbedtls_ctr_drbg_init(&ln_ctr_drbg);
    res = mbedtls_ctr_drbg_seed(&ln_ctr_drbg, mbedtls_entropy_func, &ln_entropy, NULL, 0u);
    if (res != 0) {
        mbedtls_strerror(res, errbuf, sizeof(errbuf));
        ah_unit_failf(unit, "mbedtls_ctr_drbg_seed() returned %d; %s", res, errbuf);
        return;
    }

    // This test uses embedded certificates provided with the MbedTLS library.
    // In a regular program, you would likely load the certificates using
    // mbedtls_x509_crt_parse_file() and mbedtls_pk_parse_keyfile().

    mbedtls_x509_crt ln_own_cert;
    mbedtls_x509_crt_init(&ln_own_cert);
    res = mbedtls_x509_crt_parse(&ln_own_cert, (const unsigned char*) mbedtls_test_srv_crt, mbedtls_test_srv_crt_len);
    if (res != 0) {
        mbedtls_strerror(res, errbuf, sizeof(errbuf));
        ah_unit_failf(unit, "mbedtls_x509_crt_parse() returned %d; %s", res, errbuf);
        return;
    }
    res = mbedtls_x509_crt_parse(&ln_own_cert, (const unsigned char*) mbedtls_test_cas_pem, mbedtls_test_cas_pem_len);
    if (res != 0) {
        mbedtls_strerror(res, errbuf, sizeof(errbuf));
        ah_unit_failf(unit, "mbedtls_x509_crt_parse() returned %d; %s", res, errbuf);
        return;
    }

    mbedtls_pk_context ln_own_pk;
    mbedtls_pk_init(&ln_own_pk);
    res = mbedtls_pk_parse_key(&ln_own_pk, (const unsigned char*) mbedtls_test_srv_key, mbedtls_test_srv_key_len, NULL, 0);
    if (res != 0) {
        mbedtls_strerror(res, errbuf, sizeof(errbuf));
        ah_unit_failf(unit, "mbedtls_pk_parse_key() returned %d; %s", res, errbuf);
        return;
    }

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context ln_ssl_cache;
    mbedtls_ssl_cache_init(&ln_ssl_cache);
#endif

    mbedtls_ssl_config ln_ssl_conf;
    mbedtls_ssl_config_init(&ln_ssl_conf);
    res = mbedtls_ssl_config_defaults(&ln_ssl_conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (res != 0) {
        mbedtls_strerror(res, errbuf, sizeof(errbuf));
        ah_unit_failf(unit, "mbedtls_ssl_config_defaults() returned %d; %s", res, errbuf);
        return;
    }

    mbedtls_ssl_conf_authmode(&ln_ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache(&ln_ssl_conf, &ln_ssl_cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
#endif
    mbedtls_ssl_conf_ca_chain(&ln_ssl_conf, ln_own_cert.next, NULL);
    res = mbedtls_ssl_conf_own_cert(&ln_ssl_conf, &ln_own_cert, &ln_own_pk);
    if (res != 0) {
        mbedtls_strerror(res, errbuf, sizeof(errbuf));
        ah_unit_failf(unit, "mbedtls_ssl_conf_own_cert() returned %d; %s", res, errbuf);
        return;
    }
    mbedtls_ssl_conf_rng(&ln_ssl_conf, mbedtls_ctr_drbg_random, &ln_ctr_drbg);

    ah_mbedtls_server_t ln_server;
    ah_mbedtls_server_init(&ln_server, ah_tcp_trans_get_default(), &ln_ssl_conf, s_on_conn_handshake_done);

    ah_tcp_listener_t ln;
    err = ah_tcp_listener_init(&ln, &loop, ah_mbedtls_server_as_trans(&ln_server), &s_listener_cbs);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    ln_user_data.accept_user_data.ln = &ln;
    ah_tcp_listener_set_user_data(&ln, &ln_user_data);

    // Setup TLS client.

    mbedtls_entropy_context conn_entropy;
    mbedtls_entropy_init(&conn_entropy);

    mbedtls_ctr_drbg_context conn_ctr_drbg;
    mbedtls_ctr_drbg_init(&conn_ctr_drbg);
    res = mbedtls_ctr_drbg_seed(&conn_ctr_drbg, mbedtls_entropy_func, &conn_entropy, NULL, 0u);
    if (res != 0) {
        mbedtls_strerror(res, errbuf, sizeof(errbuf));
        ah_unit_failf(unit, "mbedtls_ctr_drbg_seed() returned %d; %s", res, errbuf);
        return;
    }

    mbedtls_x509_crt conn_cacert;
    mbedtls_x509_crt_init(&conn_cacert);
    res = mbedtls_x509_crt_parse(&conn_cacert, (const unsigned char*) mbedtls_test_cas_pem, mbedtls_test_cas_pem_len);
    if (res != 0) {
        mbedtls_strerror(res, errbuf, sizeof(errbuf));
        ah_unit_failf(unit, "mbedtls_x509_crt_parse() returned %d; %s", res, errbuf);
        return;
    }

    mbedtls_x509_crt conn_own_cert;
    mbedtls_x509_crt_init(&conn_own_cert);
    res = mbedtls_x509_crt_parse(&conn_own_cert, (const unsigned char*) mbedtls_test_cli_crt, mbedtls_test_cli_crt_len);
    if (res != 0) {
        mbedtls_strerror(res, errbuf, sizeof(errbuf));
        ah_unit_failf(unit, "mbedtls_x509_crt_parse() returned %d; %s", res, errbuf);
        return;
    }

    mbedtls_pk_context conn_own_pk;
    mbedtls_pk_init(&conn_own_pk);
    res = mbedtls_pk_parse_key(&conn_own_pk, (const unsigned char*) mbedtls_test_cli_key, mbedtls_test_cli_key_len, NULL, 0);
    if (res != 0) {
        mbedtls_strerror(res, errbuf, sizeof(errbuf));
        ah_unit_failf(unit, "mbedtls_pk_parse_key() returned %d; %s", res, errbuf);
        return;
    }

    mbedtls_ssl_config conn_ssl_conf;
    mbedtls_ssl_config_init(&conn_ssl_conf);
    res = mbedtls_ssl_config_defaults(&conn_ssl_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (res != 0) {
        mbedtls_strerror(res, errbuf, sizeof(errbuf));
        ah_unit_failf(unit, "mbedtls_ssl_config_defaults() returned %d; %s", res, errbuf);
        return;
    }

    mbedtls_ssl_conf_authmode(&conn_ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conn_ssl_conf, &conn_cacert, NULL);
    res = mbedtls_ssl_conf_own_cert(&conn_ssl_conf, &conn_own_cert, &conn_own_pk);
    if (res != 0) {
        mbedtls_strerror(res, errbuf, sizeof(errbuf));
        ah_unit_failf(unit, "mbedtls_ssl_conf_own_cert() returned %d; %s", res, errbuf);
        return;
    }
    mbedtls_ssl_conf_rng(&conn_ssl_conf, mbedtls_ctr_drbg_random, &conn_ctr_drbg);

    ah_mbedtls_client_t conn_client;
    ah_mbedtls_client_init(&conn_client, ah_tcp_trans_get_default(), &conn_ssl_conf, s_on_conn_handshake_done);

    ah_tcp_conn_t conn;
    err = ah_tcp_conn_init(&conn, &loop, ah_mbedtls_client_as_trans(&conn_client), &s_conn_cbs);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    conn_user_data.ln_addr = &ln_user_data.addr;
    ah_tcp_conn_set_user_data(&conn, &conn_user_data);

    ln_user_data.conn = &conn;

    // Open listener, which will open the connection, and so on.

    err = ah_tcp_listener_open(&ln, NULL);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Submit issued events for execution.

    ah_time_t deadline;
    err = ah_time_add(ah_time_now(), 10000 * AH_TIMEDIFF_S, &deadline);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    err = ah_loop_run_until(&loop, &deadline);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Check results.

    struct s_tcp_conn_user_data* conn_data = &conn_user_data;
    (void) ah_unit_assert(unit, conn_data->did_call_open_cb, "`conn` s_on_conn_open() not called");
    (void) ah_unit_assert(unit, conn_data->did_call_connect_cb, "`conn` s_on_conn_connect() not called");
    (void) ah_unit_assert(unit, conn_data->did_call_handshake_done_cb, "`conn` s_on_conn_handshake_done() not called");
    (void) ah_unit_assert(unit, conn_data->did_call_close_cb, "`conn` s_on_conn_close() not called");
    (void) ah_unit_assert(unit, conn_data->did_call_read_alloc_cb, "`conn` s_on_conn_read_alloc() not called");
    (void) ah_unit_assert(unit, conn_data->did_call_read_done_cb, "`conn` s_on_conn_read_data() not called");
    (void) ah_unit_assert(unit, !conn_data->did_call_write_done_cb, "`conn` s_on_conn_write_done() was called");

    struct s_tcp_listener_user_data* ln_data = &ln_user_data;
    (void) ah_unit_assert(unit, ln_data->did_call_open_cb, "`ln` s_on_listener_open() not called");
    (void) ah_unit_assert(unit, ln_data->did_call_listen_cb, "`ln` s_on_listener_listen() not called");
    (void) ah_unit_assert(unit, ln_data->did_call_close_cb, "`ln` s_on_listener_close() not called");
    (void) ah_unit_assert(unit, ln_data->did_call_conn_alloc_cb, "`ln` s_on_listener_conn_alloc() not called");
    (void) ah_unit_assert(unit, ln_data->did_call_conn_accept_cb, "`ln` s_on_listener_conn_accept() not called");

    struct s_tcp_conn_user_data* acc_data = &ln_data->accept_user_data;
    (void) ah_unit_assert(unit, !acc_data->did_call_open_cb, "`acc` s_on_conn_open() was called");
    (void) ah_unit_assert(unit, !acc_data->did_call_connect_cb, "`acc` s_on_conn_connect() was called");
    (void) ah_unit_assert(unit, acc_data->did_call_handshake_done_cb, "`acc` s_on_conn_handshake_done() not called");
    (void) ah_unit_assert(unit, acc_data->did_call_close_cb, "`acc` s_on_conn_close() not called");
    (void) ah_unit_assert(unit, !acc_data->did_call_read_alloc_cb, "`acc` s_on_conn_read_alloc() was called");
    (void) ah_unit_assert(unit, !acc_data->did_call_read_done_cb, "`acc` s_on_conn_read_data() was called");
    (void) ah_unit_assert(unit, acc_data->did_call_write_done_cb, "`acc` s_on_conn_write_done() not called");

    ah_unit_assert(unit, ah_loop_is_term(&loop), "`loop` never terminated");
}
