// SPDX-License-Identifier: EPL-2.0

#include "ah/mbedtls.h"
#include "certs.h"

#include <ah/err.h>
#include <ah/loop.h>
#include <ah/sock.h>
#include <ah/tcp.h>
#include <ah/unit.h>
#include <mbedtls/debug.h>
#include <mbedtls/error.h>
#include <mbedtls/version.h>

struct s_tcp_conn_user_data {
    const ah_sockaddr_t* ln_addr;
    ah_tcp_listener_t* ln;

    ah_tcp_out_t send_msg;

    size_t* close_call_counter;

    bool did_call_open_cb;
    bool did_call_connect_cb;
    bool did_call_handshake_done_cb;
    bool did_call_close_cb;
    bool did_call_read_cb;
    bool did_call_write_cb;

    ah_unit_res_t* res;
};

struct s_tcp_listener_user_data {
    ah_sockaddr_t addr;
    ah_tcp_conn_t* conn;

    struct s_tcp_conn_user_data accept_user_data;

    bool did_call_open_cb;
    bool did_call_listen_cb;
    bool did_call_close_cb;
    bool did_call_accept_cb;

    ah_unit_res_t* res;
};

static void s_should_read_and_write_data(ah_unit_res_t* res);

void test_mbedtls(ah_unit_res_t* res)
{
    s_should_read_and_write_data(res);
}

static void ah_s_tcp_on_conn_open(void* ctx, ah_tcp_conn_t* conn, ah_err_t err);
static void ah_s_tcp_on_conn_connect(void* ctx, ah_tcp_conn_t* conn, ah_err_t err);
static void ah_s_tcp_on_conn_read(void* client, ah_tcp_conn_t* conn, ah_tcp_in_t* in, ah_err_t err);
static void ah_s_tcp_on_conn_write(void* ctx, ah_tcp_conn_t* conn, ah_tcp_out_t* out, ah_err_t err);
static void ah_s_tcp_on_conn_close(void* ctx, ah_tcp_conn_t* conn, ah_err_t err);

static void ah_s_mbedtls_client_on_handshake_done(ah_mbedtls_client_t* client, const mbedtls_x509_crt* peer_chain, ah_err_t err);

static void ah_s_tcp_on_listener_open(void* ctx, ah_tcp_listener_t* ln, ah_err_t err);
static void ah_s_tcp_on_listener_listen(void* ctx, ah_tcp_listener_t* ln, ah_err_t err);
static void ah_s_tcp_on_listener_close(void* ctx, ah_tcp_listener_t* ln, ah_err_t err);
static void ah_s_tcp_on_listener_accept(void* ctx, ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr, ah_err_t err);

static void s_print_mbedtls_err_if_any(ah_unit_ctx_t ctx, ah_mbedtls_client_t* client, ah_err_t err);

static const ah_tcp_conn_cbs_t s_conn_cbs = {
    .on_open = ah_s_tcp_on_conn_open,
    .on_connect = ah_s_tcp_on_conn_connect,
    .on_close = ah_s_tcp_on_conn_close,
    .on_read = ah_s_tcp_on_conn_read,
    .on_write = ah_s_tcp_on_conn_write,
};

static const ah_tcp_listener_cbs_t s_listener_cbs = {
    .on_open = ah_s_tcp_on_listener_open,
    .on_listen = ah_s_tcp_on_listener_listen,
    .on_close = ah_s_tcp_on_listener_close,
    .on_accept = ah_s_tcp_on_listener_accept,
};

static void ah_s_tcp_on_conn_open(void* ctx, ah_tcp_conn_t* conn, ah_err_t err)
{
    (void) ctx;

    struct s_tcp_conn_user_data* user_data = ah_tcp_conn_get_user_data(conn);

    ah_unit_res_t* res = user_data->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    err = ah_tcp_conn_set_keepalive(conn, false);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    err = ah_tcp_conn_set_nodelay(conn, true);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    err = ah_tcp_conn_set_reuseaddr(conn, false);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    err = ah_tcp_conn_connect(conn, user_data->ln_addr);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    user_data->did_call_open_cb = true;
}

static void ah_s_tcp_on_conn_connect(void* ctx, ah_tcp_conn_t* conn, ah_err_t err)
{
    (void) ctx;

    struct s_tcp_conn_user_data* user_data = ah_tcp_conn_get_user_data(conn);

    ah_unit_res_t* res = user_data->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    err = ah_tcp_conn_read_start(conn);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    user_data->did_call_connect_cb = true;
}

static void s_print_mbedtls_err_if_any(ah_unit_ctx_t ctx, ah_mbedtls_client_t* client, ah_err_t err)
{
    if (err == AH_EDEP) {
        int mbedtls_err = ah_mbedtls_client_get_last_err(client);

        char errbuf[256u];
        mbedtls_strerror(mbedtls_err, errbuf, sizeof(errbuf));
        ah_unit_print(ctx, "AH_EDEP caused by: -%#x; %s", -mbedtls_err, errbuf);
    }
}

#if AH_VIA_MSVC
# pragma warning(disable : 6011)
#endif
static void ah_s_tcp_on_conn_read(void* client, ah_tcp_conn_t* conn, ah_tcp_in_t* in, ah_err_t err)
{
    struct s_tcp_conn_user_data* user_data = ah_tcp_conn_get_user_data(conn);
    ah_unit_res_t* res = user_data->res;

    if (err == AH_EEOF) {
        err = ah_tcp_conn_close(conn);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
        return;
    }

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        s_print_mbedtls_err_if_any(AH_UNIT_CTX, client, err);
        return;
    }

    if (!ah_unit_assert(AH_UNIT_CTX, res, in != NULL, "in == NULL")) {
        return;
    }

    if (!ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, ah_rw_get_readable_size(&in->rw), 18u)) {
        return;
    }

    if (!ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, (char*) in->rw.r, "Hello, Arrowhead!")) {
        return;
    }

    ah_rw_skip_all(&in->rw);

    ah_err_t err0 = ah_tcp_conn_close(conn);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err0, AH_ENONE)) {
        return;
    }

    user_data->did_call_read_cb = true;
}
#if AH_VIA_MSVC
# pragma warning(default : 6011)
#endif

static void ah_s_tcp_on_conn_write(void* ctx, ah_tcp_conn_t* conn, ah_tcp_out_t* out, ah_err_t err)
{
    (void) ctx;
    (void) out;

    struct s_tcp_conn_user_data* user_data = ah_tcp_conn_get_user_data(conn);
    ah_unit_res_t* res = user_data->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    err = ah_tcp_conn_close(conn);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    err = ah_tcp_listener_close(user_data->ln);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    user_data->did_call_write_cb = true;
}

static void ah_s_tcp_on_conn_close(void* ctx, ah_tcp_conn_t* conn, ah_err_t err)
{
    (void) ctx;

    struct s_tcp_conn_user_data* user_data = ah_tcp_conn_get_user_data(conn);

    ah_unit_res_t* res = user_data->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    (*user_data->close_call_counter) += 1u;

    if (*user_data->close_call_counter == 2u) {
        ah_loop_t* loop = ah_tcp_conn_get_loop(conn);
        if (!ah_unit_assert(AH_UNIT_CTX, res, loop != NULL, "loop == NULL")) {
            return;
        }

        err = ah_loop_term(loop);
        if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            return;
        }
    }

    user_data->did_call_close_cb = true;
}

static void ah_s_mbedtls_client_on_handshake_done(ah_mbedtls_client_t* client, const mbedtls_x509_crt* peer_chain, ah_err_t err)
{
    ah_tcp_conn_t* conn = ah_mbedtls_client_get_conn(client);
    struct s_tcp_conn_user_data* user_data = ah_tcp_conn_get_user_data(conn);

    ah_unit_res_t* res = user_data->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        s_print_mbedtls_err_if_any(AH_UNIT_CTX, client, err);
        return;
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if (ah_buf_is_empty(&user_data->send_msg.buf)) {
        // Peer is connection/client.
        if (ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, ah_i_mbedtls_test_srv_crt_size, peer_chain->raw.len)) {
            (void) ah_unit_assert_eq_mem(AH_UNIT_CTX, res, peer_chain->raw.p, ah_i_mbedtls_test_srv_crt_data, peer_chain->raw.len);
        }
    }
    else {
        // Peer is listener/server.
        if (ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, ah_i_mbedtls_test_cln_crt_size, peer_chain->raw.len)) {
            (void) ah_unit_assert_eq_mem(AH_UNIT_CTX, res, peer_chain->raw.p, ah_i_mbedtls_test_cln_crt_data, peer_chain->raw.len);
        }
    }
#else
    (void) ah_unit_assert(AH_UNIT_CTX, res, peer_chain == NULL, "peer_chain != NULL");
#endif

    if (!ah_buf_is_empty(&user_data->send_msg.buf)) {
        err = ah_tcp_conn_write(conn, &user_data->send_msg);
        if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            s_print_mbedtls_err_if_any(AH_UNIT_CTX, client, err);
            return;
        }
    }

    user_data->did_call_handshake_done_cb = true;
}

static void ah_s_tcp_on_listener_open(void* ctx, ah_tcp_listener_t* ln, ah_err_t err)
{
    (void) ctx;

    struct s_tcp_listener_user_data* user_data = ah_tcp_listener_get_user_data(ln);

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, user_data->res, err, AH_ENONE)) {
        return;
    }

    err = ah_tcp_listener_set_nodelay(ln, true);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, user_data->res, err, AH_ENONE)) {
        return;
    }

    err = ah_tcp_listener_listen(ln, 1, (ah_tcp_conn_obs_t) { &s_conn_cbs });
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, user_data->res, err, AH_ENONE)) {
        return;
    }

    user_data->did_call_open_cb = true;
}

static void ah_s_tcp_on_listener_listen(void* ctx, ah_tcp_listener_t* ln, ah_err_t err)
{
    (void) ctx;

    struct s_tcp_listener_user_data* user_data = ah_tcp_listener_get_user_data(ln);
    ah_unit_res_t* res = user_data->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // Save the IP address the listener is bound to.
    err = ah_tcp_listener_get_laddr(ln, &user_data->addr);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // Open connection that will connect to our listener.
    err = ah_tcp_conn_open(user_data->conn, (const ah_sockaddr_t*) &ah_sockaddr_ipv4_loopback);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    user_data->did_call_listen_cb = true;
}

static void ah_s_tcp_on_listener_close(void* ctx, ah_tcp_listener_t* ln, ah_err_t err)
{
    (void) ctx;

    struct s_tcp_listener_user_data* user_data = ah_tcp_listener_get_user_data(ln);
    ah_unit_res_t* res = user_data->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    user_data->did_call_close_cb = true;
}

static void ah_s_tcp_on_listener_accept(void* ctx, ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr, ah_err_t err)
{
    (void) ctx;

    struct s_tcp_listener_user_data* user_data = ah_tcp_listener_get_user_data(ln);

    ah_unit_res_t* res = user_data->res;

    if (err == AH_ECANCELED) {
        return;
    }

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    (void) ah_unit_assert(AH_UNIT_CTX, res, raddr != NULL, "ln_addr == NULL");

    ah_tcp_conn_set_user_data(conn, &user_data->accept_user_data);

    err = ah_tcp_conn_read_start(conn);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, user_data->res, err, AH_ENONE)) {
        return;
    }

    user_data->did_call_accept_cb = true;
}

static void s_should_read_and_write_data(ah_unit_res_t* res)
{
    char errbuf[256u];
    ah_err_t err;
    int mbedtls_err;

    // Setup user data.

    size_t close_call_counter = 0u;

    struct s_tcp_conn_user_data conn_user_data = {
        .close_call_counter = &close_call_counter,
        .res = res,
    };

    struct s_tcp_listener_user_data ln_user_data = {
        .accept_user_data = (struct s_tcp_conn_user_data) {
            .close_call_counter = &close_call_counter,
            .send_msg = (ah_tcp_out_t) {
                .buf = ah_buf_from((uint8_t*) "Hello, Arrowhead!", 18u),
            },
            .res = res,
        },
        .res = res,
    };

    // Setup event loop.

    ah_loop_t loop;

    err = ah_loop_init(&loop, 4u);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // Setup TLS server/listener.

    mbedtls_entropy_context ln_entropy;
    mbedtls_entropy_init(&ln_entropy);

    mbedtls_ctr_drbg_context ln_ctr_drbg;
    mbedtls_ctr_drbg_init(&ln_ctr_drbg);
    mbedtls_err = mbedtls_ctr_drbg_seed(&ln_ctr_drbg, mbedtls_entropy_func, &ln_entropy, NULL, 0u);
    if (mbedtls_err != 0) {
        mbedtls_strerror(mbedtls_err, errbuf, sizeof(errbuf));
        ah_unit_fail(AH_UNIT_CTX, res, "mbedtls_ctr_drbg_seed() returned %d; %s", res, errbuf);
        return;
    }

    // This test uses embedded certificates provided with the MbedTLS library.
    // In a regular program, you would likely load the certificates using
    // mbedtls_x509_crt_parse_file() and mbedtls_pk_parse_keyfile().

    mbedtls_x509_crt ln_own_cert;
    mbedtls_x509_crt_init(&ln_own_cert);
    mbedtls_err = mbedtls_x509_crt_parse(&ln_own_cert, ah_i_mbedtls_test_srv_crt_data, ah_i_mbedtls_test_srv_crt_size);
    if (mbedtls_err != 0) {
        mbedtls_strerror(mbedtls_err, errbuf, sizeof(errbuf));
        ah_unit_fail(AH_UNIT_CTX, res, "mbedtls_x509_crt_parse() returned %d; %s", res, errbuf);
        return;
    }
    mbedtls_err = mbedtls_x509_crt_parse(&ln_own_cert, ah_i_mbedtls_test_ca_crt_data, ah_i_mbedtls_test_ca_crt_size);
    if (mbedtls_err != 0) {
        mbedtls_strerror(mbedtls_err, errbuf, sizeof(errbuf));
        ah_unit_fail(AH_UNIT_CTX, res, "mbedtls_x509_crt_parse() returned %d; %s", res, errbuf);
        return;
    }

    mbedtls_pk_context ln_own_pk;
    mbedtls_pk_init(&ln_own_pk);
#if MBEDTLS_VERSION_MAJOR >= 3
    mbedtls_err = mbedtls_pk_parse_key(&ln_own_pk, ah_i_mbedtls_test_srv_key_data, ah_i_mbedtls_test_srv_key_size, NULL, 0, mbedtls_ctr_drbg_random, &ln_ctr_drbg);
#else
    mbedtls_err = mbedtls_pk_parse_key(&ln_own_pk, ah_i_mbedtls_test_srv_key_data, ah_i_mbedtls_test_srv_key_size, NULL, 0);
#endif
    if (mbedtls_err != 0) {
        mbedtls_strerror(mbedtls_err, errbuf, sizeof(errbuf));
        ah_unit_fail(AH_UNIT_CTX, res, "mbedtls_pk_parse_key() returned %d; %s", res, errbuf);
        return;
    }

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context ln_ssl_cache;
    mbedtls_ssl_cache_init(&ln_ssl_cache);
#endif

    mbedtls_ssl_config ln_ssl_conf;
    mbedtls_ssl_config_init(&ln_ssl_conf);
    mbedtls_err = mbedtls_ssl_config_defaults(&ln_ssl_conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (mbedtls_err != 0) {
        mbedtls_strerror(mbedtls_err, errbuf, sizeof(errbuf));
        ah_unit_fail(AH_UNIT_CTX, res, "mbedtls_ssl_config_defaults() returned %d; %s", res, errbuf);
        return;
    }

    mbedtls_ssl_conf_authmode(&ln_ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache(&ln_ssl_conf, &ln_ssl_cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
#endif
    mbedtls_ssl_conf_ca_chain(&ln_ssl_conf, ln_own_cert.next, NULL);
    mbedtls_err = mbedtls_ssl_conf_own_cert(&ln_ssl_conf, &ln_own_cert, &ln_own_pk);
    if (mbedtls_err != 0) {
        mbedtls_strerror(mbedtls_err, errbuf, sizeof(errbuf));
        ah_unit_fail(AH_UNIT_CTX, res, "mbedtls_ssl_conf_own_cert() returned %d; %s", res, errbuf);
        return;
    }
    mbedtls_ssl_conf_rng(&ln_ssl_conf, mbedtls_ctr_drbg_random, &ln_ctr_drbg);

    ah_mbedtls_server_t ln_server;
    ah_mbedtls_server_init(&ln_server, ah_tcp_trans_get_default(), &ln_ssl_conf, ah_s_mbedtls_client_on_handshake_done);

    ah_tcp_listener_t ln;
    err = ah_tcp_listener_init(&ln, &loop, ah_mbedtls_server_as_trans(&ln_server), (ah_tcp_listener_obs_t) { &s_listener_cbs });
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    ln_user_data.accept_user_data.ln = &ln;
    ah_tcp_listener_set_user_data(&ln, &ln_user_data);

    // Setup TLS client.

    mbedtls_entropy_context conn_entropy;
    mbedtls_entropy_init(&conn_entropy);

    mbedtls_ctr_drbg_context conn_ctr_drbg;
    mbedtls_ctr_drbg_init(&conn_ctr_drbg);
    mbedtls_err = mbedtls_ctr_drbg_seed(&conn_ctr_drbg, mbedtls_entropy_func, &conn_entropy, NULL, 0u);
    if (mbedtls_err != 0) {
        mbedtls_strerror(mbedtls_err, errbuf, sizeof(errbuf));
        ah_unit_fail(AH_UNIT_CTX, res, "mbedtls_ctr_drbg_seed() returned %d; %s", res, errbuf);
        return;
    }

    mbedtls_x509_crt conn_own_cert;
    mbedtls_x509_crt_init(&conn_own_cert);
    mbedtls_err = mbedtls_x509_crt_parse(&conn_own_cert, ah_i_mbedtls_test_cln_crt_data, ah_i_mbedtls_test_cln_crt_size);
    if (mbedtls_err != 0) {
        mbedtls_strerror(mbedtls_err, errbuf, sizeof(errbuf));
        ah_unit_fail(AH_UNIT_CTX, res, "mbedtls_x509_crt_parse() returned %d; %s", res, errbuf);
        return;
    }
    mbedtls_err = mbedtls_x509_crt_parse(&conn_own_cert, ah_i_mbedtls_test_ca_crt_data, ah_i_mbedtls_test_ca_crt_size);
    if (mbedtls_err != 0) {
        mbedtls_strerror(mbedtls_err, errbuf, sizeof(errbuf));
        ah_unit_fail(AH_UNIT_CTX, res, "mbedtls_x509_crt_parse() returned %d; %s", res, errbuf);
        return;
    }

    mbedtls_pk_context conn_own_pk;
    mbedtls_pk_init(&conn_own_pk);
#if MBEDTLS_VERSION_MAJOR >= 3
    mbedtls_err = mbedtls_pk_parse_key(&conn_own_pk, ah_i_mbedtls_test_cln_key_data, ah_i_mbedtls_test_cln_key_size, NULL, 0, mbedtls_ctr_drbg_random, &conn_ctr_drbg);
#else
    mbedtls_err = mbedtls_pk_parse_key(&conn_own_pk, ah_i_mbedtls_test_cln_key_data, ah_i_mbedtls_test_cln_key_size, NULL, 0);
#endif
    if (mbedtls_err != 0) {
        mbedtls_strerror(mbedtls_err, errbuf, sizeof(errbuf));
        ah_unit_fail(AH_UNIT_CTX, res, "mbedtls_pk_parse_key() returned %d; %s", res, errbuf);
        return;
    }

    mbedtls_ssl_config conn_ssl_conf;
    mbedtls_ssl_config_init(&conn_ssl_conf);
    mbedtls_err = mbedtls_ssl_config_defaults(&conn_ssl_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (mbedtls_err != 0) {
        mbedtls_strerror(mbedtls_err, errbuf, sizeof(errbuf));
        ah_unit_fail(AH_UNIT_CTX, res, "mbedtls_ssl_config_defaults() returned %d; %s", res, errbuf);
        return;
    }

    mbedtls_ssl_conf_authmode(&conn_ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conn_ssl_conf, conn_own_cert.next, NULL);
    mbedtls_err = mbedtls_ssl_conf_own_cert(&conn_ssl_conf, &conn_own_cert, &conn_own_pk);
    if (mbedtls_err != 0) {
        mbedtls_strerror(mbedtls_err, errbuf, sizeof(errbuf));
        ah_unit_fail(AH_UNIT_CTX, res, "mbedtls_ssl_conf_own_cert() returned %d; %s", res, errbuf);
        return;
    }
    mbedtls_ssl_conf_rng(&conn_ssl_conf, mbedtls_ctr_drbg_random, &conn_ctr_drbg);

    ah_mbedtls_client_t conn_client;
    ah_mbedtls_client_init(&conn_client, ah_tcp_trans_get_default(), &conn_ssl_conf, ah_s_mbedtls_client_on_handshake_done);

    ah_tcp_conn_t conn;
    err = ah_tcp_conn_init(&conn, &loop, ah_mbedtls_client_as_trans(&conn_client), (ah_tcp_conn_obs_t) { &s_conn_cbs });
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    conn_user_data.ln_addr = &ln_user_data.addr;
    ah_tcp_conn_set_user_data(&conn, &conn_user_data);

    ln_user_data.conn = &conn;

    // Open listener, which will open the connection, and so on.

    err = ah_tcp_listener_open(&ln, (const ah_sockaddr_t*) &ah_sockaddr_ipv4_loopback);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // Submit issued events for execution.

    ah_time_t deadline;
    err = ah_time_add(ah_time_now(), 5 * AH_TIMEDIFF_S, &deadline);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }
    err = ah_loop_run_until(&loop, &deadline);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // Perform final cleanups.

    ah_mbedtls_client_term(&conn_client);
    ah_mbedtls_server_term(&ln_server);

    mbedtls_ctr_drbg_free(&ln_ctr_drbg);
    mbedtls_entropy_free(&ln_entropy);
    mbedtls_pk_free(&ln_own_pk);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free(&ln_ssl_cache);
#endif
    mbedtls_ssl_config_free(&ln_ssl_conf);
    mbedtls_x509_crt_free(&ln_own_cert);

    mbedtls_ctr_drbg_free(&conn_ctr_drbg);
    mbedtls_entropy_free(&conn_entropy);
    mbedtls_pk_free(&conn_own_pk);
    mbedtls_ssl_config_free(&conn_ssl_conf);
    mbedtls_x509_crt_free(&conn_own_cert);

    // Check results.

    struct s_tcp_conn_user_data* conn_data = &conn_user_data;
    (void) ah_unit_assert(AH_UNIT_CTX, res, conn_data->did_call_open_cb, "`conn` ah_s_tcp_on_conn_open() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, conn_data->did_call_connect_cb, "`conn` ah_s_tcp_on_conn_connect() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, conn_data->did_call_handshake_done_cb, "`conn` ah_s_mbedtls_client_on_handshake_done() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, conn_data->did_call_close_cb, "`conn` ah_s_tcp_on_conn_close() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, conn_data->did_call_read_cb, "`conn` ah_s_tcp_on_conn_read_data() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, !conn_data->did_call_write_cb, "`conn` ah_s_tcp_on_conn_write_done() was called");

    struct s_tcp_listener_user_data* ln_data = &ln_user_data;
    (void) ah_unit_assert(AH_UNIT_CTX, res, ln_data->did_call_open_cb, "`ln` ah_s_tcp_on_listener_open() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, ln_data->did_call_listen_cb, "`ln` ah_s_tcp_on_listener_listen() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, ln_data->did_call_close_cb, "`ln` ah_s_tcp_on_listener_close() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, ln_data->did_call_accept_cb, "`ln` ah_s_tcp_on_listener_accept() not called");

    struct s_tcp_conn_user_data* acc_data = &ln_data->accept_user_data;
    (void) ah_unit_assert(AH_UNIT_CTX, res, !acc_data->did_call_open_cb, "`acc` ah_s_tcp_on_conn_open() was called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, !acc_data->did_call_connect_cb, "`acc` ah_s_tcp_on_conn_connect() was called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, acc_data->did_call_handshake_done_cb, "`acc` ah_s_mbedtls_client_on_handshake_done() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, acc_data->did_call_close_cb, "`acc` ah_s_tcp_on_conn_close() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, !acc_data->did_call_read_cb, "`acc` ah_s_tcp_on_conn_read_data() was called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, acc_data->did_call_write_cb, "`acc` ah_s_tcp_on_conn_write_done() not called");

    ah_unit_assert(AH_UNIT_CTX, res, ah_loop_is_term(&loop), "`loop` never terminated");
}
