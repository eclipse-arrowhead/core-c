// SPDX-License-Identifier: EPL-2.0

#include "ah/mbedtls.h"
#include "certs.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <ah/loop.h>
#include <ah/sock.h>
#include <ah/tcp.h>
#include <ah/unit.h>
#include <mbedtls/debug.h>
#include <mbedtls/error.h>
#include <mbedtls/version.h>

struct s_conn_obs_ctx {
    ah_sockaddr_t connect_to_this_addr_on_open;

    ah_tcp_out_t rconn_out;
    bool is_accepted;

    size_t* conn_close_countdown;

    size_t on_open_count;
    size_t on_connect_count;
    size_t on_read_count;
    size_t on_write_count;
    size_t on_close_count;
    size_t on_handshake_count;
    size_t received_message_count;

    ah_unit_res_t* res;
};

struct s_listener_obs_ctx {
    ah_tcp_conn_t* open_this_conn_on_listen;

    struct s_conn_obs_ctx rconn_obs_ctx;

    size_t on_open_count;
    size_t on_listen_count;
    size_t on_accept_count;
    size_t on_close_count;

    ah_unit_res_t* res;
};

static void s_should_read_and_write_data(ah_unit_res_t* res);

void test_mbedtls(ah_unit_res_t* res)
{
    s_should_read_and_write_data(res);
}

static void s_conn_on_open(void* ctx_, ah_tcp_conn_t* conn, ah_err_t err);
static void s_conn_on_connect(void* ctx_, ah_tcp_conn_t* conn, ah_err_t err);
static void s_conn_on_read(void* ctx_, ah_tcp_conn_t* conn, ah_tcp_in_t* in, ah_err_t err);
static void s_conn_on_write(void* ctx_, ah_tcp_conn_t* conn, ah_tcp_out_t* out, ah_err_t err);
static void s_conn_on_close(void* ctx_, ah_tcp_conn_t* conn, ah_err_t err);

static void s_listener_on_open(void* ctx_, ah_tcp_listener_t* ln, ah_err_t err);
static void s_listener_on_listen(void* ctx_, ah_tcp_listener_t* ln, ah_err_t err);
static void s_listener_on_accept(void* ctx_, ah_tcp_listener_t* ln, ah_tcp_accept_t* accept, ah_err_t err);
static void s_listener_on_close(void* ctx_, ah_tcp_listener_t* ln, ah_err_t err);

static void s_client_on_handshake_done(ah_mbedtls_client_t* client, const mbedtls_x509_crt* peer_chain, ah_err_t err);
static void s_print_mbedtls_err_if_any(ah_unit_ctx_t ctx, ah_mbedtls_client_t* client, ah_err_t err);

static const ah_tcp_conn_cbs_t s_conn_cbs = {
    .on_open = s_conn_on_open,
    .on_connect = s_conn_on_connect,
    .on_read = s_conn_on_read,
    .on_write = s_conn_on_write,
    .on_close = s_conn_on_close,
};

static const ah_tcp_listener_cbs_t s_listener_cbs = {
    .on_open = s_listener_on_open,
    .on_listen = s_listener_on_listen,
    .on_accept = s_listener_on_accept,
    .on_close = s_listener_on_close,
};

#if AH_IS_WIN32
# pragma warning(disable : 6011)
#endif

// This function is not called for our accepted connection.
static void s_conn_on_open(void* ctx_, ah_tcp_conn_t* conn, ah_err_t err)
{
    struct s_conn_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_open_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        ah_tcp_conn_term(conn);
        return;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, conn != NULL, "conn != NULL")) {
        return;
    }

    err = ah_tcp_conn_set_keepalive(conn, false);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    err = ah_tcp_conn_set_nodelay(conn, true);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    err = ah_tcp_conn_set_reuseaddr(conn, false);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    err = ah_tcp_conn_connect(conn, &ctx->connect_to_this_addr_on_open);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    return;

handle_failure:
    if (conn != NULL) {
        err = ah_tcp_conn_close(conn);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

// This function is not called for our accepted connection.
static void s_conn_on_connect(void* ctx_, ah_tcp_conn_t* conn, ah_err_t err)
{
    struct s_conn_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_connect_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, conn != NULL, "conn != NULL")) {
        return;
    }

    err = ah_tcp_conn_read_start(conn);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    return;

handle_failure:
    if (conn != NULL) {
        err = ah_tcp_conn_close(conn);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

static void s_conn_on_read(void* ctx_, ah_tcp_conn_t* conn, ah_tcp_in_t* in, ah_err_t err)
{
    struct s_conn_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_read_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (err == AH_EEOF) {
        goto close_and_return;
    }

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, in != NULL, "in != NULL")) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, conn != NULL, "conn != NULL")) {
        return;
    }

    if (ah_rw_get_readable_size(&in->rw) < 18u) {
        return; // Wait until there is more data to read.
    }

    if (!ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, ah_rw_get_readable_size(&in->rw), 18u)) {
        goto handle_failure;
    }

    if (!ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, (char*) in->rw.r, "Hello, Arrowhead!")) {
        goto handle_failure;
    }

    ah_rw_skipn(&in->rw, 18u);
    ctx->received_message_count += 1u;

close_and_return:
handle_failure:
    if (conn != NULL) {
        err = ah_tcp_conn_close(conn);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

static void s_conn_on_write(void* ctx_, ah_tcp_conn_t* conn, ah_tcp_out_t* out, ah_err_t err)
{
    struct s_conn_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_write_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, out != NULL, "out != NULL")) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, conn != NULL, "conn != NULL")) {
        goto handle_failure;
    }

    return;

handle_failure:
    if (conn != NULL) {
        err = ah_tcp_conn_close(conn);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

static void s_conn_on_close(void* ctx_, ah_tcp_conn_t* conn, ah_err_t err)
{
    struct s_conn_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_close_count += 1u;

    ah_unit_res_t* res = ctx->res;

    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);

    if (!ah_unit_assert(AH_UNIT_CTX, res, conn != NULL, "conn != NULL")) {
        return;
    }

    ah_loop_t* loop = ah_tcp_conn_get_loop(conn);
    (void) ah_unit_assert(AH_UNIT_CTX, res, loop != NULL, "loop != NULL");

    err = ah_tcp_conn_term(conn);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);

    (*ctx->conn_close_countdown) -= 1u;

    if (*ctx->conn_close_countdown == 0u) {
        err = ah_loop_term(loop);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

static void s_listener_on_open(void* ctx_, ah_tcp_listener_t* ln, ah_err_t err)
{
    struct s_listener_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_open_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        if (ln != NULL) {
            ah_tcp_listener_term(ln);
        }
        return;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, ln != NULL, "ln != NULL")) {
        return;
    }

    err = ah_tcp_listener_set_nodelay(ln, false);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    err = ah_tcp_listener_listen(ln, 1u);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    return;

handle_failure:
    ah_tcp_listener_close(ln);
}

static void s_listener_on_listen(void* ctx_, ah_tcp_listener_t* ln, ah_err_t err)
{
    struct s_listener_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_listen_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, ln != NULL, "ln != NULL")) {
        return;
    }

    // As we now have a listener listening, we are ready to open the connection
    // that will connect to it. For it to know where to connect, we give it the
    // address of the listener before we open it.

    struct s_conn_obs_ctx* conn_obs_ctx = ah_tcp_conn_get_obs_ctx(ctx->open_this_conn_on_listen);
    if (!ah_unit_assert(AH_UNIT_CTX, res, conn_obs_ctx != NULL, "conn_obs_ctx != NULL")) {
        goto handle_failure;
    }

    err = ah_tcp_listener_get_laddr(ln, &conn_obs_ctx->connect_to_this_addr_on_open);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }
    err = ah_tcp_conn_open(ctx->open_this_conn_on_listen, (const ah_sockaddr_t*) &ah_sockaddr_ipv4_loopback);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    return;

handle_failure:
    if (ln != NULL) {
        (void) ah_tcp_listener_close(ln);
    }
}

static void s_listener_on_accept(void* ctx_, ah_tcp_listener_t* ln, ah_tcp_accept_t* accept, ah_err_t err)
{
    struct s_listener_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_accept_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (err == AH_ECANCELED) {
        goto handle_failure;
    }
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, accept != NULL, "accept != NULL")) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, accept->raddr != NULL, "accept->raddr != NULL")) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, accept->obs != NULL, "accept->obs != NULL")) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, accept->conn != NULL, "accept->conn != NULL")) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, ln != NULL, "ln != NULL")) {
        goto handle_failure;
    }

    accept->obs->cbs = &s_conn_cbs;
    accept->obs->ctx = &ctx->rconn_obs_ctx;

    err = ah_tcp_conn_read_start(accept->conn);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    // We are done accepting connections now.
    err = ah_tcp_listener_close(ln);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);

    return;

handle_failure:
    if (accept != NULL && accept->conn != NULL) {
        err = ah_tcp_conn_close(accept->conn);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
    if (ln != NULL) {
        err = ah_tcp_listener_close(ln);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

static void s_listener_on_close(void* ctx_, ah_tcp_listener_t* ln, ah_err_t err)
{
    struct s_listener_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_close_count += 1u;

    ah_unit_res_t* res = ctx->res;

    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);

    if (!ah_unit_assert(AH_UNIT_CTX, res, ln != NULL, "ln != NULL")) {
        return;
    }

    err = ah_tcp_listener_term(ln);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
}

static void s_client_on_handshake_done(ah_mbedtls_client_t* client, const mbedtls_x509_crt* peer_chain, ah_err_t err)
{
    ah_tcp_conn_t* conn = ah_mbedtls_client_get_tcp_conn(client);
    ah_assert_always(conn != NULL);

    struct s_conn_obs_ctx* ctx = ah_tcp_conn_get_obs_ctx(conn);
    ah_assert_always(ctx != NULL);

    ctx->on_handshake_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        s_print_mbedtls_err_if_any(AH_UNIT_CTX, client, err);
        return;
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if (ctx->is_accepted) {
        // Peer is listener/server.
        if (ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, ah_i_mbedtls_test_cln_crt_size, peer_chain->raw.len)) {
            (void) ah_unit_assert_eq_mem(AH_UNIT_CTX, res, peer_chain->raw.p, ah_i_mbedtls_test_cln_crt_data, peer_chain->raw.len);
        }
    }
    else {
        // Peer is connection/client.
        if (ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, ah_i_mbedtls_test_srv_crt_size, peer_chain->raw.len)) {
            (void) ah_unit_assert_eq_mem(AH_UNIT_CTX, res, peer_chain->raw.p, ah_i_mbedtls_test_srv_crt_data, peer_chain->raw.len);
        }
    }
#else
    (void) ah_unit_assert(AH_UNIT_CTX, res, peer_chain == NULL, "peer_chain == NULL");
#endif

    err = ah_buf_init(&ctx->rconn_out.buf, (uint8_t*) "Hello, Arrowhead!", 18u);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }
    err = ah_tcp_conn_write(conn, &ctx->rconn_out);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    return;

handle_failure:
    if (conn != NULL) {
        err = ah_tcp_conn_close(conn);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
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

static void s_should_read_and_write_data(ah_unit_res_t* res)
{
    ah_err_t err;
    char errbuf[256u];
    int mbedtls_err;

    // Setup event loop.
    ah_loop_t loop;
    err = ah_loop_init(&loop, 4u);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // When this number of connections have been closed, we terminate the event loop.
    size_t conn_close_countdown = 2u;

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
    ah_mbedtls_server_init(&ln_server, ah_tcp_trans_get_default(), &ln_ssl_conf, s_client_on_handshake_done);

    struct s_listener_obs_ctx ln_obs_ctx = {
        .rconn_obs_ctx = (struct s_conn_obs_ctx) {
            .is_accepted = true,
            .conn_close_countdown = &conn_close_countdown,
            .res = res,
        },
        .res = res,
    };

    ah_tcp_listener_t ln;
    err = ah_tcp_listener_init(&ln, &loop, ah_mbedtls_server_as_tcp_trans(&ln_server), (ah_tcp_listener_obs_t) { &s_listener_cbs, &ln_obs_ctx });
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // Setup TLS client/connection.

    mbedtls_entropy_context lconn_entropy;
    mbedtls_entropy_init(&lconn_entropy);

    mbedtls_ctr_drbg_context lconn_ctr_drbg;
    mbedtls_ctr_drbg_init(&lconn_ctr_drbg);
    mbedtls_err = mbedtls_ctr_drbg_seed(&lconn_ctr_drbg, mbedtls_entropy_func, &lconn_entropy, NULL, 0u);
    if (mbedtls_err != 0) {
        mbedtls_strerror(mbedtls_err, errbuf, sizeof(errbuf));
        ah_unit_fail(AH_UNIT_CTX, res, "mbedtls_ctr_drbg_seed() returned %d; %s", res, errbuf);
        return;
    }

    mbedtls_x509_crt lconn_own_cert;
    mbedtls_x509_crt_init(&lconn_own_cert);
    mbedtls_err = mbedtls_x509_crt_parse(&lconn_own_cert, ah_i_mbedtls_test_cln_crt_data, ah_i_mbedtls_test_cln_crt_size);
    if (mbedtls_err != 0) {
        mbedtls_strerror(mbedtls_err, errbuf, sizeof(errbuf));
        ah_unit_fail(AH_UNIT_CTX, res, "mbedtls_x509_crt_parse() returned %d; %s", res, errbuf);
        return;
    }
    mbedtls_err = mbedtls_x509_crt_parse(&lconn_own_cert, ah_i_mbedtls_test_ca_crt_data, ah_i_mbedtls_test_ca_crt_size);
    if (mbedtls_err != 0) {
        mbedtls_strerror(mbedtls_err, errbuf, sizeof(errbuf));
        ah_unit_fail(AH_UNIT_CTX, res, "mbedtls_x509_crt_parse() returned %d; %s", res, errbuf);
        return;
    }

    mbedtls_pk_context lconn_own_pk;
    mbedtls_pk_init(&lconn_own_pk);
#if MBEDTLS_VERSION_MAJOR >= 3
    mbedtls_err = mbedtls_pk_parse_key(&lconn_own_pk, ah_i_mbedtls_test_cln_key_data, ah_i_mbedtls_test_cln_key_size, NULL, 0, mbedtls_ctr_drbg_random, &lconn_ctr_drbg);
#else
    mbedtls_err = mbedtls_pk_parse_key(&lconn_own_pk, ah_i_mbedtls_test_cln_key_data, ah_i_mbedtls_test_cln_key_size, NULL, 0);
#endif
    if (mbedtls_err != 0) {
        mbedtls_strerror(mbedtls_err, errbuf, sizeof(errbuf));
        ah_unit_fail(AH_UNIT_CTX, res, "mbedtls_pk_parse_key() returned %d; %s", res, errbuf);
        return;
    }

    mbedtls_ssl_config lconn_ssl_conf;
    mbedtls_ssl_config_init(&lconn_ssl_conf);
    mbedtls_err = mbedtls_ssl_config_defaults(&lconn_ssl_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (mbedtls_err != 0) {
        mbedtls_strerror(mbedtls_err, errbuf, sizeof(errbuf));
        ah_unit_fail(AH_UNIT_CTX, res, "mbedtls_ssl_config_defaults() returned %d; %s", res, errbuf);
        return;
    }

    mbedtls_ssl_conf_authmode(&lconn_ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&lconn_ssl_conf, lconn_own_cert.next, NULL);
    mbedtls_err = mbedtls_ssl_conf_own_cert(&lconn_ssl_conf, &lconn_own_cert, &lconn_own_pk);
    if (mbedtls_err != 0) {
        mbedtls_strerror(mbedtls_err, errbuf, sizeof(errbuf));
        ah_unit_fail(AH_UNIT_CTX, res, "mbedtls_ssl_conf_own_cert() returned %d; %s", res, errbuf);
        return;
    }
    mbedtls_ssl_conf_rng(&lconn_ssl_conf, mbedtls_ctr_drbg_random, &lconn_ctr_drbg);

    ah_mbedtls_client_t lconn_client;
    ah_mbedtls_client_init(&lconn_client, ah_tcp_trans_get_default(), &lconn_ssl_conf, s_client_on_handshake_done);

    struct s_conn_obs_ctx lconn_obs_ctx = {
        .is_accepted = false,
        .conn_close_countdown = &conn_close_countdown,
        .res = res,
    };

    ah_tcp_conn_t lconn;
    err = ah_tcp_conn_init(&lconn, &loop, ah_mbedtls_client_as_tcp_trans(&lconn_client), (ah_tcp_conn_obs_t) { &s_conn_cbs, &lconn_obs_ctx });
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // The listener keeps a reference to `lconn` for us to be able to open it
    // after `ln` is ready to accept incoming connections.
    ln_obs_ctx.open_this_conn_on_listen = &lconn;

    // Open listener.
    err = ah_tcp_listener_open(&ln, (const ah_sockaddr_t*) &ah_sockaddr_ipv4_loopback);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // Execute event loop.
    ah_time_t deadline;
    err = ah_time_add(ah_time_now(), 500000 * AH_TIMEDIFF_S, &deadline);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }
    err = ah_loop_run_until(&loop, &deadline);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // Perform final cleanups.

    ah_mbedtls_client_term(&lconn_client);
    ah_mbedtls_server_term(&ln_server);

    mbedtls_ctr_drbg_free(&ln_ctr_drbg);
    mbedtls_entropy_free(&ln_entropy);
    mbedtls_pk_free(&ln_own_pk);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free(&ln_ssl_cache);
#endif
    mbedtls_ssl_config_free(&ln_ssl_conf);
    mbedtls_x509_crt_free(&ln_own_cert);

    mbedtls_ctr_drbg_free(&lconn_ctr_drbg);
    mbedtls_entropy_free(&lconn_entropy);
    mbedtls_pk_free(&lconn_own_pk);
    mbedtls_ssl_config_free(&lconn_ssl_conf);
    mbedtls_x509_crt_free(&lconn_own_cert);

    // Check results after event loop stops executing.

    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lconn_obs_ctx.on_open_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lconn_obs_ctx.on_connect_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lconn_obs_ctx.on_close_count, 1u);
    (void) ah_unit_assert(AH_UNIT_CTX, res, lconn_obs_ctx.on_read_count > 0u, "lconn_obs_ctx.on_read_count > 0u");
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lconn_obs_ctx.on_write_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lconn_obs_ctx.on_handshake_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lconn_obs_ctx.received_message_count, 1u);

    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, ln_obs_ctx.on_open_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, ln_obs_ctx.on_listen_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, ln_obs_ctx.on_close_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, ln_obs_ctx.on_accept_count, 1u);

    struct s_conn_obs_ctx* rconn_obs_ctx = &ln_obs_ctx.rconn_obs_ctx;
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rconn_obs_ctx->on_open_count, 0u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rconn_obs_ctx->on_connect_count, 0u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rconn_obs_ctx->on_close_count, 1u);
    (void) ah_unit_assert(AH_UNIT_CTX, res, rconn_obs_ctx->on_read_count > 0u, "rconn_obs_ctx->on_read_count > 0u");
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rconn_obs_ctx->on_write_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lconn_obs_ctx.on_handshake_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rconn_obs_ctx->received_message_count, 1u);

    ah_unit_assert(AH_UNIT_CTX, res, ah_loop_is_term(&loop), "`loop` never terminated");
}

#if AH_IS_WIN32
# pragma warning(default : 6011)
#endif
