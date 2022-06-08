// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "tls-utils-mbedtls.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <mbedtls/error.h>

const ah_tls_cert_t* ah_i_tls_cert_from_mbedtls(const mbedtls_x509_crt* crt)
{
    return (const ah_tls_cert_t*) crt;
}

ah_tls_err_t ah_i_tls_ctx_init(struct ah_i_tls_ctx* ctx, ah_tls_cert_store_t* certs, ah_tls_on_handshake_done_cb on_handshake_done_cb, int endpoint)
{
    ah_assert_if_debug(ctx != NULL);

    int res;

    mbedtls_entropy_init(&ctx->_entropy);

    mbedtls_ctr_drbg_init(&ctx->_ctr_drbg);
    res = mbedtls_ctr_drbg_seed(&ctx->_ctr_drbg, mbedtls_entropy_func, &ctx->_entropy, NULL, 0u);
    if (res != 0) {
        return res;
    }

    mbedtls_ssl_config_init(&ctx->_ssl_conf);
    res = mbedtls_ssl_config_defaults(&ctx->_ssl_conf, endpoint, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (res != 0) {
        return res;
    }

    mbedtls_ssl_conf_rng(&ctx->_ssl_conf, mbedtls_ctr_drbg_random, &ctx->_ctr_drbg);

    mbedtls_ssl_conf_ca_chain(&ctx->_ssl_conf, certs->_authorities, certs->_revocations);
    res = mbedtls_ssl_conf_own_cert(&ctx->_ssl_conf, certs->_own_chain, certs->_own_key);
    if (res != 0) {
        return res;
    }

    ctx->_on_handshake_done_cb = on_handshake_done_cb;

    return 0;
}

void ah_i_tls_ctx_term(struct ah_i_tls_ctx* ctx)
{
    mbedtls_ctr_drbg_free(&ctx->_ctr_drbg);
    mbedtls_entropy_free(&ctx->_entropy);
    mbedtls_ssl_config_free(&ctx->_ssl_conf);
}

ah_err_t ah_i_tls_mbedtls_res_to_err(struct ah_i_tls_errs* errs, int res)
{
    ah_assert_if_debug(errs != NULL);
    ah_assert_if_debug(res <= 0);

    switch (res) {
    case 0:
        return AH_ENONE;

    case MBEDTLS_ERR_ASN1_ALLOC_FAILED:
    case MBEDTLS_ERR_CIPHER_ALLOC_FAILED:
    case MBEDTLS_ERR_DHM_ALLOC_FAILED:
    case MBEDTLS_ERR_ECP_ALLOC_FAILED:
    case MBEDTLS_ERR_MD_ALLOC_FAILED:
    case MBEDTLS_ERR_MPI_ALLOC_FAILED:
    case MBEDTLS_ERR_PK_ALLOC_FAILED:
    case MBEDTLS_ERR_SSL_ALLOC_FAILED:
    case MBEDTLS_ERR_X509_ALLOC_FAILED:
        return AH_ENOMEM;

    case MBEDTLS_ERR_SSL_WANT_READ:
    case MBEDTLS_ERR_SSL_WANT_WRITE:
        return AH_ENOLINK;

    case MBEDTLS_ERR_SSL_CONN_EOF:
        return AH_EEOF;

    case MBEDTLS_ERR_ERROR_GENERIC_ERROR:
        if (errs->_pending_ah_err != AH_ENONE) {
            ah_err_t err = errs->_pending_ah_err;
            errs->_pending_ah_err = AH_ENONE;
            return err;
        }
        // fallthrough
    default:
        errs->_last_mbedtls_err = res;
        return AH_EDEP;
    }
}
