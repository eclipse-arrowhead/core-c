// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_TLS_H_
#define AH_INTERNAL_TLS_H_

#define AH_I_TLS_CTX_FIELDS \
 ah_loop_t* _loop;          \
 ah_tcp_trans_t _trans;     \
 void* _impl;               \
 void* _user_data;          \
 ah_tls_err_t _last_err;

#endif
