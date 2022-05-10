// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_UDP_H_
#define AH_INTERNAL_UDP_H_

#include "../defs.h"

#if AH_USE_IOCP
# include "_udp-iocp.h"
#elif AH_USE_KQUEUE
# include "_udp-kqueue.h"
#elif AH_USE_URING
# include "_udp-uring.h"
#endif

#define AH_I_UDP_OBUFS_FIELDS \
 ah_udp_obufs_t* _next;       \
 AH_I_UDP_OBUFS_PLATFORM_FIELDS

#define AH_I_UDP_SOCK_FIELDS      \
 ah_loop_t* _loop;                \
 const ah_udp_sock_vtab_t* _vtab; \
 ah_udp_obufs_t* _send_queue_head; \
 ah_udp_obufs_t* _send_queue_end;  \
 void* _trans_data;               \
 void* _user_data;                \
 bool _is_ipv6;                   \
 bool _is_open;                   \
 bool _is_receiving;              \
 AH_I_UDP_SOCK_PLATFORM_FIELDS

#define AH_I_UDP_TRANS_FIELDS      \
 ah_loop_t* _loop;                 \
 const ah_udp_trans_vtab_t* _vtab; \
 void* _trans_data;

#endif
