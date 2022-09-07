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

#define AH_I_UDP_SOCK_STATE_TERMINATED  0u
#define AH_I_UDP_SOCK_STATE_INITIALIZED 1u
#define AH_I_UDP_SOCK_STATE_CLOSED      2u
#define AH_I_UDP_SOCK_STATE_CLOSING     3u
#define AH_I_UDP_SOCK_STATE_OPEN        4u // Sends allowed.
#define AH_I_UDP_SOCK_STATE_RECEIVING   5u // Sends allowed.

#define AH_I_UDP_IN_FIELDS \
 ah_udp_in_t** _owner_ptr; \
 AH_I_UDP_IN_PLATFORM_FIELDS

#define AH_I_UDP_OUT_FIELDS \
 AH_I_UDP_OUT_PLATFORM_FIELDS

#define AH_I_UDP_SOCK_FIELDS \
 ah_loop_t* _loop;           \
 ah_udp_trans_t _trans;      \
 ah_udp_sock_obs_t _obs;     \
                             \
 ah_udp_in_t* _in;           \
                             \
 uint16_t _sock_family;      \
 uint8_t _state;             \
 AH_I_UDP_SOCK_PLATFORM_FIELDS

#endif
