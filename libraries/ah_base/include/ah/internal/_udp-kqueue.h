// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_UDP_KQUEUE_H_
#define AH_INTERNAL_UDP_KQUEUE_H_

#include "collections/list.h"

#define AH_I_UDP_IN_PLATFORM_FIELDS

#define AH_I_UDP_OUT_PLATFORM_FIELDS \
 struct ah_i_list_entry _list_entry; \
 struct msghdr _msghdr;

#define AH_I_UDP_SOCK_PLATFORM_FIELDS \
 int _fd;                             \
 uint32_t _ref_count;                 \
 struct ah_i_list _out_queue;         \
 struct ah_i_loop_evt* _recv_evt;     \
 struct ah_i_loop_evt* _send_evt;

#endif
