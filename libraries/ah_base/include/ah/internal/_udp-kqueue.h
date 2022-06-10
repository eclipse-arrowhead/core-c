// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_KQUEUE_UDP_H_
#define AH_INTERNAL_KQUEUE_UDP_H_

#define AH_I_UDP_MSG_PLATFORM_FIELDS \
 struct ah_udp_msg* _next;           \
 struct msghdr _msghdr;

#define AH_I_UDP_SOCK_PLATFORM_FIELDS \
 int _fd;                             \
 struct ah_i_udp_msg_queue _msg_queue;

struct ah_i_udp_msg_queue {
    ah_udp_msg_t* _head;
    ah_udp_msg_t* _end;
};

#endif
