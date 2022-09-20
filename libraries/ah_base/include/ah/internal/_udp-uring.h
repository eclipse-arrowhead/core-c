// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_UDP_URING_H_
#define AH_INTERNAL_UDP_URING_H_

#define AH_I_UDP_IN_PLATFORM_FIELDS

#define AH_I_UDP_OUT_PLATFORM_FIELDS \
 struct msghdr _msghdr;              \
 ah_udp_sock_t* _sock;

#define AH_I_UDP_SOCK_PLATFORM_FIELDS \
 int _fd;                             \
 uint32_t _ref_count;                 \
 ah_sockaddr_t _recv_addr;            \
 struct ah_i_loop_evt* _recv_evt;     \
 struct msghdr _recv_msghdr;

#endif
