// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_TCP_H_
#define AH_INTERNAL_TCP_H_

#include "../defs.h"

#if AH_USE_IOCP
#    include "iocp/tcp.h"
#elif AH_USE_KQUEUE
#    include "kqueue/tcp.h"
#elif AH_USE_URING
#    include "uring/tcp.h"
#endif

#define AH_I_TCP_LISTEN_CTX_FIELDS AH_I_TCP_LISTEN_CTX_PLATFORM_FIELDS
#define AH_I_TCP_READ_CTX_FIELDS   AH_I_TCP_READ_CTX_PLATFORM_FIELDS

#define AH_I_TCP_SOCK_FIELDS                                                                                           \
    ah_loop_t* _loop;                                                                                                  \
    void* _user_data;                                                                                                  \
                                                                                                                       \
    uint8_t _state;                                                                                                    \
    uint8_t _state_read;                                                                                               \
    uint8_t _state_write;                                                                                              \
    AH_I_TCP_SOCK_PLATFORM_FIELDS

#define AH_I_TCP_WRITE_CTX_FIELDS AH_I_TCP_WRITE_CTX_PLATFORM_FIELDS

#define AH_I_TCP_STATE_CLOSED     0x01
#define AH_I_TCP_STATE_OPEN       0x02
#define AH_I_TCP_STATE_CONNECTING 0x04
#define AH_I_TCP_STATE_CONNECTED  0x08
#define AH_I_TCP_STATE_LISTENING  0x10

#define AH_I_TCP_STATE_READ_OFF     0x01
#define AH_I_TCP_STATE_READ_STOPPED 0x02
#define AH_I_TCP_STATE_READ_STARTED 0x04

#define AH_I_TCP_STATE_WRITE_OFF     0x01
#define AH_I_TCP_STATE_WRITE_STOPPED 0x02
#define AH_I_TCP_STATE_WRITE_STARTED 0x04

#endif
