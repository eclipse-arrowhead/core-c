// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_SOCK_H_
#define AH_INTERNAL_SOCK_H_

#include "../defs.h"

#if AH_HAS_BSD_SOCKETS
#    include "bsd/sock.h"
#endif

#ifndef AH_I_SOCKADDR_HAS_SIZE
#    define AH_I_SOCKADDR_HAS_SIZE 0
#endif

#endif
