// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_WIN32_WINAPI_H_
#define SRC_WIN32_WINAPI_H_

#include "ah/defs.h"

#include <winsock2.h>
#include <mswsock.h>

// The below function pointers are set at the first call to ah_i_winapi_init().

extern LPFN_ACCEPTEX ah_i_winapi_AcceptEx;
extern LPFN_WSARECVMSG ah_i_winapi_WSARecvMsg;

// Can safely be called multiple times.
void ah_i_winapi_init(void);

LPTSTR ah_i_winapi_strerror(DWORD err); // Free return value with LocalFree().

// Must be called at most the number of times that ah_i_winapi_init() was called.
void ah_i_winapi_term(void);

#endif
